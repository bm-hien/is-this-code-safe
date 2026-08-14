"""Static Python AST to MalIR event extraction.

The module never imports or executes inspected source code.
"""

from __future__ import annotations

import ast
import hashlib
import warnings
from dataclasses import dataclass
from pathlib import Path

from .flow import build_local_dataflow_paths
from .motifs import build_behavior_paths
from .policy import (
    READ_METHODS,
    WRITE_METHODS,
    classify_call,
    is_persistence_path,
    is_sensitive_path,
)
from .types import Event, FileAnalysis

_DATAFLOW_SEND_SOURCES = {
    "ENV_READ",
    "SENSITIVE_FILE_READ",
    "FILE_READ",
    "SYSTEM_DISCOVERY",
}
_DATAFLOW_EXEC_SOURCES = {"NETWORK_RECEIVE", "DECODE", "UNSAFE_DESERIALIZE"}
_DATAFLOW_EXEC_SINKS = {"DYNAMIC_EXEC", "PROCESS_EXEC"}


@dataclass(frozen=True, slots=True)
class ExtractorLimits:
    max_file_bytes: int = 1_000_000
    max_events: int = 2_000


class PythonExtractor:
    def __init__(
        self,
        limits: ExtractorLimits | None = None,
        *,
        enable_dataflow: bool = True,
    ) -> None:
        self.limits = limits or ExtractorLimits()
        self.enable_dataflow = enable_dataflow

    def analyze_file(
        self, path: str | Path, display_path: str | None = None
    ) -> FileAnalysis:
        source_path = Path(path)
        with source_path.open("rb") as handle:
            payload = handle.read(self.limits.max_file_bytes + 1)
        truncated = len(payload) > self.limits.max_file_bytes
        payload = payload[: self.limits.max_file_bytes]
        digest = hashlib.sha256(payload).hexdigest()
        source = payload.decode("utf-8", errors="replace")
        result = self.analyze_source(source, display_path or str(source_path))
        result.sha256 = digest
        result.bytes_read = len(payload)
        result.truncated = truncated
        return result

    def analyze_source(self, source: str, path: str = "<memory>") -> FileAnalysis:
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        result = FileAnalysis(path=path, sha256=digest, bytes_read=len(source.encode()))
        try:
            with warnings.catch_warnings():
                # Parser warnings contain attacker-controlled source text and
                # changed category between supported Python versions.
                warnings.simplefilter("ignore")
                tree = ast.parse(source, filename=path, type_comments=True)
            module_callables = {
                node.name
                for node in tree.body
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                )
            }
            visitor = _BehaviorVisitor(
                path,
                self.limits.max_events,
                module_callables=module_callables,
            )
            visitor.visit(tree)
        except (RecursionError, SyntaxError, ValueError) as error:
            result.parse_error = _format_parse_error(error)
            return result
        result.events = visitor.events
        result.event_limit_reached = visitor.event_limit_reached
        dataflow_paths = []
        if self.enable_dataflow and _has_dataflow_candidate(visitor.events):
            try:
                dataflow_paths = build_local_dataflow_paths(
                    tree,
                    visitor.events,
                    visitor.node_events,
                    visitor.call_names,
                )
            except (RecursionError, ValueError) as error:
                result.parse_error = (
                    f"local provenance analysis stopped: {_format_parse_error(error)}"
                )
        result.behavior_paths = build_behavior_paths(
            result.events,
            dataflow_paths=dataflow_paths,
        )
        return result


class _BehaviorVisitor(ast.NodeVisitor):
    def __init__(
        self,
        path: str,
        max_events: int,
        *,
        module_callables: set[str] | None = None,
    ) -> None:
        self.path = path
        self.max_events = max_events
        self.module_callables = module_callables or set()
        self.events: list[Event] = []
        self.event_limit_reached = False
        self.aliases: dict[str, str] = {}
        self.function_stack: list[str] = []
        self.node_events: dict[int, list[int]] = {}
        self.call_names: dict[int, str] = {}

    @property
    def function(self) -> str:
        return self.function_stack[-1] if self.function_stack else "<module>"

    @property
    def phase(self) -> str:
        filename = Path(self.path).name.lower()
        install_names = {"setup", "install", "post_install", "build", "develop"}
        if filename == "setup.py" and not self.function_stack:
            return "install"
        if self.function_stack and self.function_stack[-1] in install_names:
            return "install"
        return "import" if not self.function_stack else "runtime"

    def _add(
        self,
        node: ast.AST,
        op: str,
        category: str,
        target: str,
        detail: str,
    ) -> None:
        if len(self.events) >= self.max_events:
            self.event_limit_reached = True
            return
        event_index = len(self.events)
        self.events.append(
            Event(
                op=op,
                category=category,
                target=target or "unknown",
                path=self.path,
                line=getattr(node, "lineno", 0),
                column=getattr(node, "col_offset", 0),
                function=self.function,
                phase=self.phase,
                detail=detail,
            )
        )
        self.node_events.setdefault(id(node), []).append(event_index)

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            local = item.asname or item.name.split(".")[0]
            self.aliases[local] = item.name
            self._add(node, "IMPORT", "context", item.name, "module import")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for item in node.names:
            full_name = f"{module}.{item.name}".strip(".")
            self.aliases[item.asname or item.name] = full_name
            self._add(node, "IMPORT", "context", full_name, "symbol import")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        qualified = self._alias_value(node.value)
        if qualified:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.aliases[target.id] = qualified
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        qualified = self._alias_value(node.value)
        if isinstance(node.target, ast.Name) and qualified:
            self.aliases[node.target.id] = qualified
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Subscript(self, node: ast.Subscript) -> None:
        name = self._qualified_name(node.value)
        if name in {"os.environ", "environ"}:
            key = self._literal(node.slice) or "environment"
            self._add(node, "ENV_READ", "source", key, "environment variable access")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Arguments are visited first so nested source/transform operations
        # precede the outer sink in the behavior sequence.
        for child in ast.iter_child_nodes(node):
            self.visit(child)
        name = self._qualified_name(node.func) or "unknown"
        self.call_names[id(node)] = name
        if name in {"open", "builtins.open", "io.open"}:
            self._handle_open(node, name)
            return
        classified = classify_call(name)
        if classified:
            op, category, detail = classified
            if name == "urllib.request.urlopen" and not self._has_payload(node):
                op, category, detail = (
                    "NETWORK_RECEIVE",
                    "source",
                    "remote communication",
                )
            target = self._call_target(node, name) or name
            if op == "FILE_READ" and is_sensitive_path(target):
                op, detail = "SENSITIVE_FILE_READ", "sensitive file access"
            if op == "FILE_WRITE" and is_persistence_path(target):
                op, detail = "PERSISTENCE_WRITE", "autostart location write"
            self._add(node, op, category, target, detail)

    def _handle_open(self, node: ast.Call, name: str) -> None:
        path = self._literal(node.args[0]) if node.args else None
        mode = self._literal(node.args[1]) if len(node.args) > 1 else None
        for keyword in node.keywords:
            if keyword.arg == "mode":
                mode = self._literal(keyword.value)
        mode = mode or "r"
        write = any(flag in mode for flag in ("w", "a", "x", "+"))
        if write:
            op, category, detail = "FILE_WRITE", "sink", "file write"
            if is_persistence_path(path):
                op, detail = "PERSISTENCE_WRITE", "autostart location write"
        else:
            op, category, detail = "FILE_READ", "source", "file read"
            if is_sensitive_path(path):
                op, detail = "SENSITIVE_FILE_READ", "sensitive file access"
        self._add(node, op, category, path or name, detail)

    @staticmethod
    def _has_payload(node: ast.Call) -> bool:
        if len(node.args) > 1:
            return True
        return any(
            item.arg in {"data", "json", "files", "content"} for item in node.keywords
        )

    def _call_target(self, node: ast.Call, name: str) -> str | None:
        file_methods = (*READ_METHODS, *WRITE_METHODS)
        if any(name.endswith(method) for method in file_methods):
            return self._receiver_path_target(node) or name
        for keyword in node.keywords:
            if keyword.arg in {"url", "filename", "path", "data"}:
                value = self._literal(keyword.value)
                if value:
                    return value
        if node.args:
            return self._literal(node.args[0])
        return None

    def _receiver_path_target(self, node: ast.Call) -> str | None:
        if not isinstance(node.func, ast.Attribute):
            return None
        receiver = node.func.value
        if not isinstance(receiver, ast.Call) or not receiver.args:
            return None
        factory = self._qualified_name(receiver.func)
        if factory not in {
            "Path",
            "pathlib.Path",
            "open",
            "builtins.open",
            "io.open",
        }:
            return None
        return self._literal(receiver.args[0])

    def _alias_value(self, node: ast.AST | None) -> str | None:
        if isinstance(node, (ast.Name, ast.Attribute)):
            return self._qualified_name(node)
        if isinstance(node, ast.Call):
            factory = self._qualified_name(node.func)
            if factory in {
                "aiohttp.ClientSession",
                "httpx.Client",
                "requests.Session",
                "socket.socket",
            }:
                return factory
        return None

    def _qualified_name(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Name):
            resolved = self.aliases.get(node.id)
            if resolved is not None:
                return resolved
            if node.id in self.module_callables:
                return f"<module>.{node.id}"
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._qualified_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        if isinstance(node, ast.Call):
            return self._qualified_name(node.func)
        return None

    def _literal(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            if isinstance(node.value, bytes):
                return f"<bytes:{len(node.value)}>"
            return node.value[:240]
        if isinstance(node, ast.JoinedStr):
            values = [
                item.value
                for item in node.values
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            ]
            return "".join(values)[:240] + "<dynamic>"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self._literal(node.left), self._literal(node.right)
            if left is not None and right is not None:
                return (left + right)[:240]
        return None


def _has_dataflow_candidate(events: list[Event]) -> bool:
    """Cheap gate for the bounded second AST pass, scoped per callable."""
    operations_by_function: dict[str, set[str]] = {}
    for event in events:
        operations_by_function.setdefault(event.function, set()).add(event.op)
    for operations in operations_by_function.values():
        if "NETWORK_SEND" in operations and operations & _DATAFLOW_SEND_SOURCES:
            return True
        if operations & _DATAFLOW_EXEC_SINKS and operations & _DATAFLOW_EXEC_SOURCES:
            return True
    return False


def _format_parse_error(error: Exception) -> str:
    if isinstance(error, SyntaxError):
        return f"{error.msg} (line {error.lineno or 0})"
    return str(error)
