"""Bounded, name-independent local value provenance for MalIR.

This module performs a second AST pass after event extraction. It never imports
or executes inspected code. The analysis is deliberately intraprocedural and
flow-sensitive for straight-line assignments, with conservative branch joins.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from .motifs import make_dataflow_path
from .types import BehaviorPath, Event

Trace = tuple[int, ...]
Traces = tuple[Trace, ...]

VALUE_SOURCES = {
    "ENV_READ",
    "SENSITIVE_FILE_READ",
    "FILE_READ",
    "SYSTEM_DISCOVERY",
    "NETWORK_RECEIVE",
}
VALUE_TRANSFORMS = {
    "ENCODE",
    "DECODE",
    "UNSAFE_DESERIALIZE",
    "DYNAMIC_IMPORT",
}
EXECUTION_SINKS = {"DYNAMIC_EXEC", "PROCESS_EXEC"}
_FILE_STAGE_PREFIX = "\0malir-file-stage:"
_PROCESS_LAUNCHERS = {
    "bash",
    "cmd",
    "node",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pypy",
    "pypy3",
    "python",
    "python.exe",
    "python3",
    "pythonw",
    "pythonw.exe",
    "sh",
    "start",
    "wscript",
    "wscript.exe",
    "zsh",
}


def build_local_dataflow_paths(
    tree: ast.AST,
    events: list[Event],
    node_events: dict[int, list[int]],
    call_names: dict[int, str],
    *,
    max_traces_per_value: int = 16,
    max_trace_length: int = 16,
    max_paths: int = 256,
) -> list[BehaviorPath]:
    """Return bounded source-to-sink paths within individual callables."""
    analyzer = _LocalFlowAnalyzer(
        events,
        node_events,
        call_names,
        max_traces_per_value=max_traces_per_value,
        max_trace_length=max_trace_length,
        max_paths=max_paths,
    )
    return analyzer.analyze(tree)


class _LocalFlowAnalyzer:
    def __init__(
        self,
        events: list[Event],
        node_events: dict[int, list[int]],
        call_names: dict[int, str],
        *,
        max_traces_per_value: int,
        max_trace_length: int,
        max_paths: int,
    ) -> None:
        self.events = events
        self.node_events = node_events
        self.call_names = call_names
        self.max_traces_per_value = max_traces_per_value
        self.max_trace_length = max_trace_length
        self.max_paths = max_paths
        self.env: dict[str, Traces] = {}
        self.paths: list[BehaviorPath] = []
        self.path_keys: set[tuple[str, tuple[int, ...]]] = set()
        self.file_handles: dict[str, str] = {}

    def analyze(self, tree: ast.AST) -> list[BehaviorPath]:
        if isinstance(tree, ast.Module):
            self._block(tree.body)
        return sorted(
            self.paths,
            key=lambda item: (item.event_indexes, item.motif),
        )

    def _block(self, statements: Iterable[ast.stmt]) -> None:
        for statement in statements:
            self._statement(statement)

    def _statement(self, node: ast.stmt) -> None:
        if isinstance(node, ast.Assign):
            traces = self._expr(node.value)
            for target in node.targets:
                self._assign(target, traces)
            return
        if isinstance(node, ast.AnnAssign):
            traces = self._expr(node.value) if node.value is not None else ()
            self._assign(node.target, traces)
            return
        if isinstance(node, ast.AugAssign):
            traces = self._merge(self._expr(node.target), self._expr(node.value))
            self._assign(node.target, traces)
            return
        if isinstance(node, ast.Expr):
            self._expr(node.value)
            return
        if isinstance(node, (ast.Return, ast.Raise)):
            value = getattr(node, "value", None) or getattr(node, "exc", None)
            if value is not None:
                self._expr(value)
            cause = getattr(node, "cause", None)
            if cause is not None:
                self._expr(cause)
            return
        if isinstance(node, ast.Assert):
            self._expr(node.test)
            if node.msg is not None:
                self._expr(node.msg)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._function(node)
            return
        if isinstance(node, ast.ClassDef):
            self._class(node)
            return
        if isinstance(node, ast.If):
            self._expr(node.test)
            base = self._copy_env(self.env)
            body = self._run_branch(node.body, base)
            otherwise = self._run_branch(node.orelse, base)
            self.env = self._merge_env(body, otherwise)
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            iterable = self._expr(node.iter)
            base = self._copy_env(self.env)
            self.env = self._copy_env(base)
            self._assign(node.target, iterable)
            self._block(node.body)
            loop = self._copy_env(self.env)
            joined = self._merge_env(base, loop)
            otherwise = self._run_branch(node.orelse, joined)
            self.env = self._merge_env(joined, otherwise)
            return
        if isinstance(node, ast.While):
            self._expr(node.test)
            base = self._copy_env(self.env)
            body = self._run_branch(node.body, base)
            joined = self._merge_env(base, body)
            otherwise = self._run_branch(node.orelse, joined)
            self.env = self._merge_env(joined, otherwise)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            previous_handles = dict(self.file_handles)
            for item in node.items:
                traces = self._expr(item.context_expr)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, traces)
                    if isinstance(item.optional_vars, ast.Name):
                        path_name = self._open_path_name(item.context_expr)
                        if path_name is not None:
                            self.file_handles[item.optional_vars.id] = path_name
            self._block(node.body)
            self.file_handles = previous_handles
            return
        if isinstance(node, (ast.Try, ast.TryStar)):
            self._try(node)
            return
        if isinstance(node, ast.Match):
            self._match(node)
            return
        if isinstance(node, ast.Import):
            for item in node.names:
                self.env[item.asname or item.name.split(".")[0]] = ()
            return
        if isinstance(node, ast.ImportFrom):
            for item in node.names:
                self.env[item.asname or item.name] = ()
            return
        if isinstance(node, ast.Delete):
            for target in node.targets:
                self._delete(target)
            return

        # Future Python syntax should be analyzed conservatively rather than
        # silently dropping expression children.
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._expr(child)
            elif isinstance(child, ast.stmt):
                self._statement(child)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self._expr(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self._expr(default)
        if node.returns is not None:
            self._expr(node.returns)

        outer = self.env
        outer_handles = self.file_handles
        self.env = {}
        self.file_handles = {}
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ):
            self.env[argument.arg] = ()
        if node.args.vararg is not None:
            self.env[node.args.vararg.arg] = ()
        if node.args.kwarg is not None:
            self.env[node.args.kwarg.arg] = ()
        self._block(node.body)
        self.env = outer
        self.file_handles = outer_handles

    def _class(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self._expr(decorator)
        for base in node.bases:
            self._expr(base)
        for keyword in node.keywords:
            self._expr(keyword.value)
        outer = self.env
        outer_handles = self.file_handles
        self.env = {}
        self.file_handles = {}
        self._block(node.body)
        self.env = outer
        self.file_handles = outer_handles

    def _try(self, node: ast.Try | ast.TryStar) -> None:
        base = self._copy_env(self.env)
        body = self._run_branch(node.body, base)
        normal = self._run_branch(node.orelse, body)
        branches = [normal]
        for handler in node.handlers:
            self.env = self._copy_env(base)
            if handler.type is not None:
                self._expr(handler.type)
            if handler.name:
                self.env[handler.name] = ()
            self._block(handler.body)
            branches.append(self._copy_env(self.env))
        self.env = self._merge_env(*branches)
        self._block(node.finalbody)

    def _match(self, node: ast.Match) -> None:
        subject = self._expr(node.subject)
        base = self._copy_env(self.env)
        branches: list[dict[str, Traces]] = [base]
        for case in node.cases:
            self.env = self._copy_env(base)
            self._bind_pattern(case.pattern, subject)
            if case.guard is not None:
                self._expr(case.guard)
            self._block(case.body)
            branches.append(self._copy_env(self.env))
        self.env = self._merge_env(*branches)

    def _expr(self, node: ast.AST | None) -> Traces:
        if node is None or isinstance(node, ast.Constant):
            return ()
        if isinstance(node, ast.Name):
            return self.env.get(node.id, ())
        if isinstance(node, ast.Attribute):
            return self._expr(node.value)
        if isinstance(node, ast.Subscript):
            inherited = self._merge(self._expr(node.value), self._expr(node.slice))
            event_index = self._event_index(node)
            if event_index is not None and self.events[event_index].op in VALUE_SOURCES:
                return ((event_index,),)
            return inherited
        if isinstance(node, ast.Call):
            return self._call(node)
        if isinstance(node, ast.NamedExpr):
            traces = self._expr(node.value)
            self._assign(node.target, traces)
            return traces
        if isinstance(node, ast.Lambda):
            return ()
        if isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom, ast.Starred)):
            return self._expr(node.value)
        if isinstance(node, ast.IfExp):
            return self._merge(
                self._expr(node.test),
                self._expr(node.body),
                self._expr(node.orelse),
            )
        if isinstance(node, ast.BoolOp):
            return self._merge(*(self._expr(value) for value in node.values))
        if isinstance(node, ast.BinOp):
            return self._merge(self._expr(node.left), self._expr(node.right))
        if isinstance(node, ast.UnaryOp):
            return self._expr(node.operand)
        if isinstance(node, ast.Compare):
            return self._merge(
                self._expr(node.left),
                *(self._expr(item) for item in node.comparators),
            )
        if isinstance(node, ast.JoinedStr):
            return self._merge(*(self._expr(value) for value in node.values))
        if isinstance(node, ast.FormattedValue):
            return self._merge(self._expr(node.value), self._expr(node.format_spec))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._merge(*(self._expr(item) for item in node.elts))
        if isinstance(node, ast.Dict):
            values = [self._expr(item) for item in node.keys if item is not None]
            values.extend(self._expr(item) for item in node.values)
            return self._merge(*values)
        if isinstance(
            node,
            (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp),
        ):
            return self._comprehension(node)

        return self._merge(
            *(
                self._expr(child)
                for child in ast.iter_child_nodes(node)
                if isinstance(child, ast.expr)
            )
        )

    def _call(self, node: ast.Call) -> Traces:
        function_traces = self._expr(node.func)
        arguments = [self._expr(argument) for argument in node.args]
        keywords = [
            (keyword.arg, self._expr(keyword.value)) for keyword in node.keywords
        ]
        event_index = self._event_index(node)
        all_inputs = self._merge(
            function_traces,
            *arguments,
            *(traces for _, traces in keywords),
        )
        if event_index is None:
            return all_inputs

        operation = self.events[event_index].op
        if operation in VALUE_SOURCES:
            if operation in {"FILE_READ", "SENSITIVE_FILE_READ"} and all_inputs:
                return self._append_event(
                    all_inputs,
                    event_index,
                    origin_if_empty=True,
                )
            return ((event_index,),)
        if operation in VALUE_TRANSFORMS:
            return self._append_event(all_inputs, event_index, origin_if_empty=True)
        if operation == "FILE_WRITE":
            self._record_file_stage(node, event_index, arguments, keywords)
            return all_inputs
        if operation in EXECUTION_SINKS or operation == "NETWORK_SEND":
            payload = self._sink_payload(
                node,
                operation,
                arguments,
                keywords,
            )
            self._record_sink(event_index, payload)
            return ()
        return all_inputs

    def _sink_payload(
        self,
        node: ast.Call,
        operation: str,
        arguments: list[Traces],
        keywords: list[tuple[str | None, Traces]],
    ) -> Traces:
        name = self.call_names.get(id(node), "")
        selected: list[Traces] = []
        if operation == "NETWORK_SEND":
            payload_names = {"data", "json", "files", "content", "body", "payload"}
            selected.extend(
                traces
                for keyword, traces in keywords
                if keyword is None or keyword in payload_names
            )
            if name.endswith((".send", ".sendall")):
                selected.extend(arguments[:1])
            else:
                selected.extend(arguments[1:])
        else:
            command_names = {
                "args",
                "cmd",
                "command",
                "code",
                "source",
                "object",
                "executable",
            }
            selected.extend(arguments[:1])
            selected.extend(
                traces
                for keyword, traces in keywords
                if keyword is None or keyword in command_names
            )
            if operation == "PROCESS_EXEC":
                selected.append(self._staged_file_traces(node, command_names))
        return self._merge(*selected)

    def _record_file_stage(
        self,
        node: ast.Call,
        event_index: int,
        arguments: list[Traces],
        keywords: list[tuple[str | None, Traces]],
    ) -> None:
        name = self.call_names.get(id(node), "")
        if name in {"open", "builtins.open", "io.open"}:
            return
        destination = self._file_destination_name(node)
        if destination is None:
            return
        payload = self._merge(
            *arguments,
            *(
                traces
                for keyword, traces in keywords
                if keyword not in {"path", "filename"}
            ),
        )
        staged = self._append_event(payload, event_index, origin_if_empty=False)
        remote = tuple(
            trace
            for trace in staged
            if any(self.events[index].op == "NETWORK_RECEIVE" for index in trace)
        )
        if not remote:
            return
        key = self._file_stage_key(destination)
        self.env[key] = self._merge(self.env.get(key, ()), remote)

    def _staged_file_traces(self, node: ast.Call, command_names: set[str]) -> Traces:
        expressions: list[ast.AST] = list(node.args[:1])
        expressions.extend(
            keyword.value
            for keyword in node.keywords
            if keyword.arg is None or keyword.arg in command_names
        )
        names = set().union(
            *(self._execution_path_names(expression) for expression in expressions)
        )
        return self._merge(
            *(self.env.get(self._file_stage_key(name), ()) for name in names)
        )

    def _execution_path_names(self, node: ast.AST) -> set[str]:
        staged = self._staged_names(node)
        if not staged:
            return set()
        if isinstance(node, ast.Name):
            return staged
        if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
            direct = self._staged_names(node.elts[0])
            if direct:
                return direct
            if self._is_process_launcher(node.elts[0]):
                return set().union(
                    *(self._staged_names(item) for item in node.elts[1:])
                )
            return set()
        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            prefix = self._static_command_prefix(node).lstrip()
            if not prefix or prefix.startswith(("./", ".\\")):
                return staged
            head = prefix.split(maxsplit=1)[0].strip("\"'").lower()
            if head.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] in _PROCESS_LAUNCHERS:
                return staged
        return set()

    def _staged_names(self, node: ast.AST) -> set[str]:
        return {
            child.id
            for child in ast.walk(node)
            if isinstance(child, ast.Name)
            and self.env.get(self._file_stage_key(child.id))
        }

    @staticmethod
    def _is_process_launcher(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            name = node.value.strip().lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            return name in _PROCESS_LAUNCHERS
        return (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "sys"
            and node.attr == "executable"
        )

    @classmethod
    def _static_command_prefix(cls, node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return ""
        if isinstance(node, ast.JoinedStr):
            output = []
            for item in node.values:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    output.append(item.value)
                    continue
                break
            return "".join(output)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = cls._static_command_prefix(node.left)
            if cls._statically_complete_string(node.left):
                return left + cls._static_command_prefix(node.right)
            return left
        return ""

    @staticmethod
    def _statically_complete_string(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    def _file_destination_name(self, node: ast.Call) -> str | None:
        if not isinstance(node.func, ast.Attribute):
            return None
        receiver = node.func.value
        if isinstance(receiver, ast.Name):
            return self.file_handles.get(receiver.id)
        if not isinstance(receiver, ast.Call) or not receiver.args:
            return None
        receiver_name = self.call_names.get(id(receiver), "")
        if receiver_name in {
            "open",
            "builtins.open",
            "io.open",
            "Path",
            "pathlib.Path",
        }:
            return self._name_expression(receiver.args[0])
        return None

    def _open_path_name(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Call) or not node.args:
            return None
        name = self.call_names.get(id(node), "")
        if name not in {"open", "builtins.open", "io.open"}:
            return None
        return self._name_expression(node.args[0])

    @staticmethod
    def _name_expression(node: ast.AST) -> str | None:
        return node.id if isinstance(node, ast.Name) else None

    @staticmethod
    def _file_stage_key(name: str) -> str:
        return f"{_FILE_STAGE_PREFIX}{name}"

    def _record_sink(self, sink_index: int, traces: Traces) -> None:
        sink = self.events[sink_index]
        for trace in traces:
            chain = self._append_trace(trace, sink_index)
            operations = [self.events[index].op for index in chain]
            if sink.op == "NETWORK_SEND":
                if any(
                    operation in {"ENV_READ", "SENSITIVE_FILE_READ"}
                    for operation in operations
                ):
                    self._record_from_operation(
                        "credential_or_file_exfil",
                        chain,
                        {"ENV_READ", "SENSITIVE_FILE_READ"},
                    )
                if "SYSTEM_DISCOVERY" in operations:
                    self._record_from_operation(
                        "fingerprinting_transfer",
                        chain,
                        {"SYSTEM_DISCOVERY"},
                    )
                if "FILE_READ" in operations:
                    self._record_from_operation(
                        "file_to_network",
                        chain,
                        {"FILE_READ"},
                    )
            if sink.op in EXECUTION_SINKS:
                if "NETWORK_RECEIVE" in operations:
                    self._record_from_operation(
                        "download_execute",
                        chain,
                        {"NETWORK_RECEIVE"},
                    )
                if any(
                    operation in {"DECODE", "UNSAFE_DESERIALIZE"}
                    for operation in operations
                ):
                    self._record_from_operation(
                        "encoded_execution",
                        chain,
                        {"DECODE", "UNSAFE_DESERIALIZE"},
                    )

    def _record_from_operation(
        self,
        motif: str,
        chain: Trace,
        operations: set[str],
    ) -> None:
        start = next(
            index
            for index, event_index in enumerate(chain)
            if self.events[event_index].op in operations
        )
        indexes = chain[start:]
        key = motif, indexes
        if key in self.path_keys or len(self.paths) >= self.max_paths:
            return
        self.path_keys.add(key)
        self.paths.append(make_dataflow_path(motif, indexes))

    def _comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
    ) -> Traces:
        outer = self.env
        self.env = self._copy_env(outer)
        inherited: list[Traces] = []
        for generator in node.generators:
            iterable = self._expr(generator.iter)
            inherited.append(iterable)
            self._assign(generator.target, iterable)
            inherited.extend(self._expr(condition) for condition in generator.ifs)
        if isinstance(node, ast.DictComp):
            inherited.extend((self._expr(node.key), self._expr(node.value)))
        else:
            inherited.append(self._expr(node.elt))
        result = self._merge(*inherited)
        self.env = outer
        return result

    def _assign(self, target: ast.AST, traces: Traces) -> None:
        if isinstance(target, ast.Name):
            self.env.pop(self._file_stage_key(target.id), None)
            self.env[target.id] = traces
            return
        if isinstance(target, ast.Starred):
            self._assign(target.value, traces)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign(item, traces)
            return
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            self._expr(target.value)

    def _delete(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.env.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._delete(item)

    def _bind_pattern(self, pattern: ast.pattern, traces: Traces) -> None:
        if isinstance(pattern, ast.MatchAs):
            if pattern.name:
                self.env[pattern.name] = traces
            if pattern.pattern is not None:
                self._bind_pattern(pattern.pattern, traces)
        elif isinstance(pattern, ast.MatchStar):
            if pattern.name:
                self.env[pattern.name] = traces
        elif isinstance(pattern, ast.MatchMapping):
            if pattern.rest:
                self.env[pattern.rest] = traces
            for item in pattern.patterns:
                self._bind_pattern(item, traces)
        elif isinstance(pattern, ast.MatchSequence):
            for item in pattern.patterns:
                self._bind_pattern(item, traces)
        elif isinstance(pattern, ast.MatchClass):
            for item in (*pattern.patterns, *pattern.kwd_patterns):
                self._bind_pattern(item, traces)
        elif isinstance(pattern, ast.MatchOr):
            for item in pattern.patterns:
                self._bind_pattern(item, traces)

    def _event_index(self, node: ast.AST) -> int | None:
        indexes = self.node_events.get(id(node))
        return indexes[-1] if indexes else None

    def _append_event(
        self,
        traces: Traces,
        event_index: int,
        *,
        origin_if_empty: bool,
    ) -> Traces:
        if not traces:
            return ((event_index,),) if origin_if_empty else ()
        return self._merge(
            *(self._append_trace(trace, event_index) for trace in traces)
        )

    def _append_trace(self, trace: Trace, event_index: int) -> Trace:
        if trace and trace[-1] == event_index:
            return trace
        result = (*trace, event_index)
        if len(result) <= self.max_trace_length:
            return result
        keep = self.max_trace_length - 1
        return (result[0], *result[-keep:])

    def _merge(self, *groups: Traces | Trace) -> Traces:
        output: list[Trace] = []
        seen: set[Trace] = set()
        for group in groups:
            if not group:
                continue
            candidates: Iterable[Trace]
            if isinstance(group[0], int):
                candidates = (group,)  # type: ignore[arg-type]
            else:
                candidates = group  # type: ignore[assignment]
            for trace in candidates:
                if trace in seen:
                    continue
                seen.add(trace)
                output.append(trace)
                if len(output) >= self.max_traces_per_value:
                    return tuple(output)
        return tuple(output)

    @staticmethod
    def _copy_env(environment: dict[str, Traces]) -> dict[str, Traces]:
        return dict(environment)

    def _run_branch(
        self,
        statements: Iterable[ast.stmt],
        base: dict[str, Traces],
    ) -> dict[str, Traces]:
        previous = self.env
        self.env = self._copy_env(base)
        self._block(statements)
        result = self._copy_env(self.env)
        self.env = previous
        return result

    def _merge_env(
        self,
        *environments: dict[str, Traces],
    ) -> dict[str, Traces]:
        output: dict[str, Traces] = {}
        names = set().union(*(environment.keys() for environment in environments))
        for name in names:
            output[name] = self._merge(
                *(environment.get(name, ()) for environment in environments)
            )
        return output
