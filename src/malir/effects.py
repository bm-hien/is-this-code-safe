"""Bounded effect and purpose-candidate summaries for Python MalIR.

The summary describes statically reachable effects; it does not infer author intent
or execute inspected source. Purpose labels are conservative, evidence-backed
candidates intended as model context and analyst guidance.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from collections.abc import Iterable

from .types import BehaviorPath, EffectSummary, Event, PurposeCandidate

_ORIGINS = {
    "BROWSER_COOKIE_READ": "browser-session",
    "ENV_READ": "environment",
    "SENSITIVE_FILE_READ": "sensitive-local-file",
    "FILE_READ": "local-file",
    "SYSTEM_DISCOVERY": "host-state",
    "NETWORK_RECEIVE": "network",
}
_DESTINATIONS = {
    "FILE_WRITE": "local-artifact",
    "NETWORK_SEND": "network",
    "PROCESS_EXEC": "process",
    "PERSISTENCE_WRITE": "persistence",
    "FILE_DELETE": "filesystem-delete",
}
_TRANSFORMATIONS = {
    "ENCODE": "encoding",
    "DECODE": "decoding",
    "DYNAMIC_IMPORT": "dynamic-loading",
    "CODE_COMPILE": "code-compilation",
    "DYNAMIC_EXEC": "dynamic-execution",
    "UNSAFE_DESERIALIZE": "unsafe-deserialization",
}
_FLOW_BY_MOTIF = {
    "browser_session_transfer": "browser-session-to-network",
    "credential_or_file_exfil": "sensitive-data-to-network",
    "fingerprinting_transfer": "host-state-to-network",
    "file_to_network": "local-file-to-network",
    "download_execute": "network-to-execution",
    "encoded_execution": "encoded-data-to-execution",
    "persistence_write": "code-to-persistence",
    "destructive_file_action": "code-to-filesystem-delete",
}
_PURPOSE_BY_MOTIF = {
    "browser_session_transfer": (
        "sensitive-data-transfer",
        "high",
        "browser session cookies reach an outbound transfer",
    ),
    "credential_or_file_exfil": (
        "sensitive-data-transfer",
        "high",
        "a sensitive source reaches an outbound transfer",
    ),
    "download_execute": (
        "remote-code-executor",
        "high",
        "remote input reaches code or process execution",
    ),
    "persistence_write": (
        "persistence-modifier",
        "high",
        "an autostart destination is modified",
    ),
    "destructive_file_action": (
        "destructive-file-operator",
        "high",
        "a filesystem deletion effect is present",
    ),
}
_LOCAL_TRANSFORM_BLOCKERS = {
    "BROWSER_COOKIE_READ",
    "NETWORK_RECEIVE",
    "NETWORK_SEND",
    "PROCESS_EXEC",
    "PERSISTENCE_WRITE",
    "SENSITIVE_FILE_READ",
}
_IMPORT_TIME_EFFECTS = {
    "DYNAMIC_EXEC",
    "PROCESS_EXEC",
    "NETWORK_SEND",
    "PERSISTENCE_WRITE",
    "FILE_DELETE",
}


class _DirectCallCollector(ast.NodeVisitor):
    def __init__(self, candidates: set[str]) -> None:
        self.candidates = candidates
        self.calls: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in self.candidates:
            self.calls.add(node.func.id)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return None

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return None


def build_effect_summary(
    tree: ast.AST,
    events: list[Event],
    behavior_paths: list[BehaviorPath],
) -> EffectSummary:
    """Return a language-neutral summary backed by Python AST structure."""

    origins = tuple(
        sorted({_ORIGINS[event.op] for event in events if event.op in _ORIGINS})
    )
    destinations = tuple(
        sorted(
            {_DESTINATIONS[event.op] for event in events if event.op in _DESTINATIONS}
        )
    )
    transformations = {
        _TRANSFORMATIONS[event.op] for event in events if event.op in _TRANSFORMATIONS
    }
    functions = _top_level_functions(tree)
    guards = _main_guards(tree)
    roots = _main_roots(guards, set(functions))
    reachable = _reachable_functions(functions, roots)
    pipelines = _local_file_pipelines(events)
    anchors, anchor_lines = _code_transform_anchors(tree, set(functions))
    if len(anchors) >= 2:
        transformations.add("code-generation")

    entrypoints: list[str] = []
    if guards:
        entrypoints.append("explicit-cli")
    if _has_import_time_effect(events, guards):
        entrypoints.append("import-time-effects")
    if not guards and functions:
        entrypoints.append("library-callable")
    if not entrypoints:
        entrypoints.append("module-import")
    flows = {
        _FLOW_BY_MOTIF[path.motif]
        for path in behavior_paths
        if path.motif in _FLOW_BY_MOTIF and path.evidence_kind != "proximity"
    }
    reachable_pipeline = pipelines & reachable
    if reachable_pipeline or (not guards and pipelines):
        flows.add("local-file-to-local-artifact")

    candidates = _motif_candidates(events, behavior_paths)
    operations = {event.op for event in events}
    blocked = bool(operations & _LOCAL_TRANSFORM_BLOCKERS)
    local_pipeline = bool(reachable_pipeline or (not guards and pipelines))
    if local_pipeline and len(anchors) >= 2 and not blocked and not candidates:
        confidence = "high" if guards and reachable_pipeline else "medium"
        pipeline_lines = {
            event.line
            for event in events
            if event.function in pipelines and event.op in {"FILE_READ", "FILE_WRITE"}
        }
        lines = tuple(sorted(pipeline_lines | anchor_lines)[:12])
        candidates.append(
            PurposeCandidate(
                label="local-code-transformer",
                confidence=confidence,
                reason=(
                    "an explicit local-file input/output pipeline is combined "
                    "with AST or compiler transformations"
                ),
                lines=lines,
            )
        )

    return EffectSummary(
        entrypoints=tuple(entrypoints),
        data_origins=origins,
        data_destinations=destinations,
        transformations=tuple(sorted(transformations)),
        flows=tuple(sorted(flows)),
        purpose_candidates=tuple(candidates),
    )


def _top_level_functions(
    tree: ast.AST,
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    if not isinstance(tree, ast.Module):
        return {}
    grouped: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = defaultdict(list)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            grouped[node.name].append(node)
    return {name: nodes[0] for name, nodes in grouped.items() if len(nodes) == 1}


def _main_guards(tree: ast.AST) -> list[ast.If]:
    if not isinstance(tree, ast.Module):
        return []
    return [
        node
        for node in tree.body
        if isinstance(node, ast.If) and _is_main_guard(node.test)
    ]


def _is_main_guard(node: ast.AST) -> bool:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return False
    if not isinstance(node.ops[0], ast.Eq) or len(node.comparators) != 1:
        return False
    left = node.left
    right = node.comparators[0]
    return (
        isinstance(left, ast.Name)
        and left.id == "__name__"
        and isinstance(right, ast.Constant)
        and right.value == "__main__"
    ) or (
        isinstance(right, ast.Name)
        and right.id == "__name__"
        and isinstance(left, ast.Constant)
        and left.value == "__main__"
    )


def _direct_calls(statements: Iterable[ast.stmt], candidates: set[str]) -> set[str]:
    collector = _DirectCallCollector(candidates)
    for statement in statements:
        collector.visit(statement)
    return collector.calls


def _main_roots(guards: list[ast.If], candidates: set[str]) -> set[str]:
    roots: set[str] = set()
    for guard in guards:
        roots.update(_direct_calls(guard.body, candidates))
    return roots


def _reachable_functions(
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    roots: set[str],
) -> set[str]:
    candidates = set(functions)
    edges = {
        name: _direct_calls(node.body, candidates) for name, node in functions.items()
    }
    reachable: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        reachable.add(name)
        pending.extend(edges.get(name, ()) - reachable)
    return reachable


def _local_file_pipelines(events: list[Event]) -> set[str]:
    operations: dict[str, set[str]] = defaultdict(set)
    for event in events:
        operations[event.function].add(event.op)
    return {
        function
        for function, items in operations.items()
        if function != "<module>" and "FILE_READ" in items and "FILE_WRITE" in items
    }


def _has_import_time_effect(events: list[Event], guards: list[ast.If]) -> bool:
    ranges = [
        (guard.lineno, getattr(guard, "end_lineno", guard.lineno)) for guard in guards
    ]
    return any(
        event.function == "<module>"
        and event.op in _IMPORT_TIME_EFFECTS
        and not any(start <= event.line <= end for start, end in ranges)
        for event in events
    )


def _motif_candidates(
    events: list[Event],
    paths: list[BehaviorPath],
) -> list[PurposeCandidate]:
    output: list[PurposeCandidate] = []
    seen: set[str] = set()
    for path in paths:
        policy = _PURPOSE_BY_MOTIF.get(path.motif)
        if policy is None:
            continue
        label, _default_confidence, reason = policy
        confidence = path.confidence
        if label in seen:
            continue
        seen.add(label)
        lines = tuple(
            sorted(
                {
                    events[index].line
                    for index in path.event_indexes
                    if 0 <= index < len(events)
                }
            )
        )
        output.append(
            PurposeCandidate(
                label=label,
                confidence=confidence,
                reason=reason,
                lines=lines,
            )
        )
    return output


def _code_transform_anchors(
    tree: ast.AST,
    top_level_names: set[str],
) -> tuple[set[str], set[int]]:
    aliases = _import_aliases(tree)
    anchors: set[str] = set()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(item.name == "ast" for item in node.names):
                anchors.add("ast-api")
                lines.add(node.lineno)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "ast":
                anchors.add("ast-api")
                lines.add(node.lineno)
        elif isinstance(node, ast.ClassDef):
            bases = {_qualified(base, aliases) for base in node.bases}
            if any(
                name.endswith(("NodeVisitor", "NodeTransformer"))
                for name in bases
                if name
            ):
                anchors.add("ast-visitor")
                lines.add(node.lineno)
        elif isinstance(node, ast.Call):
            name = _qualified(node.func, aliases)
            if name in {"ast.parse", "ast.unparse"}:
                anchors.add("ast-api")
                lines.add(node.lineno)
            if (
                name in {"builtins.compile", "compile"}
                and "compile" not in top_level_names
            ):
                anchors.add("runtime-compiler")
                lines.add(node.lineno)
    return anchors, {line for line in lines if line > 0}


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {"builtins": "builtins"}
    if not isinstance(tree, ast.Module):
        return aliases
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for item in node.names:
                aliases[item.asname or item.name] = f"{module}.{item.name}".strip(".")
    return aliases


def _qualified(node: ast.AST | None, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        function = _qualified(node.func, aliases)
        if (
            function in {"__import__", "builtins.__import__"}
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return node.args[0].value
        return function
    return ""
