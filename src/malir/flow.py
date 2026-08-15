"""Bounded, name-independent value provenance for MalIR.

This module performs a second AST pass after event extraction. It never imports
or executes inspected code. The analysis is flow-sensitive within callables and
can cross statically resolved top-level function calls under strict depth and
expansion limits. Globals, attributes, and dynamic dispatch remain isolated.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from .motifs import make_dataflow_path
from .policy import OUTBOUND_REQUEST_CALLS, is_sensitive_env_name
from .types import BehaviorPath, Event

Trace = tuple[int, ...]
Traces = tuple[Trace, ...]

VALUE_SOURCES = {
    "BROWSER_COOKIE_READ",
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
    "CODE_COMPILE",
}
EXECUTION_SINKS = {"DYNAMIC_EXEC", "PROCESS_EXEC"}
_FILE_STAGE_PREFIX = "\0malir-file-stage:"
_SUMMARY_BOUNDARY = -1
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


class _FunctionBindingCollector(ast.NodeVisitor):
    """Collect lexical bindings without descending into nested scopes."""

    def __init__(self) -> None:
        self.names: set[str] = set()
        self.has_star_import = False
        self.has_yield = False

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        self.names.update(item.asname or item.name.split(".")[0] for item in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            if item.name == "*":
                self.has_star_import = True
            else:
                self.names.add(item.asname or item.name)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return None

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self.visit(node.elt)
        self._visit_comprehensions(node.generators)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self.visit(node.elt)
        self._visit_comprehensions(node.generators)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self.visit(node.key)
        self.visit(node.value)
        self._visit_comprehensions(node.generators)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self.visit(node.elt)
        self._visit_comprehensions(node.generators)

    def _visit_comprehensions(
        self,
        generators: list[ast.comprehension],
    ) -> None:
        for generator in generators:
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)

    def visit_Yield(self, node: ast.Yield) -> None:
        self.has_yield = True

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        self.has_yield = True

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.names.add(node.name)
        if node.pattern is not None:
            self.visit(node.pattern)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.names.add(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.names.add(node.rest)
        for pattern in node.patterns:
            self.visit(pattern)


def build_local_dataflow_paths(
    tree: ast.AST,
    events: list[Event],
    node_events: dict[int, list[int]],
    call_names: dict[int, str],
    *,
    max_traces_per_value: int = 16,
    max_trace_length: int = 16,
    max_paths: int = 256,
    max_call_depth: int = 3,
    max_call_expansions: int = 64,
) -> list[BehaviorPath]:
    """Return bounded local and direct-call source-to-sink paths."""
    analyzer = _LocalFlowAnalyzer(
        events,
        node_events,
        call_names,
        max_traces_per_value=max_traces_per_value,
        max_trace_length=max_trace_length,
        max_paths=max_paths,
        max_call_depth=max_call_depth,
        max_call_expansions=max_call_expansions,
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
        max_call_depth: int,
        max_call_expansions: int,
    ) -> None:
        self.events = events
        self.node_events = node_events
        self.call_names = call_names
        self.max_traces_per_value = max_traces_per_value
        self.max_trace_length = max_trace_length
        self.max_paths = max_paths
        self.max_call_depth = max_call_depth
        self.max_call_expansions = max_call_expansions
        self.env: dict[str, Traces] = {}
        self.paths: list[BehaviorPath] = []
        self.path_keys: set[tuple[str, tuple[int, ...]]] = set()
        self.file_handles: dict[str, str] = {}
        self.local_functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.function_local_names: dict[int, set[str]] = {}
        self.generator_function_ids: set[int] = set()
        self.active_calls: set[str] = set()
        self.call_depth = 0
        self.call_expansions = 0
        self.return_frames: list[list[Traces]] = []
        self.local_name_frames: list[set[str]] = []

    def analyze(self, tree: ast.AST) -> list[BehaviorPath]:
        if isinstance(tree, ast.Module):
            definitions: dict[
                str,
                list[ast.FunctionDef | ast.AsyncFunctionDef],
            ] = {}
            rebound_names: set[str] = set()
            has_star_import = False
            for statement in tree.body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    definitions.setdefault(statement.name, []).append(statement)
                    continue
                collector = _FunctionBindingCollector()
                collector.visit(statement)
                rebound_names.update(collector.names)
                has_star_import = has_star_import or collector.has_star_import
            if not has_star_import:
                self.local_functions = {
                    f"<module>.{name}": nodes[0]
                    for name, nodes in definitions.items()
                    if len(nodes) == 1 and name not in rebound_names
                }
            for function in self.local_functions.values():
                self._local_bound_names(function)
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
            path_name = self._open_path_name(node.value)
            for target in node.targets:
                self._assign(target, traces)
                if isinstance(target, ast.Name):
                    if path_name is None:
                        self.file_handles.pop(target.id, None)
                    else:
                        self.file_handles[target.id] = path_name
            return
        if isinstance(node, ast.AnnAssign):
            traces = self._expr(node.value) if node.value is not None else ()
            self._assign(node.target, traces)
            if isinstance(node.target, ast.Name):
                path_name = self._open_path_name(node.value)
                if path_name is None:
                    self.file_handles.pop(node.target.id, None)
                else:
                    self.file_handles[node.target.id] = path_name
            return
        if isinstance(node, ast.AugAssign):
            traces = self._merge(self._expr(node.target), self._expr(node.value))
            self._assign(node.target, traces)
            return
        if isinstance(node, ast.Expr):
            self._expr(node.value)
            return
        if isinstance(node, ast.Return):
            traces = self._expr(node.value)
            if self.return_frames:
                self.return_frames[-1].append(traces)
            return
        if isinstance(node, ast.Raise):
            if node.exc is not None:
                self._expr(node.exc)
            if node.cause is not None:
                self._expr(node.cause)
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
        self.return_frames.append([])
        self.local_name_frames.append(self._local_bound_names(node))
        try:
            self._block(node.body)
        finally:
            self.local_name_frames.pop()
            self.return_frames.pop()
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
        if isinstance(node, ast.Await):
            if isinstance(node.value, ast.Call):
                return self._call(node.value, awaited=True)
            return self._expr(node.value)
        if isinstance(node, (ast.Yield, ast.YieldFrom, ast.Starred)):
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

    def _call(self, node: ast.Call, *, awaited: bool = False) -> Traces:
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
            name = self.call_names.get(id(node), "")
            direct_name = (
                isinstance(node.func, ast.Name) and name == f"<module>.{node.func.id}"
            )
            shadowed = not direct_name or (
                node.func.id in self.env
                or (
                    bool(self.local_name_frames)
                    and (
                        "*" in self.local_name_frames[-1]
                        or node.func.id in self.local_name_frames[-1]
                    )
                )
            )
            function = None if shadowed else self.local_functions.get(name)
            if function is None:
                return all_inputs
            if (
                isinstance(function, ast.AsyncFunctionDef)
                and not awaited
                or self._is_generator(function)
            ):
                return ()
            return self._invoke_local(
                name,
                function,
                arguments,
                keywords,
                all_inputs,
            )

        operation = self.events[event_index].op
        if operation in VALUE_SOURCES:
            if (
                operation == "NETWORK_RECEIVE"
                and self.call_names.get(id(node), "") in OUTBOUND_REQUEST_CALLS
            ):
                self._record_request_sink(
                    event_index,
                    self._request_payload(arguments, keywords),
                )
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

    def _invoke_local(
        self,
        name: str,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        arguments: list[Traces],
        keywords: list[tuple[str | None, Traces]],
        all_inputs: Traces,
    ) -> Traces:
        if self.max_call_depth <= 0 or self.max_call_expansions <= 0:
            return all_inputs
        if (
            self.call_depth >= self.max_call_depth
            or self.call_expansions >= self.max_call_expansions
            or name in self.active_calls
        ):
            return self._mark_summary(all_inputs)

        outer_env = self.env
        outer_handles = self.file_handles
        frame: list[Traces] = []
        self.env = self._bind_arguments(function, arguments, keywords)
        self.file_handles = {}
        self.return_frames.append(frame)
        self.local_name_frames.append(self._local_bound_names(function))
        self.active_calls.add(name)
        self.call_depth += 1
        self.call_expansions += 1
        try:
            self._block(function.body)
            returned = self._merge(*frame)
        finally:
            self.call_depth -= 1
            self.active_calls.remove(name)
            self.local_name_frames.pop()
            self.return_frames.pop()
            self.env = outer_env
            self.file_handles = outer_handles
        return self._mark_summary(returned)

    def _bind_arguments(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        arguments: list[Traces],
        keywords: list[tuple[str | None, Traces]],
    ) -> dict[str, Traces]:
        parameters = (*function.args.posonlyargs, *function.args.args)
        positional_only_count = len(function.args.posonlyargs)
        named = {name: traces for name, traces in keywords if name is not None}
        default_parameters = (
            parameters[-len(function.args.defaults) :] if function.args.defaults else ()
        )
        defaults = {
            parameter.arg: default
            for parameter, default in zip(
                default_parameters,
                function.args.defaults,
                strict=True,
            )
        }
        bound: dict[str, Traces] = {}
        for index, parameter in enumerate(parameters):
            supplied: list[Traces] = []
            if index < len(arguments):
                supplied.append(arguments[index])
            if index >= positional_only_count and parameter.arg in named:
                supplied.append(named[parameter.arg])
            if not supplied and parameter.arg in defaults:
                supplied.append(self._expr(defaults[parameter.arg]))
            bound[parameter.arg] = self._mark_summary(self._merge(*supplied))

        if function.args.vararg is not None:
            bound[function.args.vararg.arg] = self._mark_summary(
                self._merge(*arguments[len(parameters) :])
            )
        for parameter, default in zip(
            function.args.kwonlyargs,
            function.args.kw_defaults,
            strict=True,
        ):
            value = (
                named[parameter.arg] if parameter.arg in named else self._expr(default)
            )
            bound[parameter.arg] = self._mark_summary(value)
        if function.args.kwarg is not None:
            keyword_parameter_names = {
                parameter.arg
                for parameter in (*function.args.args, *function.args.kwonlyargs)
            }
            extras = [
                traces
                for name, traces in keywords
                if name is None or name not in keyword_parameter_names
            ]
            bound[function.args.kwarg.arg] = self._mark_summary(self._merge(*extras))
        return bound

    def _local_bound_names(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
        function_id = id(function)
        cached = self.function_local_names.get(function_id)
        if cached is not None:
            return cached
        collector = _FunctionBindingCollector()
        for statement in function.body:
            collector.visit(statement)
        names = self._parameter_names(function) | collector.names
        if collector.has_star_import:
            names.add("*")
        if collector.has_yield:
            self.generator_function_ids.add(function_id)
        self.function_local_names[function_id] = names
        return names

    def _is_generator(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        self._local_bound_names(function)
        return id(function) in self.generator_function_ids

    @staticmethod
    def _parameter_names(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
        names = {
            argument.arg
            for argument in (
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
            )
        }
        if function.args.vararg is not None:
            names.add(function.args.vararg.arg)
        if function.args.kwarg is not None:
            names.add(function.args.kwarg.arg)
        return names

    def _mark_summary(self, traces: Traces) -> Traces:
        return tuple(
            trace if _SUMMARY_BOUNDARY in trace else (*trace, _SUMMARY_BOUNDARY)
            for trace in traces
        )

    def _request_payload(
        self,
        arguments: list[Traces],
        keywords: list[tuple[str | None, Traces]],
    ) -> Traces:
        selected: list[Traces] = list(arguments[:1])
        selected.extend(
            traces
            for keyword, traces in keywords
            if keyword is None or keyword in {"url", "params"}
        )
        return self._merge(*selected)

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
            if any(
                index >= 0 and self.events[index].op == "NETWORK_RECEIVE"
                for index in trace
            )
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
        names = {
            child.id
            for child in ast.walk(node)
            if isinstance(child, ast.Name)
            and self.env.get(self._file_stage_key(child.id))
        }
        for child in ast.walk(node):
            if not isinstance(child, ast.Constant) or not isinstance(child.value, str):
                continue
            normalized = child.value.replace("\\", "/").strip().lstrip("./")
            if not normalized:
                continue
            candidates = {normalized, normalized.rsplit("/", 1)[-1]}
            names.update(
                candidate
                for candidate in candidates
                if self.env.get(self._file_stage_key(candidate))
            )
        return names

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
            return self._path_expression(receiver.args[0])
        return None

    def _open_path_name(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Call) or not node.args:
            return None
        name = self.call_names.get(id(node), "")
        if name not in {"open", "builtins.open", "io.open"}:
            return None
        return self._path_expression(node.args[0])

    @staticmethod
    def _path_expression(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value[:240]
        return None

    @staticmethod
    def _file_stage_key(name: str) -> str:
        return f"{_FILE_STAGE_PREFIX}{name}"

    def _record_request_sink(self, sink_index: int, traces: Traces) -> None:
        for trace in traces:
            expanded = self._append_trace(trace, sink_index)
            through_summary = _SUMMARY_BOUNDARY in expanded
            chain = tuple(index for index in expanded if index >= 0)
            operations = [self.events[index].op for index in chain]
            if "SYSTEM_DISCOVERY" in operations:
                self._record_from_operation(
                    "fingerprinting_transfer",
                    chain,
                    {"SYSTEM_DISCOVERY"},
                    through_summary,
                )
            if any(
                operation in {"FILE_READ", "SENSITIVE_FILE_READ"}
                for operation in operations
            ):
                self._record_from_operation(
                    "file_to_network",
                    chain,
                    {"FILE_READ", "SENSITIVE_FILE_READ"},
                    through_summary,
                )

    def _record_sink(self, sink_index: int, traces: Traces) -> None:
        sink = self.events[sink_index]
        for trace in traces:
            expanded = self._append_trace(trace, sink_index)
            through_summary = _SUMMARY_BOUNDARY in expanded
            chain = tuple(index for index in expanded if index >= 0)
            operations = [self.events[index].op for index in chain]
            if sink.op == "NETWORK_SEND":
                if "BROWSER_COOKIE_READ" in operations:
                    self._record_from_operation(
                        "browser_session_transfer",
                        chain,
                        {"BROWSER_COOKIE_READ"},
                        through_summary,
                    )
                sensitive_start = next(
                    (
                        index
                        for index, event_index in enumerate(chain)
                        if self.events[event_index].op == "SENSITIVE_FILE_READ"
                        or (
                            self.events[event_index].op == "ENV_READ"
                            and is_sensitive_env_name(self.events[event_index].target)
                        )
                    ),
                    None,
                )
                if sensitive_start is not None:
                    self._record_from_index(
                        "credential_or_file_exfil",
                        chain,
                        sensitive_start,
                        through_summary,
                    )
                if "SYSTEM_DISCOVERY" in operations:
                    self._record_from_operation(
                        "fingerprinting_transfer",
                        chain,
                        {"SYSTEM_DISCOVERY"},
                        through_summary,
                    )
                if "FILE_READ" in operations:
                    self._record_from_operation(
                        "file_to_network",
                        chain,
                        {"FILE_READ"},
                        through_summary,
                    )
            if sink.op in EXECUTION_SINKS:
                if "NETWORK_RECEIVE" in operations:
                    self._record_from_operation(
                        "download_execute",
                        chain,
                        {"NETWORK_RECEIVE"},
                        through_summary,
                    )
                if any(
                    operation in {"DECODE", "UNSAFE_DESERIALIZE"}
                    for operation in operations
                ):
                    self._record_from_operation(
                        "encoded_execution",
                        chain,
                        {"DECODE", "UNSAFE_DESERIALIZE"},
                        through_summary,
                    )

    def _record_from_operation(
        self,
        motif: str,
        chain: Trace,
        operations: set[str],
        through_summary: bool,
    ) -> None:
        start = next(
            index
            for index, event_index in enumerate(chain)
            if self.events[event_index].op in operations
        )
        self._record_from_index(motif, chain, start, through_summary)

    def _record_from_index(
        self,
        motif: str,
        chain: Trace,
        start: int,
        through_summary: bool,
    ) -> None:
        indexes = chain[start:]
        key = motif, indexes
        if key in self.path_keys or len(self.paths) >= self.max_paths:
            return
        self.path_keys.add(key)
        self.paths.append(
            make_dataflow_path(
                motif,
                indexes,
                through_summary=through_summary,
            )
        )

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
        through_summary = _SUMMARY_BOUNDARY in trace
        events = tuple(index for index in trace if index >= 0)
        if events and events[-1] == event_index:
            return trace
        result = (*events, event_index)
        if len(result) > self.max_trace_length:
            keep = self.max_trace_length - 1
            result = (result[0], *result[-keep:])
        if through_summary:
            return (*result, _SUMMARY_BOUNDARY)
        return result

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
