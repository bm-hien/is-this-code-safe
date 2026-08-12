"""Content fingerprints for leakage-aware source-package grouping."""

from __future__ import annotations

import ast
import hashlib
import warnings

from .archive import SourceMember


def source_set_hash(sources: tuple[SourceMember, ...]) -> str:
    """Hash the multiset of Python member bytes while ignoring archive paths."""

    entries = [
        len(source.payload).to_bytes(8, "big") + hashlib.sha256(source.payload).digest()
        for source in sources
    ]
    return _hash_entries(entries)


def normalized_ast_hash(sources: tuple[SourceMember, ...]) -> str:
    """Hash identifier/literal-normalized Python ASTs, ignoring member paths."""

    entries = []
    for source in sources:
        text = source.payload.decode("utf-8", errors="replace")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(text, type_comments=True)
            normalized = _IdentifierNormalizer().visit(tree)
            representation = ast.dump(
                normalized,
                annotate_fields=True,
                include_attributes=False,
            ).encode()
            entries.append(b"ast\0" + hashlib.sha256(representation).digest())
        except (RecursionError, SyntaxError, ValueError):
            entries.append(b"parse-error\0" + hashlib.sha256(source.payload).digest())
    return _hash_entries(entries)


class _IdentifierNormalizer(ast.NodeTransformer):
    """Remove local identities and literals while retaining imported APIs."""

    def generic_visit(self, node: ast.AST) -> ast.AST:
        result = super().generic_visit(node)
        if hasattr(result, "type_comment") and result.type_comment is not None:
            result.type_comment = "<TYPE_COMMENT>"
        return result

    def visit_Name(self, node: ast.Name) -> ast.AST:
        node.id = "<ID>"
        return self.generic_visit(node)

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg = "<ARG>"
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.name = "<FUNCTION>"
        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.name = "<FUNCTION>"
        return self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        node.name = "<CLASS>"
        return self.generic_visit(node)

    def visit_alias(self, node: ast.alias) -> ast.AST:
        if node.asname is not None:
            node.asname = "<ALIAS>"
        return node

    def visit_Global(self, node: ast.Global) -> ast.AST:
        node.names = ["<ID>"] * len(node.names)
        return node

    def visit_Nonlocal(self, node: ast.Nonlocal) -> ast.AST:
        node.names = ["<ID>"] * len(node.names)
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.AST:
        if node.name is not None:
            node.name = "<ID>"
        return self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> ast.AST:
        if node.name is not None:
            node.name = "<ID>"
        return self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> ast.AST:
        if node.name is not None:
            node.name = "<ID>"
        return self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        marker = f"<{type(node.value).__name__}>"
        return ast.copy_location(ast.Constant(value=marker), node)


def _hash_entries(entries: list[bytes]) -> str:
    digest = hashlib.sha256()
    for entry in sorted(entries):
        digest.update(len(entry).to_bytes(8, "big"))
        digest.update(entry)
    return digest.hexdigest()
