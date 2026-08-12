from malir.archive import SourceMember
from malir.dedup import normalized_ast_hash, source_set_hash


def _source(path, payload):
    return SourceMember(path, payload.encode(), False)


def test_source_set_hash_ignores_paths_and_order_but_not_bytes():
    first = (
        _source("one.py", "x = 1"),
        _source("two.py", "y = 2"),
    )
    renamed = tuple(
        reversed(
            (
                _source("renamed/a.py", "x = 1"),
                _source("renamed/b.py", "y = 2"),
            )
        )
    )
    changed = (
        _source("one.py", "x = 1"),
        _source("two.py", "y = 3"),
    )

    assert source_set_hash(first) == source_set_hash(renamed)
    assert source_set_hash(first) != source_set_hash(changed)


def test_normalized_ast_groups_identifier_and_literal_variants():
    first = (_source("one.py", "def fetch(alpha):\n    return alpha + 1\n"),)
    variant = (
        _source(
            "renamed.py",
            "def renamed(beta):\n    return beta + 999\n",
        ),
    )
    structural_change = (
        _source(
            "renamed.py",
            "def renamed(beta):\n    return beta * 999\n",
        ),
    )

    assert normalized_ast_hash(first) == normalized_ast_hash(variant)
    assert normalized_ast_hash(first) != normalized_ast_hash(structural_change)


def test_normalized_ast_retains_imported_api_and_attribute_semantics():
    post = (_source("one.py", "import requests as r\nr.post('x')\n"),)
    get = (_source("two.py", "import requests as client\nclient.get('y')\n"),)
    urllib = (_source("three.py", "import urllib.request as r\nr.post('z')\n"),)

    assert normalized_ast_hash(post) != normalized_ast_hash(get)
    assert normalized_ast_hash(post) != normalized_ast_hash(urllib)


def test_parse_errors_fall_back_to_exact_source_bytes():
    broken = (_source("bad.py", "def broken(:\n"),)
    renamed = (_source("renamed.py", "def broken(:\n"),)
    changed = (_source("bad.py", "def other(:\n"),)

    assert normalized_ast_hash(broken) == normalized_ast_hash(renamed)
    assert normalized_ast_hash(broken) != normalized_ast_hash(changed)
