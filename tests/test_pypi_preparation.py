from malir.extractor import PythonExtractor
from scripts.prepare_pypi_reference import (
    _assign_groups,
    _representation_hash,
    _select_and_split,
)


def _row(
    sample: str,
    rank: int,
    *,
    archive: str,
    source: str,
    ast_hash: str,
    representation: str | None = None,
):
    return {
        "sample_id": sample,
        "rank": rank,
        "project": sample,
        "normalized_project": sample,
        "version": "1",
        "status": "ok",
        "archive_sha256": archive,
        "source_set_hash": source,
        "normalized_ast_hash": ast_hash,
        "representation_hash": representation or f"rep-{sample}",
    }


def test_grouping_closes_transitive_fingerprint_collisions():
    rows = [
        _row("a", 1, archive="archive-a", source="shared", ast_hash="ast-a"),
        _row("b", 2, archive="archive-b", source="shared", ast_hash="shared-ast"),
        _row("c", 3, archive="archive-c", source="source-c", ast_hash="shared-ast"),
        _row("d", 4, archive="archive-d", source="source-d", ast_hash="ast-d"),
    ]

    grouped = _assign_groups(rows)
    group_by_sample = {row["sample_id"]: row["group_id"] for row in grouped}

    assert group_by_sample["a"] == group_by_sample["b"]
    assert group_by_sample["b"] == group_by_sample["c"]
    assert group_by_sample["c"] != group_by_sample["d"]
    assert {row["group_size"] for row in grouped if row["sample_id"] != "d"} == {3}
    assert all(row["canonical_rank"] == 1 for row in grouped if row["sample_id"] != "d")


def test_split_selects_top_groups_then_hash_assigns_equal_partitions():
    rows = [
        _row(
            f"sample-{index}",
            index,
            archive=f"archive-{index}",
            source=f"source-{index}",
            ast_hash=f"ast-{index}",
        )
        for index in range(1, 7)
    ]
    grouped = _assign_groups(rows)

    manifest = _select_and_split(grouped, 4)

    selected = [row for row in manifest if row["selected"]]
    assert {row["rank"] for row in selected} == {1, 2, 3, 4}
    assert {row["split"] for row in manifest if not row["selected"]} == {"reserve"}
    selected_groups = {}
    for row in selected:
        selected_groups.setdefault(row["split"], set()).add(row["group_id"])
    assert len(selected_groups["development"]) == 2
    assert len(selected_groups["holdout"]) == 2


def test_representation_hash_matches_model_visible_order():
    extractor = PythonExtractor(enable_dataflow=True)
    first = extractor.analyze_source("import os\nos.system('id')\n", "a.py")
    second = extractor.analyze_source("print('safe')\n", "b.py")

    digest = _representation_hash([first, second])

    assert digest == _representation_hash([first, second])
    assert digest != _representation_hash([second, first])
    assert digest != _representation_hash(
        [extractor.analyze_source("import os\nos.system('id')\n", "other.py"), second]
    )
