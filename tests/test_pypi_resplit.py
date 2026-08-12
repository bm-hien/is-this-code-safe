import pytest

from scripts.resplit_pypi_reference import (
    V2_STUDY_ID,
    _audit_v2,
    _exclude_omc_overlaps,
    _materialize_v2,
)


def _row(index: int, *, group_id: str | None = None):
    return {
        "sample_id": f"sample-{index}",
        "group_id": group_id or f"group-{index}",
        "rank": index + 1,
        "canonical_rank": index + 1,
        "selected": index < 900,
        "split": "development" if index % 2 == 0 else "holdout",
        "status": "ok",
        "archive_sha256": f"archive-{index}",
        "source_set_hash": f"source-{index}",
        "normalized_ast_hash": f"ast-{index}",
        "representation_hash": f"representation-{index}",
        "normalized_project": f"project-{index}",
    }


def test_overlap_on_one_member_excludes_the_entire_group():
    rows = [_row(0, group_id="shared"), _row(1, group_id="shared"), _row(2)]
    omc = [
        {
            "split": "test",
            "archive_sha256": "other-archive",
            "source_set_hash": rows[1]["source_set_hash"],
            "normalized_ast_hash": "other-ast",
        }
    ]

    _, exclusions = _exclude_omc_overlaps(rows, omc)

    assert exclusions == {"shared": ["source_set_hash"]}


def test_v2_selects_900_clean_groups_and_hash_splits_450_each():
    rows = [_row(index) for index in range(902)]
    exclusions = {
        "group-0": ["source_set_hash"],
        "group-1": ["normalized_ast_hash"],
    }

    manifest, selected = _materialize_v2(rows, exclusions)

    assert len({row["group_id"] for row in selected}) == 900
    assert {row["group_id"] for row in selected}.isdisjoint(exclusions)
    assert sum(row["split"] == "development" for row in selected) == 450
    assert sum(row["split"] == "holdout" for row in selected) == 450
    excluded = [row for row in manifest if row["group_id"] in exclusions]
    assert {row["split"] for row in excluded} == {"excluded-omc-overlap"}
    assert all(not row["v2_eligible"] for row in excluded)


def test_v2_audit_rejects_any_remaining_omc_overlap():
    rows = [_row(index) for index in range(900)]
    manifest, selected = _materialize_v2(rows, {})
    omc = [
        {
            "archive_sha256": "unseen-archive",
            "source_set_hash": "unseen-source",
            "normalized_ast_hash": "unseen-ast",
        }
    ]
    _audit_v2(manifest, selected, omc)

    omc[0]["normalized_ast_hash"] = selected[0]["normalized_ast_hash"]
    with pytest.raises(ValueError, match="retains an OMCBench overlap"):
        _audit_v2(manifest, selected, omc)


def test_v2_study_id_is_new_and_immutable():
    assert V2_STUDY_ID == "itcs-pypi-hard-negative-2026-08-12-v2"
