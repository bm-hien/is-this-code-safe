import math

import pytest

from scripts.pypi_hard_negative_study import (
    CONFIDENCE,
    _binomial_cdf,
    _clopper_pearson_upper,
    _development_operating_points,
    _holdout_report,
    _require_omc_validation,
    _validate_split_manifest,
)


def test_zero_event_upper_bound_matches_exact_formula():
    upper = _clopper_pearson_upper(0, 450, confidence=CONFIDENCE)
    expected = 1.0 - (1.0 - CONFIDENCE) ** (1.0 / 450.0)

    assert upper == pytest.approx(expected, rel=1e-12)
    assert upper < 0.01


def test_binomial_cdf_known_value():
    assert _binomial_cdf(0, 2, 0.5) == pytest.approx(0.25)
    assert _binomial_cdf(1, 2, 0.5) == pytest.approx(0.75)


def test_development_threshold_uses_all_benign_groups_and_recall_gate():
    pypi = [
        {
            "group_id": "pypi-a",
            "label": 0,
            "baseline_score": 100.0,
            "candidate_score": 20.0,
        }
    ]
    omc = [
        {
            "group_id": "omc-benign",
            "label": 0,
            "baseline_score": 80.0,
            "candidate_score": 30.0,
        },
        {
            "group_id": "omc-malicious-a",
            "label": 1,
            "baseline_score": 100.0,
            "candidate_score": 50.0,
        },
        {
            "group_id": "omc-malicious-b",
            "label": 1,
            "baseline_score": 10.0,
            "candidate_score": 10.0,
        },
    ]

    points = _development_operating_points(pypi, omc)

    assert points["baseline"]["threshold"] > 100.0
    assert not points["baseline"]["threshold_valid"]
    assert points["candidate"]["threshold"] == math.nextafter(30.0, math.inf)
    assert points["candidate"]["omcbench_malicious_recall"] == 0.5
    assert points["candidate"]["eligible"]


def test_holdout_gate_passes_only_with_zero_alerts():
    rows = [
        {
            "group_id": f"group-{index}",
            "baseline_score": 40.0,
            "candidate_score": 20.0,
        }
        for index in range(450)
    ]
    lock = {
        "operating_points": {
            "baseline": {"threshold": 50.0},
            "candidate": {"threshold": 30.0},
        }
    }

    passed = _holdout_report(rows, lock)
    assert passed["primary_gate"]["status"] == "pass"
    assert passed["systems"]["candidate"]["alert_groups"] == 0

    rows[0]["candidate_score"] = 30.0
    failed = _holdout_report(rows, lock)
    assert failed["primary_gate"]["status"] == "fail"
    assert failed["systems"]["candidate"]["alert_groups"] == 1


def test_omcbench_test_row_cannot_reach_scoring_boundary():
    with pytest.raises(ValueError, match="test row reached"):
        _require_omc_validation({"split": "test", "status": "ok"})


def _split_row(index: int, split: str):
    return {
        "sample_id": f"sample-{index}",
        "group_id": f"group-{index}",
        "split": split,
        "selected": True,
        "status": "ok",
        "archive_sha256": f"archive-{index}",
        "source_set_hash": f"source-{index}",
        "normalized_ast_hash": f"ast-{index}",
        "representation_hash": f"representation-{index}",
        "normalized_project": f"project-{index}",
    }


def test_selected_split_requires_450_disjoint_groups_each():
    rows = [
        _split_row(index, "development" if index < 450 else "holdout")
        for index in range(900)
    ]
    _validate_split_manifest(rows)

    rows[-1]["normalized_ast_hash"] = rows[0]["normalized_ast_hash"]
    with pytest.raises(ValueError, match="split leakage"):
        _validate_split_manifest(rows)
