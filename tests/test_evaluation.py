import json

import pytest

from malir.evaluation import (
    PredictionRow,
    calibration_metrics,
    evaluation_report,
    fpr_evidence,
    load_predictions,
    minimum_benign_for_zero_fp,
    select_threshold_at_fpr,
    selective_metrics,
    zero_failure_upper,
)


def _prediction(sample_id, label, score, split, *, group=None):
    return PredictionRow(
        sample_id=sample_id,
        label=label,
        score=score,
        split=split,
        group_id=group or sample_id,
    )


def test_threshold_is_selected_on_validation_at_target_fpr():
    threshold, metrics = select_threshold_at_fpr(
        [0, 0, 1, 1],
        [0.05, 0.20, 0.91, 0.65],
        0.001,
    )
    assert threshold == 0.65
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["recall"] == 1.0


def test_threshold_search_handles_nonmonotonic_empirical_fpr():
    threshold, metrics = select_threshold_at_fpr(
        [0, 1, 0],
        [0.9, 0.8, 0.7],
        0.5,
    )
    assert threshold == 0.8
    assert metrics["recall"] == 1.0
    assert metrics["false_positive_rate"] == 0.5


def test_low_fpr_claim_needs_enough_benign_rows():
    needed = minimum_benign_for_zero_fp(0.001)
    assert needed == 2995
    assert zero_failure_upper(needed) <= 0.001
    assert zero_failure_upper(needed - 1) > 0.001


def test_fpr_claim_uses_independent_groups():
    evidence = fpr_evidence(
        [0, 0],
        [0.1, 0.2],
        0.5,
        0.9,
        group_ids=["same-package", "same-package"],
    )
    assert evidence["row_upper_confidence_bound"] < 0.9
    assert evidence["upper_confidence_bound"] == pytest.approx(0.95)
    assert not evidence["target_supported"]


def test_calibration_does_not_replace_selective_ranking():
    labels = [0, 1]
    scores = [0.5, 0.5]
    assert calibration_metrics(labels, scores)["ece"] == 0.0
    selective = selective_metrics(labels, scores)
    assert selective["confidence_levels"] == 1
    assert selective["aurc"] == 0.5


def test_good_confidence_ranking_has_lower_aurc():
    labels = [1, 1, 0, 0]
    good = selective_metrics(labels, [0.99, 0.55, 0.45, 0.01])
    bad = selective_metrics(labels, [0.51, 0.01, 0.99, 0.49])
    assert good["aurc"] < bad["aurc"]


def test_report_is_underpowered_and_bootstrap_is_deterministic():
    rows = [
        _prediction("v-b1", 0, 0.05, "validation"),
        _prediction("v-b2", 0, 0.20, "validation"),
        _prediction("v-m1", 1, 0.90, "validation"),
        _prediction("v-m2", 1, 0.70, "validation"),
        _prediction("t-b1", 0, 0.02, "test"),
        _prediction("t-b2", 0, 0.10, "test"),
        _prediction("t-m1", 1, 0.80, "test"),
        _prediction("t-m2", 1, 0.60, "test"),
    ]
    with pytest.raises(ValueError, match="target_fpr"):
        evaluation_report(rows, target_fpr=0.0, bootstrap=0)
    first = evaluation_report(rows, bootstrap=100, seed=7)
    second = evaluation_report(rows, bootstrap=100, seed=7)
    assert not first["fpr_evidence"]["target_supported"]
    assert first["bootstrap"] == second["bootstrap"]
    reversed_report = evaluation_report(list(reversed(rows)), bootstrap=0)
    assert (
        first["predictions_fingerprint"] == reversed_report["predictions_fingerprint"]
    )
    assert first["selection"]["selected_on"] == "validation"
    assert first["selective"]["decision_margin"]["aurc"] == pytest.approx(0.0625)


def test_prediction_loader_rejects_nan_and_duplicates(tmp_path):
    path = tmp_path / "predictions.jsonl"
    valid = {
        "sample_id": "same",
        "label": 0,
        "score": 0.1,
        "split": "test",
        "group_id": "same",
    }
    path.write_text(
        json.dumps(valid) + "\n" + json.dumps(valid),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_predictions(path)

    path.write_text(
        '{"sample_id":"x","label":0,"score":NaN,"split":"test","group_id":"x"}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="non-finite"):
        load_predictions(path)

    unknown = dict(valid, sample_id="unknown", unexpected="value")
    path.write_text(json.dumps(unknown), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported prediction fields"):
        load_predictions(path)

    real = tmp_path / "real.jsonl"
    real.write_text(json.dumps(valid), encoding="utf-8")
    link = tmp_path / "link.jsonl"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        load_predictions(link)
