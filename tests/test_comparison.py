import json
from dataclasses import asdict

import pytest

from malir.cli import main
from malir.comparison import paired_comparison_report
from malir.evaluation import PredictionRow


def _row(
    sample_id,
    label,
    score,
    split,
    *,
    group=None,
    latency=1.0,
    invoked=False,
):
    return PredictionRow(
        sample_id=sample_id,
        label=label,
        score=score,
        split=split,
        group_id=group or sample_id,
        period="2026-08",
        latency_ms=latency,
        model_invoked=invoked,
    )


def _prediction_pair():
    baseline = [
        _row("v-b1", 0, 0.10, "validation"),
        _row("v-b2", 0, 0.20, "validation"),
        _row("v-m1", 1, 0.65, "validation"),
        _row("v-m2", 1, 0.55, "validation"),
        _row("t-b1", 0, 0.10, "test", latency=2.0, invoked=True),
        _row("t-b2", 0, 0.60, "test", latency=4.0, invoked=True),
        _row("t-m1", 1, 0.50, "test", latency=6.0, invoked=True),
        _row("t-m2", 1, 0.70, "test", latency=8.0, invoked=True),
    ]
    candidate = [
        _row("v-b1", 0, 0.10, "validation"),
        _row("v-b2", 0, 0.20, "validation"),
        _row("v-m1", 1, 0.80, "validation"),
        _row("v-m2", 1, 0.70, "validation"),
        _row("t-b1", 0, 0.10, "test", latency=1.0),
        _row("t-b2", 0, 0.20, "test", latency=2.0),
        _row("t-m1", 1, 0.80, "test", latency=3.0),
        _row("t-m2", 1, 0.75, "test", latency=4.0),
    ]
    return baseline, candidate


def test_paired_report_locks_thresholds_and_counts_transitions():
    baseline, candidate = _prediction_pair()
    report = paired_comparison_report(
        baseline,
        candidate,
        bootstrap=200,
        seed=17,
    )

    assert report["schema"] == "itcs.paired-comparison.v1"
    assert report["baseline"]["selection"]["threshold"] == 0.55
    assert report["candidate"]["selection"]["threshold"] == 0.70
    assert report["effects"]["recall"]["delta"] == pytest.approx(0.5)
    assert report["effects"]["false_positive_rate"]["delta"] == pytest.approx(-0.5)
    assert report["effects"]["mean_latency_ms"]["delta"] == pytest.approx(-2.5)
    rows = report["transitions"]["rows"]
    assert rows["benign"]["candidate_fixed_false_alert"] == 1
    assert rows["malicious"]["candidate_recovered_detection"] == 1
    assert report["bootstrap"]["paired"]
    assert report["bootstrap"]["successful"] > 0
    assert report["policy"]["per_system_fpr_confidence"] == pytest.approx(0.975)
    assert report["baseline"]["fpr_evidence"]["confidence"] == pytest.approx(0.975)
    assert report["claim_gate"]["status"] == "underpowered-target-fpr"


def test_comparison_is_order_independent_and_bootstrap_is_deterministic():
    baseline, candidate = _prediction_pair()
    first = paired_comparison_report(baseline, candidate, bootstrap=100, seed=5)
    second = paired_comparison_report(
        list(reversed(baseline)),
        list(reversed(candidate)),
        bootstrap=100,
        seed=5,
    )
    assert first["comparison_fingerprint"] == second["comparison_fingerprint"]
    assert first["bootstrap"] == second["bootstrap"]


def test_comparison_rejects_unaligned_or_changed_metadata():
    baseline, candidate = _prediction_pair()
    with pytest.raises(ValueError, match="sample_id sets differ"):
        paired_comparison_report(baseline, candidate[:-1], bootstrap=0)

    changed = list(candidate)
    changed[-1] = _row("t-m2", 0, 0.75, "test")
    with pytest.raises(ValueError, match="metadata mismatch"):
        paired_comparison_report(baseline, changed, bootstrap=0)


def test_comparison_rejects_group_leakage_across_splits():
    baseline, candidate = _prediction_pair()
    baseline[0] = _row("v-b1", 0, 0.10, "validation", group="shared")
    candidate[0] = _row("v-b1", 0, 0.10, "validation", group="shared")
    baseline[4] = _row("t-b1", 0, 0.10, "test", group="shared")
    candidate[4] = _row("t-b1", 0, 0.10, "test", group="shared")
    with pytest.raises(ValueError, match="crosses labels or splits"):
        paired_comparison_report(baseline, candidate, bootstrap=0)


def test_compare_predictions_cli_json(tmp_path, capsys):
    baseline, candidate = _prediction_pair()
    baseline_path = tmp_path / "baseline.jsonl"
    candidate_path = tmp_path / "candidate.jsonl"
    baseline_path.write_text(
        "\n".join(json.dumps(asdict(row)) for row in baseline),
        encoding="utf-8",
    )
    candidate_path.write_text(
        "\n".join(json.dumps(asdict(row)) for row in candidate),
        encoding="utf-8",
    )
    code = main(
        [
            "compare-predictions",
            str(baseline_path),
            str(candidate_path),
            "--bootstrap",
            "20",
            "--seed",
            "9",
            "--json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["schema"] == "itcs.paired-comparison.v1"
    assert report["policy"]["paired_resampling"]
