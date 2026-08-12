"""Paired comparison for locked validation/test prediction files."""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections import defaultdict
from statistics import median
from typing import Any

from .evaluation import (
    PredictionRow,
    average_precision,
    calibration_metrics,
    classification_metrics,
    evaluation_report,
    selective_metrics,
)

_METADATA_FIELDS = ("label", "split", "group_id", "period")
_EFFECT_DIRECTIONS = {
    "recall": "higher",
    "false_positive_rate": "lower",
    "average_precision": "higher",
    "brier_score": "lower",
    "aurc": "lower",
    "model_invocation_rate": "lower",
    "mean_latency_ms": "lower",
    "median_latency_ms": "lower",
}


def paired_comparison_report(
    baseline_rows: list[PredictionRow],
    candidate_rows: list[PredictionRow],
    *,
    target_fpr: float = 0.001,
    bootstrap: int = 2_000,
    seed: int = 0,
    confidence: float = 0.95,
) -> dict[str, Any]:
    """Compare two systems on aligned rows with independently locked thresholds."""

    if bootstrap < 0 or bootstrap > 20_000:
        raise ValueError("bootstrap must be between 0 and 20000")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    pairs = _align_rows(baseline_rows, candidate_rows)
    _validate_group_integrity(pairs)
    per_system_fpr_confidence = 1.0 - (1.0 - confidence) / 2.0
    baseline = evaluation_report(
        baseline_rows,
        target_fpr=target_fpr,
        bootstrap=0,
        seed=seed,
        confidence=per_system_fpr_confidence,
    )
    candidate = evaluation_report(
        candidate_rows,
        target_fpr=target_fpr,
        bootstrap=0,
        seed=seed,
        confidence=per_system_fpr_confidence,
    )
    test_pairs = [pair for pair in pairs if pair[0].split == "test"]
    baseline_threshold = float(baseline["selection"]["threshold"])
    candidate_threshold = float(candidate["selection"]["threshold"])
    effects = _point_effects(
        test_pairs,
        baseline_threshold,
        candidate_threshold,
    )
    intervals = _paired_group_bootstrap(
        test_pairs,
        baseline_threshold,
        candidate_threshold,
        repetitions=bootstrap,
        seed=seed,
        confidence=confidence,
    )
    transitions = _transitions(
        test_pairs,
        baseline_threshold,
        candidate_threshold,
    )
    fingerprints = {
        "baseline": baseline["predictions_fingerprint"],
        "candidate": candidate["predictions_fingerprint"],
    }
    return {
        "schema": "itcs.paired-comparison.v1",
        "comparison_fingerprint": _comparison_fingerprint(
            fingerprints,
            target_fpr=target_fpr,
            bootstrap=bootstrap,
            seed=seed,
            confidence=confidence,
        ),
        "alignment": _alignment_summary(pairs),
        "policy": {
            "target_fpr": target_fpr,
            "thresholds_selected_independently_on": "validation",
            "thresholds_frozen_on": "test",
            "resampling_unit": "group_id",
            "paired_resampling": True,
            "paired_effect_confidence": confidence,
            "joint_fpr_confidence": confidence,
            "per_system_fpr_confidence": per_system_fpr_confidence,
            "joint_fpr_control": "bonferroni-two-systems",
        },
        "baseline": baseline,
        "candidate": candidate,
        "effects": effects,
        "transitions": transitions,
        "bootstrap": intervals,
        "claim_gate": _claim_gate(effects, intervals, baseline, candidate),
    }


def _align_rows(
    baseline_rows: list[PredictionRow],
    candidate_rows: list[PredictionRow],
) -> list[tuple[PredictionRow, PredictionRow]]:
    baseline = {row.sample_id: row for row in baseline_rows}
    candidate = {row.sample_id: row for row in candidate_rows}
    if len(baseline) != len(baseline_rows) or len(candidate) != len(candidate_rows):
        raise ValueError("prediction rows must have unique sample_id values")
    baseline_ids = set(baseline)
    candidate_ids = set(candidate)
    if baseline_ids != candidate_ids:
        missing_candidate = sorted(baseline_ids - candidate_ids)[:3]
        missing_baseline = sorted(candidate_ids - baseline_ids)[:3]
        raise ValueError(
            "prediction sample_id sets differ: "
            f"missing from candidate={missing_candidate!r}; "
            f"missing from baseline={missing_baseline!r}"
        )
    pairs = []
    for sample_id in sorted(baseline_ids):
        left = baseline[sample_id]
        right = candidate[sample_id]
        mismatches = [
            field
            for field in _METADATA_FIELDS
            if getattr(left, field) != getattr(right, field)
        ]
        if mismatches:
            raise ValueError(
                f"metadata mismatch for {sample_id}: {', '.join(mismatches)}"
            )
        pairs.append((left, right))
    return pairs


def _validate_group_integrity(
    pairs: list[tuple[PredictionRow, PredictionRow]],
) -> None:
    groups: dict[str, tuple[int, str]] = {}
    for row, _ in pairs:
        identity = (row.label, row.split)
        previous = groups.setdefault(row.group_id, identity)
        if previous != identity:
            raise ValueError(f"group_id {row.group_id!r} crosses labels or splits")


def _alignment_summary(
    pairs: list[tuple[PredictionRow, PredictionRow]],
) -> dict[str, int]:
    return {
        "rows": len(pairs),
        "train_rows": sum(left.split == "train" for left, _ in pairs),
        "validation_rows": sum(left.split == "validation" for left, _ in pairs),
        "test_rows": sum(left.split == "test" for left, _ in pairs),
        "groups": len({left.group_id for left, _ in pairs}),
        "test_groups": len(
            {left.group_id for left, _ in pairs if left.split == "test"}
        ),
    }


def _point_effects(
    pairs: list[tuple[PredictionRow, PredictionRow]],
    baseline_threshold: float,
    candidate_threshold: float,
) -> dict[str, dict[str, Any]]:
    labels = [left.label for left, _ in pairs]
    baseline_scores = [left.score for left, _ in pairs]
    candidate_scores = [right.score for _, right in pairs]
    baseline_metrics = classification_metrics(
        labels, baseline_scores, baseline_threshold
    )
    candidate_metrics = classification_metrics(
        labels, candidate_scores, candidate_threshold
    )
    values = {
        "recall": (
            float(baseline_metrics["recall"]),
            float(candidate_metrics["recall"]),
        ),
        "false_positive_rate": (
            float(baseline_metrics["false_positive_rate"]),
            float(candidate_metrics["false_positive_rate"]),
        ),
        "average_precision": (
            average_precision(labels, baseline_scores),
            average_precision(labels, candidate_scores),
        ),
        "brier_score": (
            float(calibration_metrics(labels, baseline_scores)["brier_score"]),
            float(calibration_metrics(labels, candidate_scores)["brier_score"]),
        ),
        "aurc": (
            _aurc(labels, baseline_scores, baseline_threshold),
            _aurc(labels, candidate_scores, candidate_threshold),
        ),
    }
    observations = {name: len(pairs) for name in values}
    observations.update(_add_compute_effects(values, pairs))
    return {
        name: {
            "baseline": baseline_value,
            "candidate": candidate_value,
            "delta": candidate_value - baseline_value,
            "better": _EFFECT_DIRECTIONS[name],
            "paired_rows": observations[name],
        }
        for name, (baseline_value, candidate_value) in values.items()
    }


def _add_compute_effects(
    values: dict[str, tuple[float, float]],
    pairs: list[tuple[PredictionRow, PredictionRow]],
) -> dict[str, int]:
    observations: dict[str, int] = {}
    gates = [
        (left.model_invoked, right.model_invoked)
        for left, right in pairs
        if left.model_invoked is not None and right.model_invoked is not None
    ]
    if gates:
        values["model_invocation_rate"] = (
            sum(bool(left) for left, _ in gates) / len(gates),
            sum(bool(right) for _, right in gates) / len(gates),
        )
        observations["model_invocation_rate"] = len(gates)
    latencies = [
        (float(left.latency_ms), float(right.latency_ms))
        for left, right in pairs
        if left.latency_ms is not None and right.latency_ms is not None
    ]
    if latencies:
        left_values = [left for left, _ in latencies]
        right_values = [right for _, right in latencies]
        values["mean_latency_ms"] = (
            sum(left_values) / len(left_values),
            sum(right_values) / len(right_values),
        )
        values["median_latency_ms"] = (
            median(left_values),
            median(right_values),
        )
        observations["mean_latency_ms"] = len(latencies)
        observations["median_latency_ms"] = len(latencies)
    return observations


def _aurc(labels: list[int], scores: list[float], threshold: float) -> float:
    return float(
        selective_metrics(
            labels,
            scores,
            threshold=threshold,
            confidence_kind="decision-margin",
        )["aurc"]
    )


def _transitions(
    pairs: list[tuple[PredictionRow, PredictionRow]],
    baseline_threshold: float,
    candidate_threshold: float,
) -> dict[str, Any]:
    row_counts = _transition_counts(
        [
            (
                left.label,
                left.score >= baseline_threshold,
                right.score >= candidate_threshold,
            )
            for left, right in pairs
        ]
    )
    grouped: dict[str, list[tuple[PredictionRow, PredictionRow]]] = defaultdict(list)
    for pair in pairs:
        grouped[pair[0].group_id].append(pair)
    group_states = []
    for members in grouped.values():
        label = members[0][0].label
        baseline_alert = any(left.score >= baseline_threshold for left, _ in members)
        candidate_alert = any(
            right.score >= candidate_threshold for _, right in members
        )
        group_states.append((label, baseline_alert, candidate_alert))
    return {
        "rows": row_counts,
        "groups_any_alert": _transition_counts(group_states),
    }


def _transition_counts(
    states: list[tuple[int, bool, bool]],
) -> dict[str, dict[str, int]]:
    benign = {
        "both_clear": 0,
        "candidate_fixed_false_alert": 0,
        "candidate_introduced_false_alert": 0,
        "both_alert": 0,
    }
    malicious = {
        "both_missed": 0,
        "candidate_recovered_detection": 0,
        "candidate_lost_detection": 0,
        "both_detected": 0,
    }
    for label, baseline_alert, candidate_alert in states:
        if label == 0:
            key = {
                (False, False): "both_clear",
                (True, False): "candidate_fixed_false_alert",
                (False, True): "candidate_introduced_false_alert",
                (True, True): "both_alert",
            }[(baseline_alert, candidate_alert)]
            benign[key] += 1
        else:
            key = {
                (False, False): "both_missed",
                (False, True): "candidate_recovered_detection",
                (True, False): "candidate_lost_detection",
                (True, True): "both_detected",
            }[(baseline_alert, candidate_alert)]
            malicious[key] += 1
    return {
        "benign": {"total": sum(benign.values()), **benign},
        "malicious": {"total": sum(malicious.values()), **malicious},
    }


def _paired_group_bootstrap(
    pairs: list[tuple[PredictionRow, PredictionRow]],
    baseline_threshold: float,
    candidate_threshold: float,
    *,
    repetitions: int,
    seed: int,
    confidence: float,
) -> dict[str, Any]:
    if repetitions == 0:
        return {
            "unit": "group_id",
            "repetitions": 0,
            "successful": 0,
            "intervals": {},
        }
    grouped: dict[str, list[tuple[PredictionRow, PredictionRow]]] = defaultdict(list)
    for pair in pairs:
        grouped[pair[0].group_id].append(pair)
    group_ids = sorted(grouped)
    if len(group_ids) < 2:
        return {
            "unit": "group_id",
            "repetitions": repetitions,
            "successful": 0,
            "intervals": {},
        }
    rng = random.Random(seed)
    samples: dict[str, list[float]] = defaultdict(list)
    successful = 0
    for _ in range(repetitions):
        sampled = [
            pair
            for group_id in rng.choices(group_ids, k=len(group_ids))
            for pair in grouped[group_id]
        ]
        labels = [left.label for left, _ in sampled]
        if not any(labels) or all(labels):
            continue
        effects = _point_effects(
            sampled,
            baseline_threshold,
            candidate_threshold,
        )
        for name, effect in effects.items():
            samples[name].append(float(effect["delta"]))
        successful += 1
    alpha = (1.0 - confidence) / 2.0
    point_effects = _point_effects(pairs, baseline_threshold, candidate_threshold)
    intervals = {
        name: {
            "estimate": point_effects[name]["delta"],
            "lower": _percentile(values, alpha),
            "upper": _percentile(values, 1.0 - alpha),
            "confidence": confidence,
            "replicates": len(values),
            "better": _EFFECT_DIRECTIONS[name],
        }
        for name, values in sorted(samples.items())
        if values
    }
    return {
        "unit": "group_id",
        "paired": True,
        "seed": seed,
        "confidence": confidence,
        "repetitions": repetitions,
        "successful": successful,
        "intervals": intervals,
    }


def _claim_gate(
    effects: dict[str, dict[str, Any]],
    bootstrap: dict[str, Any],
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    recall = bootstrap["intervals"].get("recall")
    false_positive_rate = bootstrap["intervals"].get("false_positive_rate")
    if recall is None or false_positive_rate is None:
        return {
            "primary": "recall_at_validation_selected_target_fpr",
            "status": "not-assessed",
            "supported": False,
            "reason": "paired group bootstrap produced no usable interval",
        }
    effect_supported = recall["lower"] > 0.0 and false_positive_rate["upper"] <= 0.0
    target_supported = bool(
        baseline["fpr_evidence"]["target_supported"]
        and candidate["fpr_evidence"]["target_supported"]
    )
    if not target_supported:
        status = "underpowered-target-fpr"
    elif effect_supported:
        status = "supported"
    else:
        status = "not-supported"
    return {
        "primary": "recall_at_validation_selected_target_fpr",
        "status": status,
        "supported": effect_supported and target_supported,
        "paired_effect_supported": effect_supported,
        "target_fpr_supported_for_both": target_supported,
        "recall_delta": effects["recall"]["delta"],
        "false_positive_rate_delta": effects["false_positive_rate"]["delta"],
        "rule": (
            "paired recall delta lower bound > 0, FPR delta upper bound <= 0, "
            "and both systems meet the target-FPR confidence-bound gate"
        ),
    }


def _comparison_fingerprint(
    fingerprints: dict[str, str],
    *,
    target_fpr: float,
    bootstrap: int,
    seed: int,
    confidence: float,
) -> str:
    payload = json.dumps(
        {
            "predictions": fingerprints,
            "target_fpr": target_fpr,
            "bootstrap": bootstrap,
            "seed": seed,
            "confidence": confidence,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _percentile(values: list[float], quantile: float) -> float:
    if not values or not 0.0 <= quantile <= 1.0:
        raise ValueError("percentile needs values and a quantile in [0, 1]")
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction
