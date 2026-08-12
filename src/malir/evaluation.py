"""Leakage-conscious, low-FPR and selective-classification metrics."""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import NormalDist, median
from typing import Any

_SPLITS = {"train", "validation", "test"}
_PREDICTION_FIELDS = {
    "group_id",
    "label",
    "latency_ms",
    "model_invoked",
    "period",
    "sample_id",
    "score",
    "split",
}
_POSITIVE = {1, "1", "malicious", "suspicious", "positive"}
_NEGATIVE = {0, "0", "benign", "clean", "negative"}


@dataclass(frozen=True)
class PredictionRow:
    sample_id: str
    label: int
    score: float
    split: str
    group_id: str
    period: str | None = None
    model_invoked: bool | None = None
    latency_ms: float | None = None

    @property
    def confidence(self) -> float:
        return max(self.score, 1.0 - self.score)


def load_predictions(
    path: str | Path,
    *,
    max_bytes: int = 20_000_000,
    max_rows: int = 1_000_000,
    max_line_bytes: int = 1_000_000,
) -> list[PredictionRow]:
    _validate_limits(max_bytes, max_rows, max_line_bytes)
    prediction_path = Path(path)
    if prediction_path.is_symlink():
        raise ValueError("prediction file cannot be a symlink")
    if prediction_path.stat().st_size > max_bytes:
        raise ValueError(f"prediction file exceeds {max_bytes} bytes")
    rows: list[PredictionRow] = []
    seen_ids: set[str] = set()
    total_bytes = 0
    with prediction_path.open(encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            line_bytes = len(raw_line.encode("utf-8"))
            total_bytes += line_bytes
            if total_bytes > max_bytes:
                raise ValueError(f"prediction file exceeds {max_bytes} bytes")
            if line_bytes > max_line_bytes:
                raise ValueError(f"prediction row {line_number} is too large")
            if not raw_line.strip():
                continue
            if len(rows) >= max_rows:
                raise ValueError(f"prediction file exceeds {max_rows} rows")
            try:
                record = json.loads(raw_line, parse_constant=_reject_constant)
                row = _parse_row(record)
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(
                    f"invalid prediction row {line_number}: {error}"
                ) from error
            if row.sample_id in seen_ids:
                raise ValueError(f"duplicate prediction sample_id: {row.sample_id}")
            seen_ids.add(row.sample_id)
            rows.append(row)
    if not rows:
        raise ValueError("prediction file contains no rows")
    return rows


def _validate_limits(max_bytes: int, max_rows: int, max_line_bytes: int) -> None:
    if max_bytes < 1 or max_rows < 1 or max_line_bytes < 1:
        raise ValueError("prediction limits must be positive")


def _parse_row(record: Any) -> PredictionRow:
    if not isinstance(record, dict):
        raise TypeError("row must be a JSON object")
    unknown_fields = sorted(set(record).difference(_PREDICTION_FIELDS))
    if unknown_fields:
        joined = ", ".join(unknown_fields)
        raise ValueError(f"unsupported prediction fields: {joined}")
    sample_id = _text(record, "sample_id")
    split = _text(record, "split")
    if split not in _SPLITS:
        raise ValueError("split must be train, validation, or test")
    score = _number(record, "score")
    if not 0.0 <= score <= 1.0:
        raise ValueError("score must be between 0 and 1")
    invoked = record.get("model_invoked")
    if invoked is not None and not isinstance(invoked, bool):
        raise TypeError("model_invoked must be boolean when present")
    latency = None
    if record.get("latency_ms") is not None:
        latency = _number(record, "latency_ms")
        if latency < 0.0:
            raise ValueError("latency_ms cannot be negative")
    return PredictionRow(
        sample_id=sample_id,
        label=_label(record["label"]),
        score=score,
        split=split,
        group_id=_text(record, "group_id"),
        period=_optional_text(record, "period"),
        model_invoked=invoked,
        latency_ms=latency,
    )


def _text(record: dict[str, Any], key: str) -> str:
    value = record[key]
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{key} must be non-empty text")
    if len(value) > 2_048:
        raise ValueError(f"{key} is too long")
    return value


def _optional_text(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{key} must be non-empty text when present")
    if len(value) > 2_048:
        raise ValueError(f"{key} is too long")
    return value


def _number(record: dict[str, Any], key: str) -> float:
    value = record[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{key} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{key} must be finite")
    return result


def _label(value: Any) -> int:
    if isinstance(value, bool):
        raise TypeError("label must identify benign or malicious")
    normalized = value.lower() if isinstance(value, str) else value
    if normalized in _POSITIVE:
        return 1
    if normalized in _NEGATIVE:
        return 0
    raise ValueError(f"unsupported label: {value!r}")


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def select_threshold_at_fpr(
    labels: list[int],
    scores: list[float],
    target_fpr: float,
) -> tuple[float, dict[str, float | int]]:
    """Choose a validation threshold with maximal recall under the FPR budget."""

    _validate_vectors(labels, scores)
    if not 0.0 <= target_fpr < 1.0:
        raise ValueError("target_fpr must be in [0, 1)")
    if not any(label == 0 for label in labels):
        raise ValueError("validation split needs at least one benign row")
    candidates = [math.nextafter(max(scores), math.inf)]
    candidates.extend(sorted(set(scores), reverse=True))
    feasible = []
    for candidate in candidates:
        metrics = classification_metrics(labels, scores, candidate)
        if float(metrics["false_positive_rate"]) <= target_fpr:
            feasible.append((candidate, metrics))
    return max(
        feasible,
        key=lambda item: (
            float(item[1]["recall"]),
            float(item[1]["precision"]),
            -float(item[0]),
        ),
    )


def classification_metrics(
    labels: list[int],
    scores: list[float],
    threshold: float,
) -> dict[str, float | int]:
    _validate_vectors(labels, scores)
    if not math.isfinite(threshold):
        raise ValueError("threshold must be finite")
    predictions = [int(score >= threshold) for score in scores]
    tp = sum(prediction == label == 1 for prediction, label in zip(predictions, labels))
    tn = sum(prediction == label == 0 for prediction, label in zip(predictions, labels))
    fp = sum(
        prediction == 1 and label == 0 for prediction, label in zip(predictions, labels)
    )
    fn = sum(
        prediction == 0 and label == 1 for prediction, label in zip(predictions, labels)
    )
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "rows": len(labels),
        "positives": sum(labels),
        "benign": len(labels) - sum(labels),
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0,
        "false_positive_rate": fpr,
        "false_alerts_per_10000_benign": fpr * 10_000,
    }


def average_precision(labels: list[int], scores: list[float]) -> float:
    """Tie-aware non-interpolated average precision."""

    _validate_vectors(labels, scores)
    positives = sum(labels)
    if positives == 0:
        return 0.0
    grouped: dict[float, list[int]] = defaultdict(list)
    for score, label in zip(scores, labels, strict=True):
        grouped[score].append(label)
    true_positive = 0
    seen = 0
    previous_recall = 0.0
    area = 0.0
    for score in sorted(grouped, reverse=True):
        members = grouped[score]
        true_positive += sum(members)
        seen += len(members)
        recall = true_positive / positives
        area += (recall - previous_recall) * (true_positive / seen)
        previous_recall = recall
    return area


def calibration_metrics(
    labels: list[int],
    scores: list[float],
    *,
    bins: int = 10,
) -> dict[str, float | int]:
    _validate_vectors(labels, scores)
    if bins < 1:
        raise ValueError("bins must be positive")
    brier = sum((score - label) ** 2 for score, label in zip(scores, labels)) / len(
        labels
    )
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(bins)]
    for score, label in zip(scores, labels, strict=True):
        index = min(bins - 1, int(score * bins))
        buckets[index].append((score, label))
    ece = 0.0
    occupied = 0
    for bucket in buckets:
        if not bucket:
            continue
        occupied += 1
        mean_score = sum(score for score, _ in bucket) / len(bucket)
        mean_label = sum(label for _, label in bucket) / len(bucket)
        ece += len(bucket) / len(labels) * abs(mean_score - mean_label)
    return {
        "brier_score": brier,
        "ece": ece,
        "ece_bins": bins,
        "occupied_bins": occupied,
    }


def selective_metrics(
    labels: list[int],
    scores: list[float],
    *,
    threshold: float = 0.5,
    confidence_kind: str = "decision-margin",
    coverages: tuple[float, ...] = (0.5, 0.8, 0.9, 0.95, 1.0),
) -> dict[str, Any]:
    """Risk-coverage using the locked decision and whole confidence ties."""

    _validate_vectors(labels, scores)
    if not math.isfinite(threshold) or threshold < 0.0:
        raise ValueError("threshold must be finite and non-negative")
    if confidence_kind not in {"decision-margin", "max-probability"}:
        raise ValueError("unsupported confidence_kind")
    grouped: dict[float, list[int]] = defaultdict(list)
    for label, score in zip(labels, scores, strict=True):
        error = int((score >= threshold) != bool(label))
        confidence = _selective_confidence(score, threshold, confidence_kind)
        grouped[confidence].append(error)
    retained = 0
    errors = 0
    previous_coverage = 0.0
    aurc = 0.0
    curve: list[dict[str, float | int]] = []
    for confidence in sorted(grouped, reverse=True):
        group_errors = grouped[confidence]
        retained += len(group_errors)
        errors += sum(group_errors)
        coverage = retained / len(labels)
        risk = errors / retained
        aurc += (coverage - previous_coverage) * risk
        previous_coverage = coverage
        curve.append(
            {
                "coverage": coverage,
                "risk": risk,
                "retained": retained,
                "confidence_floor": confidence,
            }
        )
    points = []
    for requested in coverages:
        if not 0.0 < requested <= 1.0:
            raise ValueError("requested coverage must be in (0, 1]")
        point = next(item for item in curve if float(item["coverage"]) >= requested)
        points.append({"requested_coverage": requested, **point})
    return {
        "aurc": aurc,
        "confidence_kind": confidence_kind,
        "confidence_levels": len(grouped),
        "risk_coverage": points,
    }


def _selective_confidence(
    score: float,
    threshold: float,
    confidence_kind: str,
) -> float:
    if confidence_kind == "max-probability":
        return max(score, 1.0 - score)
    if score >= threshold:
        span = 1.0 - threshold
        return (score - threshold) / span if span > 0.0 else 0.0
    return (threshold - score) / threshold if threshold > 0.0 else 0.0


def zero_failure_upper(
    benign_count: int,
    *,
    confidence: float = 0.95,
) -> float:
    """Exact one-sided binomial upper bound when zero false alerts occur."""

    if benign_count < 1:
        raise ValueError("benign_count must be positive")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    alpha = 1.0 - confidence
    return 1.0 - alpha ** (1.0 / benign_count)


def minimum_benign_for_zero_fp(
    target_fpr: float,
    *,
    confidence: float = 0.95,
) -> int:
    if not 0.0 < target_fpr < 1.0:
        raise ValueError("target_fpr must be in (0, 1)")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    estimate = math.ceil(math.log1p(-confidence) / math.log1p(-target_fpr))
    while zero_failure_upper(estimate, confidence=confidence) > target_fpr:
        estimate += 1
    return estimate


def wilson_upper(
    events: int,
    trials: int,
    *,
    confidence: float = 0.95,
) -> float:
    if trials < 1 or not 0 <= events <= trials:
        raise ValueError("events must be between zero and positive trials")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    z = NormalDist().inv_cdf(confidence)
    proportion = events / trials
    z2 = z * z
    denominator = 1.0 + z2 / trials
    centre = (proportion + z2 / (2.0 * trials)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1.0 - proportion) / trials + z2 / (4.0 * trials * trials)
        )
        / denominator
    )
    return min(1.0, centre + margin)


def fpr_evidence(
    labels: list[int],
    scores: list[float],
    threshold: float,
    target_fpr: float,
    *,
    group_ids: list[str] | None = None,
    confidence: float = 0.95,
) -> dict[str, Any]:
    """Report row FPR plus a conservative independent-group power check."""

    metrics = classification_metrics(labels, scores, threshold)
    benign = int(metrics["benign"])
    false_positive = int(metrics["false_positive"])
    if benign < 1:
        raise ValueError("test split needs at least one benign row")
    supplied_groups = group_ids is not None
    if group_ids is None:
        group_ids = [f"row:{index}" for index in range(len(labels))]
    if len(group_ids) != len(labels):
        raise ValueError("group_ids must match labels")
    benign_groups = {
        group_id
        for label, group_id in zip(labels, group_ids, strict=True)
        if label == 0
    }
    false_positive_groups = {
        group_id
        for label, score, group_id in zip(labels, scores, group_ids, strict=True)
        if label == 0 and score >= threshold
    }
    row_upper, row_method = _binomial_upper(
        false_positive,
        benign,
        confidence=confidence,
    )
    group_upper, group_method = _binomial_upper(
        len(false_positive_groups),
        len(benign_groups),
        confidence=confidence,
    )
    minimum = minimum_benign_for_zero_fp(target_fpr, confidence=confidence)
    return {
        "target_fpr": target_fpr,
        "confidence": confidence,
        "benign": benign,
        "false_positive": false_positive,
        "empirical_fpr": metrics["false_positive_rate"],
        "benign_groups": len(benign_groups),
        "false_positive_groups": len(false_positive_groups),
        "empirical_group_alert_rate": len(false_positive_groups) / len(benign_groups),
        "group_ids_supplied": supplied_groups,
        "row_upper_confidence_bound": row_upper,
        "upper_confidence_bound": group_upper,
        "bound_method": group_method,
        "row_bound_method": row_method,
        "target_supported": row_upper <= target_fpr and group_upper <= target_fpr,
        "minimum_benign_if_zero_fp": minimum,
        "minimum_independent_benign_groups_if_zero_fp": minimum,
    }


def _binomial_upper(
    events: int,
    trials: int,
    *,
    confidence: float,
) -> tuple[float, str]:
    if events == 0:
        return (
            zero_failure_upper(trials, confidence=confidence),
            "exact-zero-event-binomial",
        )
    return (
        wilson_upper(events, trials, confidence=confidence),
        "one-sided-wilson",
    )


def evaluation_report(
    rows: list[PredictionRow],
    *,
    target_fpr: float = 0.001,
    bootstrap: int = 2_000,
    seed: int = 0,
    confidence: float = 0.95,
) -> dict[str, Any]:
    if not 0.0 < target_fpr < 1.0:
        raise ValueError("target_fpr must be in (0, 1)")
    if bootstrap < 0 or bootstrap > 20_000:
        raise ValueError("bootstrap must be between 0 and 20000")
    validation = [row for row in rows if row.split == "validation"]
    test = [row for row in rows if row.split == "test"]
    if not validation or not test:
        raise ValueError("predictions need non-empty validation and test splits")
    validation_labels, validation_scores = _vectors(validation)
    test_labels, test_scores = _vectors(test)
    threshold, validation_at_threshold = select_threshold_at_fpr(
        validation_labels,
        validation_scores,
        target_fpr,
    )
    test_at_threshold = classification_metrics(test_labels, test_scores, threshold)
    validation_result = _quality_metrics(
        validation_labels,
        validation_scores,
        threshold,
        validation_at_threshold,
    )
    test_result = _quality_metrics(
        test_labels,
        test_scores,
        threshold,
        test_at_threshold,
    )
    report: dict[str, Any] = {
        "schema": "itcs.evaluation.v1",
        "predictions_fingerprint": _predictions_fingerprint(rows),
        "selection": {
            "threshold": threshold,
            "selected_on": "validation",
            "target_fpr": target_fpr,
        },
        "validation": validation_result,
        "test": test_result,
        "fpr_evidence": fpr_evidence(
            test_labels,
            test_scores,
            threshold,
            target_fpr,
            group_ids=[row.group_id for row in test],
            confidence=confidence,
        ),
        "selective": {
            "operating_threshold": threshold,
            "decision_margin": selective_metrics(
                test_labels,
                test_scores,
                threshold=threshold,
                confidence_kind="decision-margin",
            ),
            "max_probability": selective_metrics(
                test_labels,
                test_scores,
                threshold=threshold,
                confidence_kind="max-probability",
            ),
        },
        "conditional_compute": _conditional_compute(test),
        "periods": _period_metrics(test, threshold),
    }
    if bootstrap:
        report["bootstrap"] = group_bootstrap(
            test,
            threshold,
            repetitions=bootstrap,
            seed=seed,
            confidence=confidence,
        )
    else:
        report["bootstrap"] = {"repetitions": 0, "successful": 0, "intervals": {}}
    return report


def _quality_metrics(
    labels: list[int],
    scores: list[float],
    threshold: float,
    base: dict[str, float | int] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = dict(
        base if base is not None else classification_metrics(labels, scores, threshold)
    )
    result["average_precision"] = average_precision(labels, scores)
    result.update(calibration_metrics(labels, scores))
    return result


def group_bootstrap(
    rows: list[PredictionRow],
    threshold: float,
    *,
    repetitions: int = 2_000,
    seed: int = 0,
    confidence: float = 0.95,
) -> dict[str, Any]:
    if repetitions < 1:
        raise ValueError("repetitions must be positive")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    grouped: dict[str, list[PredictionRow]] = defaultdict(list)
    for row in rows:
        grouped[row.group_id].append(row)
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
    for _ in range(repetitions):
        sampled: list[PredictionRow] = []
        for group_id in rng.choices(group_ids, k=len(group_ids)):
            sampled.extend(grouped[group_id])
        labels, scores = _vectors(sampled)
        if not any(labels) or all(labels):
            continue
        metrics = classification_metrics(labels, scores, threshold)
        samples["recall"].append(float(metrics["recall"]))
        samples["false_positive_rate"].append(float(metrics["false_positive_rate"]))
        samples["average_precision"].append(average_precision(labels, scores))
        samples["aurc"].append(
            float(
                selective_metrics(
                    labels,
                    scores,
                    threshold=threshold,
                    confidence_kind="decision-margin",
                )["aurc"]
            )
        )
    intervals = {
        name: {
            "lower": _percentile(values, (1.0 - confidence) / 2.0),
            "upper": _percentile(values, 1.0 - (1.0 - confidence) / 2.0),
        }
        for name, values in sorted(samples.items())
        if values
    }
    successful = len(next(iter(samples.values()))) if samples else 0
    return {
        "unit": "group_id",
        "seed": seed,
        "confidence": confidence,
        "repetitions": repetitions,
        "successful": successful,
        "intervals": intervals,
    }


def _conditional_compute(rows: list[PredictionRow]) -> dict[str, Any]:
    invoked = [row.model_invoked for row in rows if row.model_invoked is not None]
    latencies = [row.latency_ms for row in rows if row.latency_ms is not None]
    result: dict[str, Any] = {
        "reported_gate_rows": len(invoked),
        "model_invocation_rate": sum(invoked) / len(invoked) if invoked else None,
        "reported_latency_rows": len(latencies),
    }
    if latencies:
        ordered = sorted(float(value) for value in latencies)
        result["median_latency_ms"] = median(ordered)
        result["p95_latency_ms"] = ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]
    return result


def _period_metrics(
    rows: list[PredictionRow],
    threshold: float,
) -> dict[str, Any]:
    grouped: dict[str, list[PredictionRow]] = defaultdict(list)
    for row in rows:
        if row.period is not None:
            grouped[row.period].append(row)
    result: dict[str, Any] = {}
    for period, members in sorted(grouped.items()):
        labels, scores = _vectors(members)
        metrics = classification_metrics(labels, scores, threshold)
        metrics["mean_max_probability"] = sum(row.confidence for row in members) / len(
            members
        )
        metrics["mean_decision_margin"] = sum(
            _selective_confidence(row.score, threshold, "decision-margin")
            for row in members
        ) / len(members)
        known_gate = [
            row.model_invoked for row in members if row.model_invoked is not None
        ]
        metrics["model_invocation_rate"] = (
            sum(known_gate) / len(known_gate) if known_gate else None
        )
        result[period] = metrics
    return result


def _predictions_fingerprint(rows: list[PredictionRow]) -> str:
    canonical = [asdict(row) for row in sorted(rows, key=lambda item: item.sample_id)]
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _vectors(rows: list[PredictionRow]) -> tuple[list[int], list[float]]:
    return [row.label for row in rows], [row.score for row in rows]


def _validate_vectors(labels: list[int], scores: list[float]) -> None:
    if not labels or len(labels) != len(scores):
        raise ValueError("labels and scores must have equal non-zero length")
    if any(label not in (0, 1) for label in labels):
        raise ValueError("labels must be zero or one")
    if any(not math.isfinite(score) or not 0.0 <= score <= 1.0 for score in scores):
        raise ValueError("scores must be finite probabilities")


def _percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction
