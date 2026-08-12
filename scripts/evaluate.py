#!/usr/bin/env python3
"""Evaluate a trained classifier on labeled MalIR JSONL."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import time
from pathlib import Path

from malir.data import load_examples
from malir.model import OnlineLogisticModel


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset")
    models = parser.add_mutually_exclusive_group(required=True)
    models.add_argument("--model", help="sparse model checkpoint")
    models.add_argument("--micro-model", help="µMal checkpoint")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--threads", type=int, default=2)
    args = parser.parse_args()
    if not 0.0 <= args.threshold <= 1.0:
        parser.error("threshold must be between 0 and 1")

    if args.model:
        predictor = OnlineLogisticModel.load(args.model)
        checkpoint = Path(args.model)
        model_type = "sparse-logistic"
    else:
        from malir.microlm import MicroMalPredictor

        predictor = MicroMalPredictor.load(args.micro_model, args.threads)
        checkpoint = Path(args.micro_model)
        model_type = "micro-transformer"

    examples = load_examples(args.dataset)
    probabilities: list[float] = []
    timings: list[float] = []
    labels: list[int] = []
    for tokens, label in examples:
        started = time.perf_counter()
        probability = predictor.predict_proba(tokens)
        timings.append((time.perf_counter() - started) * 1_000.0)
        probabilities.append(probability)
        labels.append(label)

    result = classification_metrics(labels, probabilities, args.threshold)
    ordered = sorted(timings)
    p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    result.update(
        {
            "schema": "malir.evaluation.v1",
            "model": model_type,
            "model_bytes": checkpoint.stat().st_size,
            "examples": len(labels),
            "threshold": args.threshold,
            "average_precision": average_precision(labels, probabilities),
            "median_inference_ms": statistics.median(timings),
            "p95_inference_ms": ordered[p95_index],
        }
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def classification_metrics(
    labels: list[int],
    probabilities: list[float],
    threshold: float,
) -> dict[str, float | int]:
    predictions = [int(value >= threshold) for value in probabilities]
    tp = sum(prediction == label == 1 for prediction, label in zip(predictions, labels))
    tn = sum(prediction == label == 0 for prediction, label in zip(predictions, labels))
    fp = sum(
        prediction == 1 and label == 0 for prediction, label in zip(predictions, labels)
    )
    fn = sum(
        prediction == 0 and label == 1 for prediction, label in zip(predictions, labels)
    )
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    return {
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / max(1e-12, precision + recall),
        "false_positive_rate": fp / max(1, fp + tn),
    }


def average_precision(labels: list[int], probabilities: list[float]) -> float:
    ranked = sorted(
        zip(probabilities, labels),
        key=lambda item: item[0],
        reverse=True,
    )
    positives = sum(labels)
    if positives == 0:
        return 0.0
    hits = 0
    total = 0.0
    for rank, (_, label) in enumerate(ranked, 1):
        if label:
            hits += 1
            total += hits / rank
    return total / positives


if __name__ == "__main__":
    raise SystemExit(main())
