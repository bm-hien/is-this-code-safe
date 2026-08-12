#!/usr/bin/env python3
"""Smoke-evaluate a checkpoint; use the locked-prediction CLI for claims."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import time
from pathlib import Path

from malir.data import load_examples
from malir.evaluation import average_precision, classification_metrics
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
            "schema": "itcs.smoke-evaluation.v1",
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


if __name__ == "__main__":
    raise SystemExit(main())
