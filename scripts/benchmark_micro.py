#!/usr/bin/env python3
"""Measure µMal single-example CPU inference latency."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import time
from pathlib import Path

from malir.microlm import MicroMalPredictor

TOKENS = [
    "P:runtime|C:source|O:ENV_READ|T:ci_token",
    "P:runtime|C:transform|O:ENCODE|T:base64.b64encode",
    "P:runtime|C:sink|O:NETWORK_SEND|T:remote",
    "MOTIF:credential_or_file_exfil",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("checkpoint")
    parser.add_argument("--repeats", type=int, default=200)
    parser.add_argument("--threads", type=int, default=2)
    args = parser.parse_args()

    predictor = MicroMalPredictor.load(args.checkpoint, args.threads)
    for _ in range(10):
        predictor.predict_proba(TOKENS)
    timings = []
    probability = 0.0
    for _ in range(args.repeats):
        started = time.perf_counter()
        probability = predictor.predict_proba(TOKENS)
        timings.append((time.perf_counter() - started) * 1_000.0)
    ordered = sorted(timings)
    p95 = ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]
    output = {
        "schema": "malir.micro-benchmark.v1",
        "checkpoint_bytes": Path(args.checkpoint).stat().st_size,
        "parameters": predictor.parameter_count,
        "threads": args.threads,
        "repeats": args.repeats,
        "median_ms": round(statistics.median(timings), 4),
        "p95_ms": round(p95, 4),
        "probability": round(probability, 6),
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
