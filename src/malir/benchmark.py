"""Repeatable CPU and memory benchmark helpers."""

from __future__ import annotations

import math
import platform
import statistics
import time
import tracemalloc
from pathlib import Path

from .scanner import Scanner


def benchmark_scan(
    target: str | Path,
    repeats: int = 20,
    scanner: Scanner | None = None,
) -> dict:
    if repeats < 2:
        raise ValueError("repeats must be at least 2")
    scanner = scanner or Scanner()
    scanner.scan(target)
    timings: list[float] = []
    files = 0
    tracemalloc.start()
    for _ in range(repeats):
        started = time.perf_counter()
        report = scanner.scan(target)
        timings.append((time.perf_counter() - started) * 1_000.0)
        files = report.files_scanned
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    ordered = sorted(timings)
    p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    mean_ms = statistics.fmean(timings)
    return {
        "schema": "malir.benchmark.v1",
        "target": str(Path(target).resolve()),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "repeats": repeats,
        "files_per_run": files,
        "mean_ms": round(mean_ms, 4),
        "median_ms": round(statistics.median(timings), 4),
        "p95_ms": round(ordered[p95_index], 4),
        "files_per_second": (
            round(files / (mean_ms / 1_000.0), 2) if mean_ms else None
        ),
        "tracemalloc_peak_bytes": peak,
    }
