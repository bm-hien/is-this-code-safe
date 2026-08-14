"""Repeatable CPU and memory benchmark helpers."""

from __future__ import annotations

import math
import platform
import statistics
import time
import tracemalloc
from pathlib import Path

from .scanner import Scanner


def benchmark_dataflow_ablation(
    target: str | Path,
    repeats: int = 20,
) -> dict:
    baseline = benchmark_scan(
        target,
        repeats=repeats,
        scanner=Scanner(enable_dataflow=False),
    )
    dataflow = benchmark_scan(
        target,
        repeats=repeats,
        scanner=Scanner(enable_dataflow=True),
    )
    baseline_median = baseline["median_ms"]
    baseline_peak = baseline["tracemalloc_peak_bytes"]
    return {
        "schema": "malir.dataflow-ablation.v1",
        "baseline": baseline,
        "dataflow": dataflow,
        "mean_overhead_percent": round(
            100.0 * (dataflow["mean_ms"] / baseline["mean_ms"] - 1.0),
            3,
        ),
        "median_overhead_percent": round(
            100.0 * (dataflow["median_ms"] / baseline_median - 1.0),
            3,
        ),
        "p95_overhead_percent": round(
            100.0 * (dataflow["p95_ms"] / baseline["p95_ms"] - 1.0),
            3,
        ),
        "peak_allocation_overhead_percent": round(
            100.0 * (dataflow["tracemalloc_peak_bytes"] / baseline_peak - 1.0),
            3,
        ),
    }


def benchmark_call_summary_ablation(
    target: str | Path,
    repeats: int = 20,
) -> dict:
    """Compare local-only flow with bounded direct-call summaries."""
    local_only = benchmark_scan(
        target,
        repeats=repeats,
        scanner=Scanner(
            enable_dataflow=True,
            enable_call_summaries=False,
        ),
    )
    summaries = benchmark_scan(
        target,
        repeats=repeats,
        scanner=Scanner(
            enable_dataflow=True,
            enable_call_summaries=True,
        ),
    )
    return {
        "schema": "malir.call-summary-ablation.v1",
        "local_only": local_only,
        "summaries": summaries,
        "mean_overhead_percent": round(
            100.0 * (summaries["mean_ms"] / local_only["mean_ms"] - 1.0),
            3,
        ),
        "median_overhead_percent": round(
            100.0 * (summaries["median_ms"] / local_only["median_ms"] - 1.0),
            3,
        ),
        "p95_overhead_percent": round(
            100.0 * (summaries["p95_ms"] / local_only["p95_ms"] - 1.0),
            3,
        ),
        "peak_allocation_overhead_percent": round(
            100.0
            * (
                summaries["tracemalloc_peak_bytes"]
                / local_only["tracemalloc_peak_bytes"]
                - 1.0
            ),
            3,
        ),
    }


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
        "dataflow_enabled": scanner.enable_dataflow,
        "call_summaries_enabled": scanner.enable_call_summaries,
        "files_per_run": files,
        "mean_ms": round(mean_ms, 4),
        "median_ms": round(statistics.median(timings), 4),
        "p95_ms": round(ordered[p95_index], 4),
        "files_per_second": (
            round(files / (mean_ms / 1_000.0), 2) if mean_ms else None
        ),
        "tracemalloc_peak_bytes": peak,
    }
