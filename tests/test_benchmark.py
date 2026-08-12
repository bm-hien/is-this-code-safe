from pathlib import Path

from malir.benchmark import benchmark_scan


def test_benchmark_returns_latency_and_memory():
    target = Path(__file__).parent / "fixtures"
    result = benchmark_scan(target, repeats=2)
    assert result["files_per_run"] == 3
    assert result["median_ms"] > 0
    assert result["tracemalloc_peak_bytes"] > 0
