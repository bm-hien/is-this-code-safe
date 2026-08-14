import json
from pathlib import Path

from malir.benchmark import (
    benchmark_call_summary_ablation,
    benchmark_dataflow_ablation,
    benchmark_scan,
)
from malir.cli import main


def test_benchmark_returns_latency_and_memory():
    target = Path(__file__).parent / "fixtures"
    result = benchmark_scan(target, repeats=2)
    assert result["files_per_run"] == 5
    assert result["dataflow_enabled"] is True
    assert result["call_summaries_enabled"] is True
    assert result["median_ms"] > 0
    assert result["tracemalloc_peak_bytes"] > 0


def test_dataflow_ablation_reports_both_modes():
    target = Path(__file__).parent / "fixtures"
    result = benchmark_dataflow_ablation(target, repeats=2)
    assert result["schema"] == "malir.dataflow-ablation.v1"
    assert result["baseline"]["dataflow_enabled"] is False
    assert result["dataflow"]["dataflow_enabled"] is True
    assert isinstance(result["mean_overhead_percent"], float)
    assert isinstance(result["median_overhead_percent"], float)
    assert isinstance(result["p95_overhead_percent"], float)
    assert isinstance(result["peak_allocation_overhead_percent"], float)


def test_call_summary_ablation_reports_both_modes():
    target = Path(__file__).parent / "fixtures"
    result = benchmark_call_summary_ablation(target, repeats=2)
    assert result["schema"] == "malir.call-summary-ablation.v1"
    assert result["local_only"]["dataflow_enabled"] is True
    assert result["local_only"]["call_summaries_enabled"] is False
    assert result["summaries"]["dataflow_enabled"] is True
    assert result["summaries"]["call_summaries_enabled"] is True
    assert isinstance(result["mean_overhead_percent"], float)
    assert isinstance(result["median_overhead_percent"], float)
    assert isinstance(result["p95_overhead_percent"], float)
    assert isinstance(result["peak_allocation_overhead_percent"], float)


def test_cli_compares_call_summary_cost(capsys):
    target = Path(__file__).parent / "fixtures"
    code = main(
        [
            "benchmark",
            str(target),
            "--repeats",
            "2",
            "--compare-summaries",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["schema"] == "malir.call-summary-ablation.v1"
