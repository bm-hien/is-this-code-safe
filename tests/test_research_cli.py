import json
from pathlib import Path

from malir.cli import main

EXAMPLES = Path(__file__).parents[1] / "examples"


def test_audit_manifest_cli_json(capsys):
    code = main(
        [
            "audit-manifest",
            str(EXAMPLES / "research_manifest.jsonl"),
            "--json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["schema"] == "itcs.manifest-audit.v1"
    assert report["rows"] == 12
    assert report["issues"] == []


def test_evaluate_predictions_cli_json(capsys):
    code = main(
        [
            "evaluate-predictions",
            str(EXAMPLES / "research_predictions.jsonl"),
            "--bootstrap",
            "20",
            "--seed",
            "11",
            "--json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["schema"] == "itcs.evaluation.v1"
    assert report["selection"]["selected_on"] == "validation"
    assert report["fpr_evidence"]["minimum_benign_if_zero_fp"] == 2995
    assert not report["fpr_evidence"]["target_supported"]
