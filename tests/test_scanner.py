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


def test_parse_error_becomes_warning(tmp_path):
    target = tmp_path / "broken.py"
    target.write_text("def broken(:\n", encoding="utf-8")
    report = Scanner().scan(tmp_path)
    assert report.files[0].parse_error
    assert any("parse error" in warning for warning in report.warnings)
