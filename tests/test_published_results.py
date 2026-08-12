from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

RESULTS = (
    Path(__file__).parents[1] / "research" / "results" / "omcbench-python-2026-08-12"
)
FORBIDDEN_PAYLOAD_KEYS = {
    "archive_path",
    "code",
    "content",
    "path",
    "source",
    "tokens",
}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_no_payload_keys(value: Any) -> None:
    if isinstance(value, dict):
        assert FORBIDDEN_PAYLOAD_KEYS.isdisjoint(value)
        for child in value.values():
            _assert_no_payload_keys(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_payload_keys(child)


def test_published_omcbench_results_are_complete_and_payload_free() -> None:
    expected: dict[str, str] = {}
    for line in (RESULTS / "SHA256SUMS").read_text().splitlines():
        digest, filename = line.split(maxsplit=1)
        expected[filename] = digest

    assert set(expected) == {
        "local_flow_predictions.jsonl",
        "paired_report.json",
        "proximity_predictions.jsonl",
        "sample_audit.jsonl",
        "study.json",
    }
    for filename, digest in expected.items():
        assert _digest(RESULTS / filename) == digest

    for filename in (
        "local_flow_predictions.jsonl",
        "proximity_predictions.jsonl",
        "sample_audit.jsonl",
    ):
        rows = [
            json.loads(line) for line in (RESULTS / filename).read_text().splitlines()
        ]
        assert len(rows) == 400
        for row in rows:
            _assert_no_payload_keys(row)

    study = json.loads((RESULTS / "study.json").read_text())
    assert study["corpus"]["pinned"] is True
    assert study["results"]["status_counts"] == {"ok": 400}
    assert study["grouping"]["normalized_ast_groups"] == 338
