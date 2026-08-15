#!/usr/bin/env python3
"""Build µMal data for the 2026-08-15-r2 deletion-aware MalIR contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from build_micro_dataset_2026_08_15 import VARIANTS, _variant_source, build_rows

from malir.data import load_training_dataset

TRAIN_CLEANUP = """\ndef collect():\n    os.remove('cache.tmp')\n"""
TRAIN_DESTRUCTIVE = """\ndef collect():\n    os.remove('user_documents')\n"""
VALIDATION_CLEANUP = (
    """\ndef collect():\n    platform.platform()\n    shutil.rmtree('build')\n"""
)
VALIDATION_DESTRUCTIVE = (
    """\ndef collect():\n    platform.platform()\n    shutil.rmtree('payloads')\n"""
)


def _delete_pair_rows(
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
            (negative_id, 0, "temporary-cleanup", negative_source),
            (positive_id, 1, "destructive-file-operator", positive_source),
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


def build_r2_rows() -> list[dict]:
    rows = build_rows()
    rows.extend(
        _delete_pair_rows(
            "train",
            "train-temporary-cleanup-2026-08-15-r2",
            "train-destructive-delete-2026-08-15-r2",
            "train-delete-context-2026-08-15-r2",
            TRAIN_CLEANUP,
            TRAIN_DESTRUCTIVE,
        )
    )
    rows.extend(
        _delete_pair_rows(
            "validation",
            "validation-build-cleanup-2026-08-15-r2",
            "validation-recursive-delete-2026-08-15-r2",
            "validation-delete-context-2026-08-15-r2",
            VALIDATION_CLEANUP,
            VALIDATION_DESTRUCTIVE,
        )
    )
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("examples/micro_train_2026_08_15_r2.jsonl"),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    rows = build_r2_rows()
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
