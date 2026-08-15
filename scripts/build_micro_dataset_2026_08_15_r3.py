#!/usr/bin/env python3
"""Build µMal data for the 2026-08-15-r3 process-aware MalIR contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from build_micro_dataset_2026_08_15 import VARIANTS
from build_micro_dataset_2026_08_15_r2 import build_r2_rows

from malir.data import load_training_dataset

TRAIN_COMPILER = "os.system('gcc --version')\n"
TRAIN_SHELL = "os.system('sh payload.sh')\n"
VALIDATION_COMPILER = (
    "platform.platform()\nsubprocess.run(['/usr/bin/clang', '--version'])\n"
)
VALIDATION_SHELL = "platform.platform()\nsubprocess.run(['sh', 'payload.sh'])\n"


def _setup_variant(source: str, variant: str) -> str:
    prefix = "import json\n" if variant == "import-context" else ""
    suffix = (
        "\nif __name__ == '__main__':\n    pass\n" if variant == "explicit-cli" else ""
    )
    return prefix + source + suffix


def _process_pair_rows(
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
            (negative_id, 0, "install-build-process", negative_source),
            (positive_id, 1, "install-shell-execution", positive_source),
        ):
            rows.append(
                {
                    "sample_id": f"{group_id}--{variant}",
                    "group_id": group_id,
                    "split": split,
                    "role": role,
                    "label": label,
                    "pair_id": pair_id,
                    "source": _setup_variant(source, variant),
                    "source_path": "setup.py",
                }
            )
    return rows


def build_r3_rows() -> list[dict]:
    rows = build_r2_rows()
    rows.extend(
        _process_pair_rows(
            "train",
            "train-install-compiler-2026-08-15-r3",
            "train-install-shell-2026-08-15-r3",
            "train-install-process-context-2026-08-15-r3",
            TRAIN_COMPILER,
            TRAIN_SHELL,
        )
    )
    rows.extend(
        _process_pair_rows(
            "validation",
            "validation-install-compiler-2026-08-15-r3",
            "validation-install-shell-2026-08-15-r3",
            "validation-install-process-context-2026-08-15-r3",
            VALIDATION_COMPILER,
            VALIDATION_SHELL,
        )
    )
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("examples/micro_train_2026_08_15_r3.jsonl"),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    rows = build_r3_rows()
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
