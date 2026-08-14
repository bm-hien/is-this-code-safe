#!/usr/bin/env python3
"""Build µMal V3 paired-effect training and validation records."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from build_micro_dataset import SCENARIOS, build_records, event, scenario

from malir.data import load_training_dataset

_FILE_TRANSFER_GROUPS = {
    "train-artifact-publisher",
    "train-backup-sync",
    "validation-package-upload",
    "validation-backup-upload",
}


def _v3_base_scenarios() -> list[dict]:
    output = []
    for item in SCENARIOS:
        copied = {**item, "tokens": list(item["tokens"])}
        if item["id"] in _FILE_TRANSFER_GROUPS:
            copied["tokens"].append("MOTIF:file_to_network")
        if item["id"] == "train-local-obfuscator":
            copied["tokens"].extend(
                [
                    event("context", "IMPORT", "stdlib"),
                    event("source", "ENV_READ", "build_mode", phase="import"),
                    event("sink", "DYNAMIC_EXEC", "exec", phase="import"),
                    "EFFECT:FLOW:local_file_to_local_artifact",
                    "EFFECT:TRANSFORM:code_generation",
                ]
            )
        output.append(copied)
    return output


EXTRA_SCENARIOS = [
    scenario(
        "train-local-secret-bundle",
        "train",
        0,
        "local-sensitive-data-export",
        [
            event("source", "SENSITIVE_FILE_READ", ".config/credentials"),
            event("transform", "DYNAMIC_IMPORT", "codec_backend"),
            event("transform", "ENCODE", "base64.b64encode"),
            event("sink", "FILE_WRITE", "audit.bundle"),
        ],
        pair_id="train-sensitive-destination-v3",
    ),
    scenario(
        "train-encoded-secret-exfil-v3",
        "train",
        1,
        "sensitive-data-transfer",
        [
            event("source", "SENSITIVE_FILE_READ", ".config/credentials"),
            event("transform", "DYNAMIC_IMPORT", "codec_backend"),
            event("transform", "ENCODE", "base64.b64encode"),
            event("sink", "NETWORK_SEND", "https://collector.invalid"),
            "MOTIF:credential_or_file_exfil",
        ],
        pair_id="train-sensitive-destination-v3",
    ),
    scenario(
        "train-local-template-runner",
        "train",
        0,
        "local-code-transformer",
        [
            event("source", "FILE_READ", "template.py"),
            event("transform", "DYNAMIC_IMPORT", "template_backend"),
            event("transform", "CODE_COMPILE", "compile"),
            event("sink", "DYNAMIC_EXEC", "exec"),
            event("sink", "FILE_WRITE", "generated.py"),
            "PURPOSE:local_code_transformer",
        ],
        pair_id="train-code-origin-v3",
    ),
    scenario(
        "train-remote-compiled-executor",
        "train",
        1,
        "remote-code-executor",
        [
            event("source", "NETWORK_RECEIVE", "remote_source"),
            event("transform", "DYNAMIC_IMPORT", "runtime_backend"),
            event("transform", "CODE_COMPILE", "compile"),
            event("sink", "DYNAMIC_EXEC", "exec"),
            "MOTIF:download_execute",
        ],
        pair_id="train-code-origin-v3",
    ),
    scenario(
        "validation-local-secret-artifact",
        "validation",
        0,
        "local-sensitive-data-export",
        [
            event("source", "ENV_READ", "cloud_secret"),
            event("transform", "DYNAMIC_IMPORT", "codec_backend"),
            event("transform", "ENCODE", "base64.b64encode"),
            event("sink", "FILE_WRITE", "credential.backup"),
        ],
        pair_id="validation-sensitive-destination-v3",
    ),
    scenario(
        "validation-encoded-secret-transfer-v3",
        "validation",
        1,
        "sensitive-data-transfer",
        [
            event("source", "ENV_READ", "cloud_secret"),
            event("transform", "DYNAMIC_IMPORT", "codec_backend"),
            event("transform", "ENCODE", "base64.b64encode"),
            event("sink", "NETWORK_SEND", "https://collector.invalid"),
            "MOTIF:credential_or_file_exfil",
        ],
        pair_id="validation-sensitive-destination-v3",
    ),
]

V3_SCENARIOS = [*_v3_base_scenarios(), *EXTRA_SCENARIOS]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("examples/micro_train_v3.jsonl"),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows = build_records(V3_SCENARIOS)
    encoded = "\n".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows
    )
    args.output.write_text(encoded + "\n", encoding="utf-8")
    dataset = load_training_dataset(args.output)
    summary = {
        "output": str(args.output),
        "train_examples": len(dataset.train),
        "validation_examples": len(dataset.validation),
        "train_groups": len({row.group_id for row in dataset.train}),
        "validation_groups": len({row.group_id for row in dataset.validation}),
        "paired_rows": sum(row.pair_id is not None for row in dataset.all_examples),
        "dataset_sha256": dataset.dataset_sha256,
        "split_fingerprint": dataset.split_fingerprint,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
