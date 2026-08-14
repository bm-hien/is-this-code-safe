#!/usr/bin/env python3
"""Build the leakage-audited synthetic µMal V2 behavior dataset."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from malir.data import load_training_dataset


def event(
    category: str,
    operation: str,
    target: str,
    *,
    phase: str = "runtime",
) -> str:
    return f"P:{phase}|C:{category}|O:{operation}|T:{target}"


def scenario(
    identifier: str,
    split: str,
    label: int,
    role: str,
    tokens: list[str],
    *,
    pair_id: str | None = None,
) -> dict:
    return {
        "id": identifier,
        "split": split,
        "label": label,
        "role": role,
        "tokens": tokens,
        "pair_id": pair_id,
    }


SCENARIOS = [
    scenario(
        "train-local-compiler",
        "train",
        0,
        "local-code-transformer",
        [
            event("source", "FILE_READ", "input.py"),
            event("transform", "CODE_COMPILE", "compile"),
            event("sink", "FILE_WRITE", "output.py"),
            "PURPOSE:local_code_transformer",
        ],
    ),
    scenario(
        "train-local-obfuscator",
        "train",
        0,
        "local-code-transformer",
        [
            event("source", "FILE_READ", "module.py"),
            event("transform", "DYNAMIC_IMPORT", "backend"),
            event("transform", "ENCODE", "zlib.compress"),
            event("sink", "DYNAMIC_EXEC", "exec"),
            event("sink", "FILE_WRITE", "protected.py"),
            "PURPOSE:local_code_transformer",
        ],
        pair_id="train-execution-context",
    ),
    scenario(
        "train-artifact-publisher",
        "train",
        0,
        "artifact-transfer",
        [
            event("source", "FILE_READ", "dist/package.whl"),
            event("sink", "NETWORK_SEND", "https://registry.invalid/upload"),
        ],
        pair_id="train-file-network",
    ),
    scenario(
        "train-backup-sync",
        "train",
        0,
        "authorized-backup",
        [
            event("source", "FILE_READ", "documents"),
            event("transform", "ENCODE", "gzip.compress"),
            event("sink", "NETWORK_SEND", "https://backup.invalid"),
        ],
        pair_id="train-encoded-network",
    ),
    scenario(
        "train-download-cache",
        "train",
        0,
        "remote-data-cache",
        [
            event("source", "NETWORK_RECEIVE", "https://cdn.invalid/data"),
            event("sink", "FILE_WRITE", "cache.bin"),
        ],
        pair_id="train-network-input",
    ),
    scenario(
        "train-telemetry-client",
        "train",
        0,
        "diagnostic-telemetry",
        [
            event("source", "SYSTEM_DISCOVERY", "platform.platform"),
            event("sink", "NETWORK_SEND", "https://telemetry.invalid"),
        ],
        pair_id="train-host-network",
    ),
    scenario(
        "train-build-runner",
        "train",
        0,
        "local-build-tool",
        [
            event("source", "FILE_READ", "project.toml"),
            event("sink", "PROCESS_EXEC", "compiler"),
            event("sink", "FILE_WRITE", "build.log"),
        ],
    ),
    scenario(
        "train-plugin-loader",
        "train",
        0,
        "plugin-system",
        [
            event("transform", "DYNAMIC_IMPORT", "plugin_name"),
            event("source", "FILE_READ", "plugin.json"),
        ],
    ),
    scenario(
        "train-environment-config",
        "train",
        0,
        "configuration",
        [
            event("source", "ENV_READ", "log_level"),
            event("sink", "FILE_WRITE", "settings.json"),
        ],
    ),
    scenario(
        "train-local-archive",
        "train",
        0,
        "local-archive",
        [
            event("source", "FILE_READ", "dataset.csv"),
            event("transform", "ENCODE", "bz2.compress"),
            event("sink", "FILE_WRITE", "dataset.bz2"),
        ],
    ),
    scenario(
        "train-environment-exfil",
        "train",
        1,
        "sensitive-data-transfer",
        [
            event("source", "ENV_READ", "ci_token"),
            event("transform", "ENCODE", "base64.b64encode"),
            event("sink", "NETWORK_SEND", "https://collector.invalid"),
            "MOTIF:credential_or_file_exfil",
        ],
        pair_id="train-encoded-network",
    ),
    scenario(
        "train-sensitive-file-exfil",
        "train",
        1,
        "sensitive-data-transfer",
        [
            event("source", "SENSITIVE_FILE_READ", ".ssh/id_rsa"),
            event("sink", "NETWORK_SEND", "https://collector.invalid"),
            "MOTIF:credential_or_file_exfil",
        ],
        pair_id="train-file-network",
    ),
    scenario(
        "train-download-process",
        "train",
        1,
        "remote-code-executor",
        [
            event("source", "NETWORK_RECEIVE", "https://payload.invalid"),
            event("sink", "PROCESS_EXEC", "payload"),
            "MOTIF:download_execute",
        ],
        pair_id="train-network-input",
    ),
    scenario(
        "train-encoded-dynamic-exec",
        "train",
        1,
        "remote-code-executor",
        [
            event("source", "NETWORK_RECEIVE", "remote_blob"),
            event("transform", "DECODE", "base64.b64decode"),
            event("sink", "DYNAMIC_EXEC", "exec"),
            "MOTIF:download_execute",
            "MOTIF:encoded_execution",
        ],
        pair_id="train-execution-context",
    ),
    scenario(
        "train-persistence-write",
        "train",
        1,
        "persistence-modifier",
        [
            event("source", "FILE_READ", "payload.py"),
            event("sink", "PERSISTENCE_WRITE", ".bashrc"),
            "MOTIF:persistence_write",
        ],
    ),
    scenario(
        "train-destructive-delete",
        "train",
        1,
        "destructive-file-operator",
        [
            event("sink", "FILE_DELETE", "user_documents"),
            "MOTIF:destructive_file_action",
        ],
    ),
    scenario(
        "train-install-execution",
        "train",
        1,
        "install-time-executor",
        [
            event("sink", "PROCESS_EXEC", "shell", phase="install"),
            "MOTIF:install_time_execution",
            "EFFECT:ENTRY:install_time",
        ],
    ),
    scenario(
        "train-fingerprinting-transfer",
        "train",
        1,
        "host-fingerprinting-transfer",
        [
            event("source", "SYSTEM_DISCOVERY", "hostname"),
            event("sink", "NETWORK_SEND", "https://collector.invalid"),
            "MOTIF:fingerprinting_transfer",
        ],
        pair_id="train-host-network",
    ),
    scenario(
        "train-unsafe-deserialize",
        "train",
        1,
        "encoded-executor",
        [
            event("transform", "UNSAFE_DESERIALIZE", "pickle.loads"),
            event("sink", "DYNAMIC_EXEC", "exec"),
            "MOTIF:encoded_execution",
        ],
    ),
    scenario(
        "train-install-exfil",
        "train",
        1,
        "install-time-exfiltration",
        [
            event("source", "ENV_READ", "api_key", phase="install"),
            event("sink", "NETWORK_SEND", "https://collector.invalid", phase="install"),
            "MOTIF:credential_or_file_exfil",
            "EFFECT:ENTRY:install_time",
        ],
    ),
    scenario(
        "validation-local-codegen",
        "validation",
        0,
        "local-code-transformer",
        [
            event("source", "FILE_READ", "grammar.py"),
            event("transform", "CODE_COMPILE", "compile"),
            event("sink", "DYNAMIC_EXEC", "exec"),
            event("sink", "FILE_WRITE", "parser.py"),
            "PURPOSE:local_code_transformer",
        ],
        pair_id="validation-execution-context",
    ),
    scenario(
        "validation-package-upload",
        "validation",
        0,
        "artifact-transfer",
        [
            event("source", "ENV_READ", "release_channel"),
            event("source", "FILE_READ", "release.tar.gz"),
            event("sink", "NETWORK_SEND", "https://packages.invalid"),
        ],
        pair_id="validation-file-network",
    ),
    scenario(
        "validation-updater-cache",
        "validation",
        0,
        "remote-data-cache",
        [
            event("source", "NETWORK_RECEIVE", "https://updates.invalid/index"),
            event("transform", "DECODE", "json.loads"),
            event("sink", "FILE_WRITE", "index.json"),
        ],
        pair_id="validation-network-input",
    ),
    scenario(
        "validation-diagnostic-report",
        "validation",
        0,
        "local-diagnostics",
        [
            event("source", "SYSTEM_DISCOVERY", "platform"),
            event("source", "ENV_READ", "timezone"),
            event("sink", "FILE_WRITE", "diagnostics.txt"),
        ],
        pair_id="validation-host-context",
    ),
    scenario(
        "validation-backup-upload",
        "validation",
        0,
        "authorized-backup",
        [
            event("source", "SYSTEM_DISCOVERY", "hostname"),
            event("source", "FILE_READ", "workspace"),
            event("transform", "ENCODE", "gzip.compress"),
            event("sink", "NETWORK_SEND", "https://backup.invalid"),
        ],
        pair_id="validation-encoded-network",
    ),
    scenario(
        "validation-cookie-exfil",
        "validation",
        1,
        "sensitive-data-transfer",
        [
            event("source", "SENSITIVE_FILE_READ", "browser/cookies"),
            event("transform", "ENCODE", "base64.b64encode"),
            event("sink", "NETWORK_SEND", "socket.send"),
            "MOTIF:credential_or_file_exfil",
        ],
        pair_id="validation-file-network",
    ),
    scenario(
        "validation-remote-shell",
        "validation",
        1,
        "remote-code-executor",
        [
            event("source", "NETWORK_RECEIVE", "command"),
            event("transform", "DECODE", "binascii.unhexlify"),
            event("sink", "PROCESS_EXEC", "shell"),
            "MOTIF:download_execute",
        ],
        pair_id="validation-network-input",
    ),
    scenario(
        "validation-credential-persistence",
        "validation",
        1,
        "persistence-modifier",
        [
            event("source", "ENV_READ", "cloud_secret"),
            event("sink", "PERSISTENCE_WRITE", "startup"),
            "MOTIF:persistence_write",
        ],
        pair_id="validation-host-context",
    ),
    scenario(
        "validation-destructive-archive",
        "validation",
        1,
        "destructive-file-operator",
        [
            event("source", "FILE_READ", "documents"),
            event("transform", "ENCODE", "gzip.compress"),
            event("sink", "FILE_DELETE", "documents"),
            "MOTIF:destructive_file_action",
        ],
        pair_id="validation-encoded-network",
    ),
    scenario(
        "validation-remote-dynamic-exec",
        "validation",
        1,
        "remote-code-executor",
        [
            event("source", "NETWORK_RECEIVE", "remote_source"),
            event("transform", "DECODE", "base64.b64decode"),
            event("transform", "DYNAMIC_IMPORT", "runtime_backend"),
            event("sink", "DYNAMIC_EXEC", "eval"),
            "MOTIF:download_execute",
            "MOTIF:encoded_execution",
        ],
        pair_id="validation-execution-context",
    ),
]

VARIANTS = (
    ("base", []),
    ("import-context", [event("context", "IMPORT", "stdlib", phase="import")]),
    ("explicit-cli", ["EFFECT:ENTRY:explicit_cli"]),
)


def build_records() -> list[dict]:
    records = []
    for item in SCENARIOS:
        for suffix, additions in VARIANTS:
            record = {
                "sample_id": f"{item['id']}--{suffix}",
                "group_id": item["id"],
                "split": item["split"],
                "role": item["role"],
                "label": item["label"],
                "tokens": item["tokens"] + additions,
            }
            if item["pair_id"] is not None:
                record["pair_id"] = item["pair_id"]
            records.append(record)
    return records


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("examples/micro_train_v2.jsonl"),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows = build_records()
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
        "dataset_sha256": dataset.dataset_sha256,
        "split_fingerprint": dataset.split_fingerprint,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
