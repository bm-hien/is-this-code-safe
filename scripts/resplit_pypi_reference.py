#!/usr/bin/env python3
"""Create the preregistered leakage-closed V2 split without scoring."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.acquire_pypi_reference import (
    _atomic_write,
    _file_sha256,
    _read_jsonl,
    _write_json,
    _write_jsonl,
)
from scripts.pypi_hard_negative_study import EXPECTED_OMC_AUDIT_SHA256

V1_STUDY_ID = "itcs-pypi-hard-negative-2026-08-12-v1"
V2_STUDY_ID = "itcs-pypi-hard-negative-2026-08-12-v2"
TARGET_GROUPS = 900
GROUPS_PER_SPLIT = 450


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("v1_preparation_dir")
    parser.add_argument("omcbench_audit")
    parser.add_argument("output_dir")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source = _regular_directory(Path(args.v1_preparation_dir))
    output = _empty_output(Path(args.output_dir))
    omc_path = Path(args.omcbench_audit)
    v1_record, v1_hashes = _verify_v1_preparation(source)
    omc_rows = _verified_omc_rows(omc_path)
    v1_rows = _read_jsonl(source / "group-manifest.jsonl")
    group_rows, exclusions = _exclude_omc_overlaps(v1_rows, omc_rows)
    v2_group_manifest, split_manifest = _materialize_v2(group_rows, exclusions)
    _audit_v2(v2_group_manifest, split_manifest, omc_rows)

    _atomic_write(
        output / "artifact-audit.jsonl",
        _read_regular(source / "artifact-audit.jsonl", 20 * 1024 * 1024),
    )
    _write_jsonl(output / "group-manifest.jsonl", v2_group_manifest)
    _write_jsonl(output / "split-manifest.jsonl", split_manifest)
    output_hashes = {
        name: _file_sha256(output / name)
        for name in (
            "artifact-audit.jsonl",
            "group-manifest.jsonl",
            "split-manifest.jsonl",
        )
    }
    split_groups = {
        split: {row["group_id"] for row in split_manifest if row["split"] == split}
        for split in ("development", "holdout")
    }
    group_sizes = Counter(row["group_id"] for row in group_rows)
    selected_groups = {row["group_id"] for row in split_manifest}
    record = {
        "schema": "itcs.pypi-preparation.v2",
        "study_id": V2_STUDY_ID,
        "created_at": datetime.now(UTC).isoformat(),
        "input": {
            "plan_sha256": v1_record["input"]["plan_sha256"],
            "artifacts": v1_record["input"]["artifacts"],
            "declared_bytes": v1_record["input"]["declared_bytes"],
            "v1_study_id": V1_STUDY_ID,
            "v1_checksums_sha256": _file_sha256(source / "checksums.json"),
            "v1_group_manifest_sha256": v1_hashes["group-manifest.jsonl"],
            "omcbench_audit_sha256": EXPECTED_OMC_AUDIT_SHA256,
        },
        "leakage_closure": {
            "comparison_scope": "all-400-published-OMCBench-rows",
            "fields": [
                "archive_sha256",
                "source_set_hash",
                "normalized_ast_hash",
            ],
            "excluded_groups": len(exclusions),
            "excluded_artifacts": sum(group_sizes[group_id] for group_id in exclusions),
            "groups": [
                {"group_id": group_id, "overlap_fields": exclusions[group_id]}
                for group_id in sorted(exclusions)
            ],
        },
        "counts": {
            "eligible_artifacts_before_leakage_closure": len(v1_rows),
            "groups_before_leakage_closure": len(group_sizes),
            "groups_after_leakage_closure": len(group_sizes) - len(exclusions),
            "selected_artifacts": len(split_manifest),
            "selected_groups": len(selected_groups),
            "development_groups": len(split_groups["development"]),
            "holdout_groups": len(split_groups["holdout"]),
        },
        "limits": v1_record["limits"],
        "worker": {
            "network": "disabled-by-container-command",
            "fingerprints_reused_without_payload_reanalysis": True,
        },
        "output_sha256": output_hashes,
        "detector_scores_computed": False,
    }
    _write_json(output / "preparation.json", record)
    checksums = {
        **output_hashes,
        "preparation.json": _file_sha256(output / "preparation.json"),
    }
    _write_json(
        output / "checksums.json",
        {"schema": "itcs.checksums.v1", "sha256": checksums},
    )
    print(
        json.dumps(
            {
                "schema": "itcs.pypi-resplit-summary.v2",
                "study_id": V2_STUDY_ID,
                "excluded_overlap_groups": len(exclusions),
                "selected_artifacts": len(split_manifest),
                "development_groups": len(split_groups["development"]),
                "holdout_groups": len(split_groups["holdout"]),
                "split_manifest_sha256": output_hashes["split-manifest.jsonl"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _verify_v1_preparation(
    directory: Path,
) -> tuple[dict[str, Any], dict[str, str]]:
    checksums = _read_json(directory / "checksums.json").get("sha256")
    expected = {
        "artifact-audit.jsonl",
        "group-manifest.jsonl",
        "split-manifest.jsonl",
        "preparation.json",
    }
    if not isinstance(checksums, dict) or set(checksums) != expected:
        raise ValueError("V1 preparation checksums are incomplete")
    for name, digest in checksums.items():
        if not isinstance(digest, str) or _file_sha256(directory / name) != digest:
            raise ValueError(f"V1 preparation hash mismatch: {name}")
    record = _read_json(directory / "preparation.json")
    if record.get("study_id") != V1_STUDY_ID:
        raise ValueError("source preparation is not V1")
    if record.get("detector_scores_computed") is not False:
        raise ValueError("source preparation was not score blind")
    expected_outputs = {
        name: digest for name, digest in checksums.items() if name != "preparation.json"
    }
    if record.get("output_sha256") != expected_outputs:
        raise ValueError("V1 preparation record/checksum mismatch")
    return record, checksums


def _verified_omc_rows(path: Path) -> list[dict[str, Any]]:
    if _file_sha256(path) != EXPECTED_OMC_AUDIT_SHA256:
        raise ValueError("OMCBench audit hash mismatch")
    rows = _read_jsonl(path)
    support = Counter((row.get("split"), row.get("label")) for row in rows)
    if len(rows) != 400 or support != {
        ("validation", 0): 100,
        ("validation", 1): 100,
        ("test", 0): 100,
        ("test", 1): 100,
    }:
        raise ValueError("unexpected OMCBench audit support")
    return rows


def _exclude_omc_overlaps(
    pypi_rows: list[dict[str, Any]],
    omc_rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    fields = ("archive_sha256", "source_set_hash", "normalized_ast_hash")
    omc_values = {field: {str(row[field]) for row in omc_rows} for field in fields}
    exclusions: dict[str, set[str]] = {}
    for row in pypi_rows:
        group_id = str(row["group_id"])
        for field in fields:
            if str(row[field]) in omc_values[field]:
                exclusions.setdefault(group_id, set()).add(field)
    normalized = {
        group_id: sorted(overlap_fields)
        for group_id, overlap_fields in exclusions.items()
    }
    return pypi_rows, normalized


def _materialize_v2(
    rows: list[dict[str, Any]],
    exclusions: dict[str, list[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_group: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_group.setdefault(str(row["group_id"]), []).append(row)
    clean_groups = set(by_group) - set(exclusions)
    ordered = sorted(
        clean_groups,
        key=lambda group_id: (
            min(int(row["canonical_rank"]) for row in by_group[group_id]),
            group_id,
        ),
    )
    if len(ordered) < TARGET_GROUPS:
        raise ValueError("leakage closure leaves fewer than 900 groups")
    selected_groups = set(ordered[:TARGET_GROUPS])
    split_order = sorted(
        selected_groups,
        key=lambda group_id: hashlib.sha256(
            f"{V2_STUDY_ID}|{group_id}".encode()
        ).hexdigest(),
    )
    splits = {
        group_id: "development" if index % 2 == 0 else "holdout"
        for index, group_id in enumerate(split_order)
    }
    manifest = []
    selected_rows = []
    for row in rows:
        group_id = str(row["group_id"])
        base = {
            key: value for key, value in row.items() if key not in {"selected", "split"}
        }
        selected = group_id in selected_groups
        if group_id in exclusions:
            disposition = "excluded-omc-overlap"
        elif selected:
            disposition = splits[group_id]
        else:
            disposition = "reserve"
        item = {
            **base,
            "v1_selected": bool(row.get("selected")),
            "v1_split": row.get("split"),
            "v2_eligible": group_id not in exclusions,
            "v2_exclusion_fields": exclusions.get(group_id, []),
            "selected": selected,
            "split": disposition,
        }
        manifest.append(item)
        if selected:
            selected_rows.append(item)
    manifest.sort(key=lambda row: (int(row["rank"]), str(row["sample_id"])))
    selected_rows.sort(key=lambda row: (int(row["rank"]), str(row["sample_id"])))
    return manifest, selected_rows


def _audit_v2(
    manifest: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    omc_rows: list[dict[str, Any]],
) -> None:
    groups: dict[str, set[str]] = {}
    for row in selected:
        groups.setdefault(str(row["group_id"]), set()).add(str(row["split"]))
    if any(len(splits) != 1 for splits in groups.values()):
        raise ValueError("V2 group crosses splits")
    counts = Counter(next(iter(splits)) for splits in groups.values())
    if counts != {"development": GROUPS_PER_SPLIT, "holdout": GROUPS_PER_SPLIT}:
        raise ValueError("V2 does not contain 450 groups per split")
    omc_values = {
        field: {str(row[field]) for row in omc_rows}
        for field in ("archive_sha256", "source_set_hash", "normalized_ast_hash")
    }
    for field, values in omc_values.items():
        if any(str(row[field]) in values for row in selected):
            raise ValueError(f"V2 retains an OMCBench overlap: {field}")
    for field in (
        "archive_sha256",
        "source_set_hash",
        "normalized_ast_hash",
        "representation_hash",
        "normalized_project",
    ):
        partitions: dict[str, set[str]] = {}
        for row in selected:
            partitions.setdefault(str(row[field]), set()).add(str(row["split"]))
        if any(len(splits) != 1 for splits in partitions.values()):
            raise ValueError(f"V2 split leakage: {field}")
    excluded = {row["group_id"] for row in manifest if not row["v2_eligible"]}
    if excluded & set(groups):
        raise ValueError("V2 selected an excluded overlap group")


def _read_regular(path: Path, limit: int) -> bytes:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("input is not a regular non-symlinked file")
    if info.st_size > limit:
        raise ValueError("input exceeds byte limit")
    return path.read_bytes()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_read_regular(path, 20 * 1024 * 1024))
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON: {path.name}") from error
    if not isinstance(value, dict):
        raise TypeError(f"JSON root must be an object: {path.name}")
    return value


def _regular_directory(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("input directory cannot be a symlink")
    path = Path(os.path.abspath(path))
    if not path.is_dir():
        raise ValueError("input directory does not exist")
    return path


def _empty_output(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("output directory cannot be a symlink")
    path = Path(os.path.abspath(path))
    if path.exists():
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or any(path.iterdir()):
            raise ValueError("output directory must be empty")
    else:
        path.mkdir(parents=True)
    return path


if __name__ == "__main__":
    raise SystemExit(main())
