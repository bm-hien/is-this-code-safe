#!/usr/bin/env python3
"""Fingerprint and split PyPI archives without extracting or scoring them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import stat
import sys
import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from malir.archive import (
    ArchiveLimits,
    UnsafeArchiveError,
    analyze_sources,
    load_python_archive,
)
from malir.dedup import normalized_ast_hash, source_set_hash
from scripts.acquire_pypi_reference import (
    MAX_ARTIFACT_BYTES,
    STUDY_ID,
    _artifact_from_dict,
    _file_sha256,
    _read_jsonl,
    _verify_plan,
    _write_json,
    _write_jsonl,
)

EXPECTED_PLAN_SHA256 = (
    "3077d781efbf2ece56c86b3720293104696f4a35aaa882b236c6ad84e5c3518d"
)
TARGET_GROUPS = 900
DEVELOPMENT_GROUPS = 450
MAX_EVENTS = 2_000


class _UnionFind:
    def __init__(self, values: list[str]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: str) -> str:
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if left_root > right_root:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("acquisition_dir")
    parser.add_argument("output_dir")
    parser.add_argument(
        "--container-image",
        required=True,
        help="immutable image digest recorded in preparation metadata",
    )
    parser.add_argument("--progress-every", type=int, default=25)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.progress_every < 1:
        raise ValueError("progress-every must be positive")
    started = time.perf_counter()
    acquisition = _regular_directory(Path(args.acquisition_dir))
    output = _empty_output(Path(args.output_dir))
    plan = _verify_plan(acquisition)
    if plan["plan_sha256"] != EXPECTED_PLAN_SHA256:
        raise ValueError("acquisition plan is not the preregistered plan")
    plan_rows = _read_jsonl(acquisition / "artifacts.jsonl")
    limits = ArchiveLimits(max_archive_bytes=MAX_ARTIFACT_BYTES)
    audit_rows = []
    for index, row in enumerate(plan_rows, 1):
        audit_rows.append(
            _fingerprint_artifact(acquisition, row, limits, max_events=MAX_EVENTS)
        )
        if index % args.progress_every == 0 or index == len(plan_rows):
            print(
                f"fingerprinted {index}/{len(plan_rows)} artifacts",
                file=sys.stderr,
                flush=True,
            )

    grouped = _assign_groups(audit_rows)
    manifest = _select_and_split(grouped, TARGET_GROUPS)
    _audit_split(manifest)
    selected = [row for row in manifest if row["selected"]]
    _write_jsonl(output / "artifact-audit.jsonl", audit_rows)
    _write_jsonl(output / "group-manifest.jsonl", manifest)
    _write_jsonl(output / "split-manifest.jsonl", selected)
    hashes = {
        name: _file_sha256(output / name)
        for name in (
            "artifact-audit.jsonl",
            "group-manifest.jsonl",
            "split-manifest.jsonl",
        )
    }
    preparation = _preparation_record(
        audit_rows,
        manifest,
        plan,
        limits,
        args.container_image,
        hashes,
        elapsed_seconds=time.perf_counter() - started,
    )
    _write_json(output / "preparation.json", preparation)
    hashes["preparation.json"] = _file_sha256(output / "preparation.json")
    _write_json(
        output / "checksums.json",
        {"schema": "itcs.checksums.v1", "sha256": hashes},
    )
    print(
        json.dumps(
            {
                "schema": "itcs.pypi-preparation-summary.v1",
                "eligible_artifacts": preparation["counts"]["eligible_artifacts"],
                "normalized_groups": preparation["counts"]["groups"],
                "selected_groups": preparation["counts"]["selected_groups"],
                "development_groups": preparation["counts"]["development_groups"],
                "holdout_groups": preparation["counts"]["holdout_groups"],
                "split_manifest_sha256": hashes["split-manifest.jsonl"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _fingerprint_artifact(
    acquisition: Path,
    row: dict[str, Any],
    limits: ArchiveLimits,
    *,
    max_events: int,
) -> dict[str, Any]:
    artifact = _artifact_from_dict(row)
    storage_name = row.get("storage_name")
    if not isinstance(storage_name, str):
        raise TypeError("artifact storage name is missing")
    archive_path = acquisition / "artifacts" / storage_name
    started = time.perf_counter()
    try:
        contents = load_python_archive(archive_path, limits)
    except UnsafeArchiveError as error:
        return {
            **_public_artifact(row),
            "status": "archive-rejected",
            "error": _safe_error(error),
            "elapsed_ms": round((time.perf_counter() - started) * 1_000, 6),
        }
    if contents.archive_sha256 != artifact.sha256:
        raise ValueError("archive SHA-256 changed after acquisition")
    if contents.archive_bytes != artifact.size:
        raise ValueError("archive size changed after acquisition")
    if not contents.sources:
        return {
            **_public_artifact(row),
            "status": "no-python-source",
            "archive_format": contents.archive_format,
            "members_seen": contents.members_seen,
            "warnings": list(contents.warnings),
            "elapsed_ms": round((time.perf_counter() - started) * 1_000, 6),
        }

    exact_hash = source_set_hash(contents.sources)
    ast_hash = normalized_ast_hash(contents.sources)
    analyses = analyze_sources(
        contents.sources,
        enable_dataflow=True,
        max_events=max_events,
    )
    representation_hash = _representation_hash(analyses)
    return {
        **_public_artifact(row),
        "sample_id": f"pypi:{artifact.sha256[:32]}",
        "status": "ok",
        "archive_format": contents.archive_format,
        "members_seen": contents.members_seen,
        "python_files": len(contents.sources),
        "python_bytes": contents.python_bytes,
        "source_set_hash": exact_hash,
        "normalized_ast_hash": ast_hash,
        "representation_hash": representation_hash,
        "parse_error_files": sum(item.parse_error is not None for item in analyses),
        "event_limit_files": sum(item.event_limit_reached for item in analyses),
        "events": sum(len(item.events) for item in analyses),
        "behavior_paths": sum(len(item.behavior_paths) for item in analyses),
        "dataflow_paths": sum(
            path.evidence_kind == "dataflow"
            for analysis in analyses
            for path in analysis.behavior_paths
        ),
        "warnings": list(contents.warnings),
        "elapsed_ms": round((time.perf_counter() - started) * 1_000, 6),
    }


def _representation_hash(analyses) -> str:
    digest = hashlib.sha256()
    for analysis in analyses:
        tokens = [f"FILE:{analysis.path}", *analysis.tokens]
        for token in tokens:
            payload = token.encode("utf-8", errors="surrogatepass")
            digest.update(len(payload).to_bytes(8, "big"))
            digest.update(payload)
    return digest.hexdigest()


def _assign_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    eligible = [row for row in rows if row.get("status") == "ok"]
    identifiers = [str(row["sample_id"]) for row in eligible]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("duplicate sample ID")
    union = _UnionFind(identifiers)
    for field in ("archive_sha256", "source_set_hash", "normalized_ast_hash"):
        owners: dict[str, str] = {}
        for row in eligible:
            value = str(row[field])
            sample_id = str(row["sample_id"])
            previous = owners.setdefault(value, sample_id)
            union.union(previous, sample_id)

    members: dict[str, list[dict[str, Any]]] = {}
    for row in eligible:
        members.setdefault(union.find(str(row["sample_id"])), []).append(row)
    groups = {}
    for group_rows in members.values():
        identity = _group_id(group_rows)
        canonical_rank = min(int(row["rank"]) for row in group_rows)
        for row in group_rows:
            groups[str(row["sample_id"])] = {
                **row,
                "group_id": identity,
                "canonical_rank": canonical_rank,
                "group_size": len(group_rows),
            }
    return [groups[str(row["sample_id"])] for row in eligible]


def _group_id(rows: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for value in sorted(str(row["archive_sha256"]) for row in rows):
        payload = value.encode()
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return f"pypi-group:{digest.hexdigest()}"


def _select_and_split(
    grouped: list[dict[str, Any]],
    target_groups: int,
) -> list[dict[str, Any]]:
    if target_groups < 2 or target_groups % 2:
        raise ValueError("target group count must be positive and even")
    by_group: dict[str, list[dict[str, Any]]] = {}
    for row in grouped:
        by_group.setdefault(str(row["group_id"]), []).append(row)
    ordered = sorted(
        by_group,
        key=lambda group_id: (
            min(int(row["canonical_rank"]) for row in by_group[group_id]),
            group_id,
        ),
    )
    if len(ordered) < target_groups:
        raise ValueError("fewer eligible groups than the frozen target")
    selected_groups = set(ordered[:target_groups])
    split_order = sorted(
        selected_groups,
        key=lambda group_id: hashlib.sha256(
            f"{STUDY_ID}|{group_id}".encode()
        ).hexdigest(),
    )
    splits = {
        group_id: "development" if index % 2 == 0 else "holdout"
        for index, group_id in enumerate(split_order)
    }
    output = []
    for row in grouped:
        group_id = str(row["group_id"])
        selected = group_id in selected_groups
        output.append(
            {
                **row,
                "selected": selected,
                "split": splits[group_id] if selected else "reserve",
            }
        )
    return sorted(output, key=lambda row: (int(row["rank"]), row["sample_id"]))


def _audit_split(rows: list[dict[str, Any]]) -> None:
    selected = [row for row in rows if row["selected"]]
    group_splits: dict[str, set[str]] = {}
    for row in selected:
        group_splits.setdefault(str(row["group_id"]), set()).add(str(row["split"]))
    if any(len(splits) != 1 for splits in group_splits.values()):
        raise ValueError("group crosses the development/holdout split")
    counts = Counter(next(iter(splits)) for splits in group_splits.values())
    if counts != {"development": DEVELOPMENT_GROUPS, "holdout": 450}:
        raise ValueError("split does not contain 450 groups per partition")
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
            raise ValueError(f"split leakage detected for {field}")


def _preparation_record(
    audit_rows: list[dict[str, Any]],
    manifest: list[dict[str, Any]],
    plan: dict[str, Any],
    limits: ArchiveLimits,
    container_image: str,
    hashes: dict[str, str],
    *,
    elapsed_seconds: float,
) -> dict[str, Any]:
    status = Counter(str(row["status"]) for row in audit_rows)
    group_sizes = Counter(str(row["group_id"]) for row in manifest)
    selected = [row for row in manifest if row["selected"]]
    selected_groups = {str(row["group_id"]) for row in selected}
    split_groups = {
        split: {str(row["group_id"]) for row in selected if row["split"] == split}
        for split in ("development", "holdout")
    }
    return {
        "schema": "itcs.pypi-preparation.v1",
        "study_id": STUDY_ID,
        "input": {
            "plan_sha256": plan["plan_sha256"],
            "artifacts": plan["artifacts"],
            "declared_bytes": plan["declared_bytes"],
        },
        "worker": {
            "container_image": container_image,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "elapsed_seconds": elapsed_seconds,
            "network": "disabled-by-container-command",
        },
        "limits": asdict(limits) | {"max_events_per_file": MAX_EVENTS},
        "counts": {
            "status": dict(sorted(status.items())),
            "eligible_artifacts": len(manifest),
            "groups": len(group_sizes),
            "duplicate_groups": sum(size > 1 for size in group_sizes.values()),
            "artifacts_in_duplicate_groups": sum(
                size for size in group_sizes.values() if size > 1
            ),
            "selected_artifacts": len(selected),
            "selected_groups": len(selected_groups),
            "development_groups": len(split_groups["development"]),
            "holdout_groups": len(split_groups["holdout"]),
        },
        "output_sha256": hashes,
        "detector_scores_computed": False,
    }


def _public_artifact(row: dict[str, Any]) -> dict[str, Any]:
    artifact = _artifact_from_dict(row)
    return {
        "rank": artifact.rank,
        "project": artifact.project,
        "normalized_project": artifact.normalized_project,
        "version": artifact.version,
        "archive_sha256": artifact.sha256,
        "archive_bytes": artifact.size,
        "storage_name": row["storage_name"],
        "packagetype": artifact.packagetype,
        "upload_time": artifact.upload_time,
    }


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


def _safe_error(error: BaseException) -> str:
    return " ".join(str(error).split())[:300] or type(error).__name__


if __name__ == "__main__":
    raise SystemExit(main())