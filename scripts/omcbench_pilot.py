#!/usr/bin/env python3
"""Run a non-executing, paired ITCS pilot on a pinned OMCBench checkout."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePath
from typing import Any

from malir.archive import (
    ArchiveLimits,
    UnsafeArchiveError,
    analyze_sources,
    load_python_archive,
)
from malir.comparison import paired_comparison_report
from malir.detector import decide
from malir.evaluation import PredictionRow

PINNED_CORPUS_COMMIT = "f0722971eddb654c308106c9086ff69da5b0484b"
PINNED_MANIFEST_SHA256 = (
    "c3b65ae73dbe78f5a9dbf18a77fb604c431848e4ed093f4c4b078eb6765fb84c"
)


@dataclass(frozen=True, slots=True)
class CorpusItem:
    sample_id: str
    archive_name: str
    label: int
    split: str = ""

    @property
    def group_id(self) -> str:
        return self.sample_id


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="paired proximity/local-flow pilot; package code is never run"
    )
    parser.add_argument("benchmark_root", help="pinned OMCBench checkout")
    parser.add_argument("-o", "--output-dir", required=True)
    parser.add_argument("--seed", type=int, default=20_260_812)
    parser.add_argument("--validation-fraction", type=float, default=0.5)
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--bootstrap", type=int, default=2_000)
    parser.add_argument(
        "--max-per-label",
        type=int,
        default=0,
        help="deterministic smoke subset; zero uses all 200 per label",
    )
    parser.add_argument("--max-events", type=int, default=2_000)
    parser.add_argument("--progress-every", type=int, default=25)
    parser.add_argument("--allow-unpinned", action="store_true")
    parser.add_argument(
        "--container-image",
        default="unspecified",
        help="immutable image digest recorded in study metadata",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 0.0 < args.validation_fraction < 1.0:
        raise ValueError("validation-fraction must be in (0, 1)")
    if args.max_per_label not in (0, 1) and args.max_per_label < 2:
        raise ValueError("max-per-label must be zero, one, or at least two")
    if args.max_events < 1 or args.progress_every < 1:
        raise ValueError("event and progress limits must be positive")

    started_at = datetime.now(UTC)
    started = time.perf_counter()
    root = Path(args.benchmark_root).resolve()
    output = Path(args.output_dir).resolve()
    provenance = _verify_provenance(root, args.allow_unpinned)
    items = _load_items(root / "results" / "manifest.csv")
    if args.max_per_label:
        items = _subset(items, args.max_per_label, args.seed)
    items = _assign_splits(items, args.validation_fraction, args.seed)
    _validate_study_items(items)
    _prepare_output(output)
    limits = ArchiveLimits()
    baseline_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    ordered = sorted(
        items,
        key=lambda item: _rank(args.seed, "scan", item.sample_id),
    )
    for index, item in enumerate(ordered, 1):
        baseline, candidate, audit = _scan_item(
            root,
            item,
            limits,
            max_events=args.max_events,
            candidate_first=(
                int(_rank(args.seed, "order", item.sample_id)[-1], 16) % 2 == 1
            ),
        )
        baseline_rows.append(baseline)
        candidate_rows.append(candidate)
        audit_rows.append(audit)
        if index % args.progress_every == 0 or index == len(ordered):
            elapsed = time.perf_counter() - started
            print(
                f"scanned {index}/{len(ordered)} packages in {elapsed:.1f}s",
                file=sys.stderr,
                flush=True,
            )

    baseline_rows.sort(key=lambda row: str(row["sample_id"]))
    candidate_rows.sort(key=lambda row: str(row["sample_id"]))
    audit_rows.sort(key=lambda row: str(row["sample_id"]))
    baseline_path = output / "proximity_predictions.jsonl"
    candidate_path = output / "local_flow_predictions.jsonl"
    audit_path = output / "sample_audit.jsonl"
    _write_jsonl(baseline_path, baseline_rows)
    _write_jsonl(candidate_path, candidate_rows)
    _write_jsonl(audit_path, audit_rows)

    baseline_predictions = [PredictionRow(**row) for row in baseline_rows]
    candidate_predictions = [PredictionRow(**row) for row in candidate_rows]
    report = paired_comparison_report(
        baseline_predictions,
        candidate_predictions,
        target_fpr=args.target_fpr,
        bootstrap=args.bootstrap,
        seed=args.seed,
    )
    report_path = output / "paired_report.json"
    _write_json(report_path, report)

    elapsed_seconds = time.perf_counter() - started
    study = _study_record(
        args,
        root,
        items,
        audit_rows,
        report,
        provenance,
        limits,
        started_at=started_at,
        elapsed_seconds=elapsed_seconds,
        output_files=[
            baseline_path,
            candidate_path,
            audit_path,
            report_path,
        ],
    )
    study_path = output / "study.json"
    _write_json(study_path, study)
    summary = {
        "schema": "itcs.omcbench-pilot-summary.v1",
        "packages": len(items),
        "elapsed_seconds": elapsed_seconds,
        "status_counts": study["results"]["status_counts"],
        "score_changed_packages": study["results"]["score_changed_packages"],
        "recall_delta": report["effects"]["recall"]["delta"],
        "false_positive_rate_delta": (
            report["effects"]["false_positive_rate"]["delta"]
        ),
        "claim_status": report["claim_gate"]["status"],
        "output_dir": str(output),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def _verify_provenance(root: Path, allow_unpinned: bool) -> dict[str, Any]:
    manifest = root / "results" / "manifest.csv"
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("manifest must be a regular, non-symlinked file")
    manifest_hash = _file_sha256(manifest)
    commit = _git_head(root)
    pinned = commit == PINNED_CORPUS_COMMIT and manifest_hash == PINNED_MANIFEST_SHA256
    if not pinned and not allow_unpinned:
        raise ValueError(
            "OMCBench provenance mismatch; use the pinned commit and manifest"
        )
    return {
        "pinned": pinned,
        "commit": commit,
        "manifest_sha256": manifest_hash,
        "expected_commit": PINNED_CORPUS_COMMIT,
        "expected_manifest_sha256": PINNED_MANIFEST_SHA256,
    }


def _load_items(manifest: Path) -> list[CorpusItem]:
    if manifest.stat().st_size > 2_000_000:
        raise ValueError("manifest exceeds two megabytes")
    with manifest.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        expected = {"folder_name", "ecosystem", "label_true"}
        if set(reader.fieldnames or ()) != expected:
            raise ValueError("unexpected OMCBench manifest fields")
        items = []
        seen_names: set[str] = set()
        for row in reader:
            if row["ecosystem"] != "py":
                continue
            name = row["folder_name"]
            if (
                not name
                or PurePath(name).name != name
                or "/" in name
                or "\\" in name
                or any(ord(character) < 32 for character in name)
            ):
                raise ValueError("unsafe archive name in manifest")
            if name in seen_names:
                raise ValueError("duplicate Python archive in manifest")
            seen_names.add(name)
            label_text = row["label_true"]
            if label_text not in {"benign", "malicious"}:
                raise ValueError("unsupported manifest label")
            items.append(
                CorpusItem(
                    sample_id=_sample_id(name),
                    archive_name=name,
                    label=int(label_text == "malicious"),
                )
            )
    if not items:
        raise ValueError("manifest contains no Python rows")
    return items


def _subset(
    items: list[CorpusItem],
    max_per_label: int,
    seed: int,
) -> list[CorpusItem]:
    selected = []
    for label in (0, 1):
        members = sorted(
            (item for item in items if item.label == label),
            key=lambda item: _rank(seed, "subset", item.archive_name),
        )
        selected.extend(members[:max_per_label])
    return selected


def _assign_splits(
    items: list[CorpusItem],
    validation_fraction: float,
    seed: int,
) -> list[CorpusItem]:
    output = []
    for label in (0, 1):
        members = sorted(
            (item for item in items if item.label == label),
            key=lambda item: _rank(seed, "split", item.archive_name),
        )
        if len(members) < 2:
            raise ValueError("each label needs at least two samples")
        validation_count = round(len(members) * validation_fraction)
        validation_count = min(len(members) - 1, max(1, validation_count))
        for index, item in enumerate(members):
            output.append(
                CorpusItem(
                    sample_id=item.sample_id,
                    archive_name=item.archive_name,
                    label=item.label,
                    split=("validation" if index < validation_count else "test"),
                )
            )
    return output


def _validate_study_items(items: list[CorpusItem]) -> None:
    ids = [item.sample_id for item in items]
    if len(ids) != len(set(ids)):
        raise ValueError("sample IDs are not unique")
    support = Counter((item.split, item.label) for item in items)
    if any(
        support[(split, label)] < 1
        for split in ("validation", "test")
        for label in (0, 1)
    ):
        raise ValueError("validation and test need both labels")


def _scan_item(
    root: Path,
    item: CorpusItem,
    limits: ArchiveLimits,
    *,
    max_events: int,
    candidate_first: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    archive_path = root / "packages" / item.archive_name
    load_started = time.perf_counter()
    try:
        contents = load_python_archive(archive_path, limits)
        load_ms = (time.perf_counter() - load_started) * 1_000.0
    except (OSError, UnsafeArchiveError, ValueError) as error:
        load_ms = (time.perf_counter() - load_started) * 1_000.0
        digest = _file_sha256(archive_path) if archive_path.is_file() else None
        prediction = _prediction(item, 0.0, load_ms)
        audit = {
            "sample_id": item.sample_id,
            "archive_name": item.archive_name,
            "archive_sha256": digest,
            "archive_bytes": (
                archive_path.stat().st_size if archive_path.is_file() else None
            ),
            "label": item.label,
            "split": item.split,
            "status": "archive-rejected",
            "error": _safe_error(error),
            "load_ms": load_ms,
        }
        return dict(prediction), dict(prediction), audit

    modes = [True, False] if candidate_first else [False, True]
    outcomes: dict[bool, dict[str, Any]] = {}
    for enable_dataflow in modes:
        analysis_started = time.perf_counter()
        analyses = analyze_sources(
            contents.sources,
            enable_dataflow=enable_dataflow,
            max_events=max_events,
        )
        decision = decide(analyses)
        analysis_ms = (time.perf_counter() - analysis_started) * 1_000.0
        outcomes[enable_dataflow] = {
            "score": decision.risk_score / 100.0,
            "analysis_ms": analysis_ms,
            "parse_errors": sum(item.parse_error is not None for item in analyses),
            "truncated_files": sum(item.truncated for item in analyses),
            "event_limit_files": sum(item.event_limit_reached for item in analyses),
            "dataflow_paths": sum(
                path.evidence_kind == "dataflow"
                for analysis in analyses
                for path in analysis.behavior_paths
            ),
            "proximity_paths": sum(
                path.evidence_kind == "proximity"
                for analysis in analyses
                for path in analysis.behavior_paths
            ),
            "evidence_count": len(decision.evidence),
        }

    baseline = _prediction(
        item,
        float(outcomes[False]["score"]),
        load_ms + float(outcomes[False]["analysis_ms"]),
    )
    candidate = _prediction(
        item,
        float(outcomes[True]["score"]),
        load_ms + float(outcomes[True]["analysis_ms"]),
    )
    status = "ok" if contents.sources else "no-python-source"
    audit = {
        "sample_id": item.sample_id,
        "archive_name": item.archive_name,
        "archive_sha256": contents.archive_sha256,
        "archive_bytes": contents.archive_bytes,
        "archive_format": contents.archive_format,
        "members_seen": contents.members_seen,
        "python_files": len(contents.sources),
        "python_bytes": contents.python_bytes,
        "label": item.label,
        "split": item.split,
        "status": status,
        "warnings": list(contents.warnings),
        "load_ms": load_ms,
        "proximity_only": outcomes[False],
        "local_flow": outcomes[True],
    }
    return baseline, candidate, audit


def _prediction(
    item: CorpusItem,
    score: float,
    latency_ms: float,
) -> dict[str, Any]:
    return {
        "sample_id": item.sample_id,
        "label": item.label,
        "score": round(score, 8),
        "split": item.split,
        "group_id": item.group_id,
        "model_invoked": False,
        "latency_ms": round(latency_ms, 6),
    }


def _study_record(
    args: argparse.Namespace,
    root: Path,
    items: list[CorpusItem],
    audit_rows: list[dict[str, Any]],
    report: dict[str, Any],
    provenance: dict[str, Any],
    limits: ArchiveLimits,
    *,
    started_at: datetime,
    elapsed_seconds: float,
    output_files: list[Path],
) -> dict[str, Any]:
    status_counts = Counter(str(row["status"]) for row in audit_rows)
    score_changed = sum(
        abs(
            float(row.get("local_flow", {}).get("score", 0.0))
            - float(row.get("proximity_only", {}).get("score", 0.0))
        )
        > 1e-12
        for row in audit_rows
    )
    archive_fingerprint = _archive_set_fingerprint(audit_rows)
    return {
        "schema": "itcs.omcbench-pilot.v1",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(UTC).isoformat(),
        "elapsed_seconds": elapsed_seconds,
        "repository_commit": _git_head(Path(__file__).resolve().parents[1]),
        "corpus": {
            "name": "OMCBench",
            "root_recorded_as": str(root),
            **provenance,
            "archive_set_fingerprint": archive_fingerprint,
        },
        "configuration": {
            "seed": args.seed,
            "validation_fraction": args.validation_fraction,
            "target_fpr": args.target_fpr,
            "bootstrap": args.bootstrap,
            "max_per_label": args.max_per_label,
            "max_events": args.max_events,
            "error_handling": "archive-rejection-as-score-zero",
            "baseline": "proximity-only",
            "candidate": "candidate-gated-local-flow",
            "analysis_latency_includes_archive_read": True,
            "limits": asdict(limits),
        },
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
            "container_image": args.container_image,
            "cgroup_memory_max": _read_optional(Path("/sys/fs/cgroup/memory.max")),
            "cgroup_cpu_max": _read_optional(Path("/sys/fs/cgroup/cpu.max")),
        },
        "support": {
            f"{split}_{'malicious' if label else 'benign'}": count
            for (split, label), count in sorted(
                Counter((item.split, item.label) for item in items).items()
            )
        },
        "results": {
            "status_counts": dict(sorted(status_counts.items())),
            "python_files": sum(int(row.get("python_files", 0)) for row in audit_rows),
            "python_bytes": sum(int(row.get("python_bytes", 0)) for row in audit_rows),
            "parse_error_files": sum(
                int(row.get("local_flow", {}).get("parse_errors", 0))
                for row in audit_rows
            ),
            "dataflow_paths": sum(
                int(row.get("local_flow", {}).get("dataflow_paths", 0))
                for row in audit_rows
            ),
            "score_changed_packages": score_changed,
            "claim_status": report["claim_gate"]["status"],
        },
        "output_sha256": {path.name: _file_sha256(path) for path in output_files},
    }


def _archive_set_fingerprint(rows: list[dict[str, Any]]) -> str:
    canonical = [
        {
            "sample_id": row["sample_id"],
            "archive_sha256": row.get("archive_sha256"),
            "archive_bytes": row.get("archive_bytes"),
        }
        for row in sorted(rows, key=lambda item: str(item["sample_id"]))
    ]
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _prepare_output(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("output directory cannot be a symlink")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError("output path must be a directory")
    if any(path.iterdir()):
        raise ValueError("output directory must be empty")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    payload = "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows
    )
    _atomic_write(path, payload)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _atomic_write(path: Path, payload: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    if path.exists() or temporary.exists():
        raise ValueError(f"refusing to overwrite {path.name}")
    with temporary.open("x", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _sample_id(archive_name: str) -> str:
    digest = hashlib.sha256(archive_name.encode()).hexdigest()
    return f"omc-py-{digest[:20]}"


def _rank(seed: int, namespace: str, value: str) -> str:
    return hashlib.sha256(f"{seed}\0{namespace}\0{value}".encode()).hexdigest()


def _safe_error(error: Exception) -> str:
    text = "".join(
        character if 32 <= ord(character) < 127 else "?" for character in str(error)
    )
    return f"{type(error).__name__}: {text}"[:300]


def _git_head(root: Path) -> str | None:
    git = root / ".git"
    if not git.is_dir():
        return None
    head = (git / "HEAD").read_text(encoding="utf-8").strip()
    if head.startswith("ref: "):
        reference = git / head.removeprefix("ref: ")
        if not reference.is_file():
            return None
        head = reference.read_text(encoding="utf-8").strip()
    return head if len(head) == 40 else None


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_optional(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
