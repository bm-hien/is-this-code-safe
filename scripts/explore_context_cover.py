#!/usr/bin/env python3
"""Development-only evaluation for context-cover-v2.

The runner refuses PyPI holdout rows and OMCBench test rows. It reads package
archives with MalIR's bounded non-executing reader and never installs/imports
sample code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import resource
import stat
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path, PurePath
from typing import Any

from malir.archive import ArchiveLimits, analyze_sources, load_python_archive
from malir.dedup import normalized_ast_hash, source_set_hash
from malir.detector import CascadeConfig, decide

EXPECTED_OMC_AUDIT_SHA256 = (
    "654738c01823a4e7dd6919563f7c056db1e85e29acdb5c2531bfcc3ca7b5263f"
)
EXPECTED_PYPI_DEVELOPMENT_GROUPS = 450
MAX_ARTIFACT_BYTES = 25 * 1024 * 1024
MAX_EVENTS = 2_000
SYSTEMS = {
    "context_max_v1": CascadeConfig(rule_aggregation="context-max-v1"),
    "context_cover_v2": CascadeConfig(rule_aggregation="context-cover-v2"),
    "context_causal_v6": CascadeConfig(rule_aggregation="context-causal-v6"),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("acquisition_dir")
    parser.add_argument("split_manifest")
    parser.add_argument("omcbench_root")
    parser.add_argument("omcbench_audit")
    parser.add_argument("output_dir")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--progress-every", type=int, default=25)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 1 <= args.workers <= 2:
        raise ValueError("workers must be 1 or 2")
    if args.progress_every < 1:
        raise ValueError("progress-every must be positive")
    acquisition = _regular_directory(Path(args.acquisition_dir))
    omcbench = _regular_directory(Path(args.omcbench_root))
    output = _empty_output(Path(args.output_dir))
    pypi_rows = _load_pypi_development(Path(args.split_manifest))
    omc_rows = _load_omc_validation(Path(args.omcbench_audit))
    started = time.perf_counter()
    cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    pypi_predictions = _parallel_score(
        "PyPI development",
        pypi_rows,
        args.workers,
        args.progress_every,
        _score_pypi,
        acquisition,
    )
    omc_predictions = _parallel_score(
        "OMCBench validation",
        omc_rows,
        args.workers,
        args.progress_every,
        _score_omc,
        omcbench,
    )
    pypi_predictions.sort(key=lambda row: (int(row["rank"]), row["sample_id"]))
    omc_predictions.sort(key=lambda row: row["sample_id"])
    _write_jsonl(output / "pypi-development-predictions.jsonl", pypi_predictions)
    _write_jsonl(output / "omc-validation-predictions.jsonl", omc_predictions)
    report = {
        "schema": "itcs.context-cover-development.v1",
        "scope": "development-only; no PyPI holdout or OMCBench test scored",
        "systems": _operating_points(pypi_predictions, omc_predictions),
        "support": {
            "pypi_artifacts": len(pypi_predictions),
            "pypi_groups": len({row["group_id"] for row in pypi_predictions}),
            "omc_validation_artifacts": len(omc_predictions),
            "omc_validation_malicious_groups": len(
                {row["group_id"] for row in omc_predictions if row["label"] == 1}
            ),
        },
        "timing": {
            "wall_seconds": time.perf_counter() - started,
            "parent_cpu_seconds": time.process_time() - cpu_started,
            "child_cpu_seconds": _child_cpu_seconds(children_started),
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
    }
    _write_json(output / "report.json", report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _load_pypi_development(path: Path) -> list[dict[str, Any]]:
    rows = _read_jsonl(path)
    selected = [row for row in rows if row.get("split") == "development"]
    if any(
        row.get("selected") is not True or row.get("status") != "ok" for row in selected
    ):
        raise ValueError("invalid PyPI development row")
    groups = {str(row["group_id"]) for row in selected}
    if len(groups) != EXPECTED_PYPI_DEVELOPMENT_GROUPS:
        raise ValueError("PyPI development support is not 450 groups")
    return selected


def _load_omc_validation(path: Path) -> list[dict[str, Any]]:
    if _file_sha256(path) != EXPECTED_OMC_AUDIT_SHA256:
        raise ValueError("OMCBench audit hash mismatch")
    rows = _read_jsonl(path)
    if len(rows) != 400:
        raise ValueError("OMCBench audit must contain 400 rows")
    selected = [row for row in rows if row.get("split") == "validation"]
    if len(selected) != 200:
        raise ValueError("OMCBench validation support must be 200 artifacts")
    if any(row.get("status") != "ok" for row in selected):
        raise ValueError("OMCBench validation contains an invalid row")
    return selected


def _parallel_score(
    label: str,
    rows: list[dict[str, Any]],
    workers: int,
    progress_every: int,
    scorer,
    root: Path,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scorer, row, root) for row in rows]
        for index, future in enumerate(as_completed(futures), 1):
            output.append(future.result())
            if index % progress_every == 0 or index == len(futures):
                print(
                    f"scored {label} {index}/{len(futures)}",
                    file=sys.stderr,
                    flush=True,
                )
    return output


def _score_pypi(row: dict[str, Any], acquisition: Path) -> dict[str, Any]:
    if row.get("split") != "development":
        raise ValueError("refusing to score a PyPI non-development row")
    storage_name = str(row.get("storage_name", ""))
    if not storage_name or PurePath(storage_name).name != storage_name:
        raise ValueError("unsafe PyPI storage name")
    contents = load_python_archive(
        acquisition / "artifacts" / storage_name,
        ArchiveLimits(max_archive_bytes=MAX_ARTIFACT_BYTES),
    )
    if contents.archive_sha256 != row["archive_sha256"]:
        raise ValueError("PyPI archive hash mismatch")
    if contents.archive_bytes != row["archive_bytes"]:
        raise ValueError("PyPI archive size mismatch")
    _verify_source_fingerprints(contents.sources, row)
    analyses = analyze_sources(
        contents.sources, enable_dataflow=True, max_events=MAX_EVENTS
    )
    scores = _scores(analyses)
    return {
        "sample_id": row["sample_id"],
        "group_id": row["group_id"],
        "split": "development",
        "label": 0,
        "rank": row["rank"],
        "project": row["project"],
        "version": row["version"],
        "python_files": row["python_files"],
        "python_bytes": row["python_bytes"],
        **scores,
    }


def _score_omc(row: dict[str, Any], root: Path) -> dict[str, Any]:
    if row.get("split") != "validation":
        raise ValueError("refusing to score an OMCBench non-validation row")
    archive_name = str(row.get("archive_name", ""))
    if not archive_name or PurePath(archive_name).name != archive_name:
        raise ValueError("unsafe OMCBench archive name")
    contents = load_python_archive(root / "packages" / archive_name, ArchiveLimits())
    if contents.archive_sha256 != row["archive_sha256"]:
        raise ValueError("OMCBench archive hash mismatch")
    _verify_source_fingerprints(contents.sources, row)
    analyses = analyze_sources(
        contents.sources, enable_dataflow=True, max_events=MAX_EVENTS
    )
    return {
        "sample_id": row["sample_id"],
        "group_id": row["group_id"],
        "split": "validation",
        "label": int(row["label"]),
        **_scores(analyses),
    }


def _verify_source_fingerprints(sources, row: dict[str, Any]) -> None:
    if source_set_hash(sources) != row["source_set_hash"]:
        raise ValueError("source-set hash mismatch")
    if normalized_ast_hash(sources) != row["normalized_ast_hash"]:
        raise ValueError("normalized-AST hash mismatch")


def _scores(analyses) -> dict[str, float]:
    return {
        name: decide(analyses, config=config).rule_score
        for name, config in SYSTEMS.items()
    }


def _operating_points(
    pypi_rows: list[dict[str, Any]],
    omc_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    output = {}
    for system in SYSTEMS:
        benign_rows = pypi_rows + [row for row in omc_rows if row["label"] == 0]
        benign_groups = _group_maxima(benign_rows, system)
        threshold = math.nextafter(max(benign_groups.values()), math.inf)
        malicious_groups = _group_maxima(
            [row for row in omc_rows if row["label"] == 1], system
        )
        alerts = sum(score >= threshold for score in malicious_groups.values())
        pypi_max = max(float(row[system]) for row in pypi_rows)
        omc_benign_max = max(
            float(row[system]) for row in omc_rows if row["label"] == 0
        )
        hard_negatives = sorted(
            pypi_rows,
            key=lambda row: (-float(row[system]), int(row["rank"])),
        )[:10]
        output[system] = {
            "threshold": threshold,
            "maximum_development_benign_score": max(benign_groups.values()),
            "maximum_pypi_development_score": pypi_max,
            "maximum_omc_validation_benign_score": omc_benign_max,
            "omc_malicious_group_recall": alerts / len(malicious_groups),
            "omc_malicious_alert_groups": alerts,
            "omc_malicious_groups": len(malicious_groups),
            "threshold_valid": threshold <= 100.0,
            "top_pypi_hard_negatives": [
                {
                    "project": row["project"],
                    "version": row["version"],
                    "score": row[system],
                    "python_files": row["python_files"],
                }
                for row in hard_negatives
            ],
        }
    return output


def _child_cpu_seconds(started) -> float:
    ended = resource.getrusage(resource.RUSAGE_CHILDREN)
    return ended.ru_utime + ended.ru_stime - started.ru_utime - started.ru_stime


def _group_maxima(rows: list[dict[str, Any]], field: str) -> dict[str, float]:
    output: dict[str, float] = {}
    for row in rows:
        group_id = str(row["group_id"])
        score = float(row[field])
        output[group_id] = max(output.get(group_id, -math.inf), score)
    if not output:
        raise ValueError("cannot score an empty group set")
    return output


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("JSONL input must be a regular non-symlinked file")
    if info.st_size > 50 * 1024 * 1024:
        raise ValueError("JSONL input exceeds 50 MiB")
    rows = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSONL at line {line_number}") from error
        if not isinstance(row, dict):
            raise TypeError("JSONL rows must be objects")
        rows.append(row)
    return rows


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    payload = "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows
    )
    path.write_text(payload, encoding="utf-8")


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
        if not path.is_dir() or any(path.iterdir()):
            raise ValueError("output directory must be empty")
    else:
        path.mkdir(parents=True)
    return path


if __name__ == "__main__":
    raise SystemExit(main())
