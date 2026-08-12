#!/usr/bin/env python3
"""Run the locked PyPI development and one-shot holdout study."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import resource
import stat
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path, PurePath
from typing import Any

from malir.archive import ArchiveLimits, analyze_sources, load_python_archive
from malir.dedup import normalized_ast_hash, source_set_hash
from malir.detector import CascadeConfig, decide
from scripts.acquire_pypi_reference import (
    MAX_ARTIFACT_BYTES,
    _file_sha256,
    _read_jsonl,
    _verify_plan,
    _write_json,
    _write_jsonl,
)
from scripts.prepare_pypi_reference import _representation_hash

STUDY_ID = "itcs-pypi-hard-negative-2026-08-12-v2"
EXPECTED_OMC_AUDIT_SHA256 = (
    "654738c01823a4e7dd6919563f7c056db1e85e29acdb5c2531bfcc3ca7b5263f"
)
TARGET_FPR = 0.01
CONFIDENCE = 0.975
MIN_MALICIOUS_RECALL = 0.20
EXPECTED_GROUPS_PER_SPLIT = 450
MAX_EVENTS = 2_000
BASELINE = CascadeConfig(rule_aggregation="legacy-top8")
CANDIDATE = CascadeConfig(rule_aggregation="context-max-v1")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    development = commands.add_parser("development")
    development.add_argument("acquisition_dir")
    development.add_argument("preparation_dir")
    development.add_argument("omcbench_root")
    development.add_argument("omcbench_audit")
    development.add_argument("output_dir")
    _worker_arguments(development)
    holdout = commands.add_parser("holdout")
    holdout.add_argument("acquisition_dir")
    holdout.add_argument("preparation_dir")
    holdout.add_argument("development_dir")
    holdout.add_argument("output_dir")
    _worker_arguments(holdout)
    return parser


def _worker_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository-commit", required=True)
    parser.add_argument("--container-image", required=True)
    parser.add_argument("--progress-every", type=int, default=25)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.repository_commit):
        raise ValueError("repository-commit must be a full lowercase SHA")
    if args.progress_every < 1:
        raise ValueError("progress-every must be positive")
    if args.command == "development":
        summary = run_development(args)
    else:
        summary = run_holdout(args)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def run_development(args: argparse.Namespace) -> dict[str, Any]:
    started_at = datetime.now(UTC)
    wall_started = time.perf_counter()
    cpu_started = time.process_time()
    acquisition = _regular_directory(Path(args.acquisition_dir))
    preparation = _regular_directory(Path(args.preparation_dir))
    omcbench = _regular_directory(Path(args.omcbench_root))
    output = _empty_output(Path(args.output_dir))
    plan = _verify_plan(acquisition)
    split_rows, prep_record, prep_hashes = _verify_preparation(
        acquisition, preparation, plan
    )
    omc_audit_rows = _load_omc_audit(Path(args.omcbench_audit))
    omc_rows = [row for row in omc_audit_rows if row["split"] == "validation"]
    cross_corpus = _cross_corpus_audit(omc_audit_rows, split_rows)

    pypi_rows = _score_pypi_partition(
        acquisition,
        split_rows,
        "development",
        args.progress_every,
    )
    omc_predictions = _score_omc_validation(
        omcbench,
        omc_rows,
        args.progress_every,
    )
    pypi_path = output / "pypi-development-predictions.jsonl"
    omc_path = output / "omc-validation-predictions.jsonl"
    _write_jsonl(pypi_path, pypi_rows)
    _write_jsonl(omc_path, omc_predictions)
    operating_points = _development_operating_points(pypi_rows, omc_predictions)
    holdout_authorized = bool(operating_points["candidate"]["eligible"])
    report = {
        "schema": "itcs.pypi-development-report.v1",
        "study_id": STUDY_ID,
        "created_at": started_at.isoformat(),
        "reference_benign": {
            "pypi_artifacts": len(pypi_rows),
            "pypi_groups": len({row["group_id"] for row in pypi_rows}),
            "omcbench_artifacts": sum(row["label"] == 0 for row in omc_predictions),
            "omcbench_groups": len(
                {row["group_id"] for row in omc_predictions if row["label"] == 0}
            ),
        },
        "omcbench_validation_malicious": {
            "artifacts": sum(row["label"] == 1 for row in omc_predictions),
            "groups": len(
                {row["group_id"] for row in omc_predictions if row["label"] == 1}
            ),
        },
        "operating_points": operating_points,
        "holdout_authorized": holdout_authorized,
        "cross_corpus_audit": cross_corpus,
        "omcbench_test_artifacts_scored": 0,
        "timing": {
            "wall_seconds": time.perf_counter() - wall_started,
            "cpu_seconds": time.process_time() - cpu_started,
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
    }
    report_path = output / "development-report.json"
    _write_json(report_path, report)
    development_hashes = {
        path.name: _file_sha256(path) for path in (pypi_path, omc_path, report_path)
    }
    code_hashes = _code_hashes()
    configuration = _configuration()
    configuration_fingerprint = _canonical_hash(
        {"configuration": configuration, "code_sha256": code_hashes}
    )
    lock = {
        "schema": "itcs.pypi-study-lock.v1",
        "study_id": STUDY_ID,
        "created_at": datetime.now(UTC).isoformat(),
        "repository_commit": args.repository_commit,
        "container_image": args.container_image,
        "configuration": configuration,
        "configuration_fingerprint": configuration_fingerprint,
        "code_sha256": code_hashes,
        "input_sha256": {
            "acquisition_plan": plan["plan_sha256"],
            "preparation_checksums": _file_sha256(preparation / "checksums.json"),
            "split_manifest": prep_hashes["split-manifest.jsonl"],
            "omcbench_audit": EXPECTED_OMC_AUDIT_SHA256,
        },
        "development_output_sha256": development_hashes,
        "operating_points": operating_points,
        "holdout_authorized": holdout_authorized,
        "protocol_deviations": [],
        "preparation_schema": prep_record["schema"],
    }
    lock_path = output / "study-lock.json"
    _write_json(lock_path, lock)
    checksums = {**development_hashes, lock_path.name: _file_sha256(lock_path)}
    _write_json(
        output / "checksums.json",
        {"schema": "itcs.checksums.v1", "sha256": checksums},
    )
    return {
        "schema": "itcs.pypi-development-summary.v1",
        "holdout_authorized": holdout_authorized,
        "candidate": operating_points["candidate"],
        "study_lock_sha256": checksums["study-lock.json"],
    }


def run_holdout(args: argparse.Namespace) -> dict[str, Any]:
    started_at = datetime.now(UTC)
    wall_started = time.perf_counter()
    cpu_started = time.process_time()
    acquisition = _regular_directory(Path(args.acquisition_dir))
    preparation = _regular_directory(Path(args.preparation_dir))
    development = _regular_directory(Path(args.development_dir))
    output = _empty_output(Path(args.output_dir))
    plan = _verify_plan(acquisition)
    split_rows, _, prep_hashes = _verify_preparation(acquisition, preparation, plan)
    lock = _verify_lock(
        development,
        preparation,
        plan,
        prep_hashes,
        repository_commit=args.repository_commit,
        container_image=args.container_image,
    )
    predictions = _score_pypi_partition(
        acquisition,
        split_rows,
        "holdout",
        args.progress_every,
    )
    prediction_path = output / "holdout-predictions.jsonl"
    _write_jsonl(prediction_path, predictions)
    report = _holdout_report(predictions, lock)
    report["created_at"] = started_at.isoformat()
    report["timing"] = _timing_report(
        predictions,
        wall_seconds=time.perf_counter() - wall_started,
        cpu_seconds=time.process_time() - cpu_started,
    )
    report_path = output / "holdout-report.json"
    _write_json(report_path, report)
    study = {
        "schema": "itcs.pypi-hard-negative-study.v1",
        "study_id": STUDY_ID,
        "repository_commit": args.repository_commit,
        "container_image": args.container_image,
        "configuration_fingerprint": lock["configuration_fingerprint"],
        "input_sha256": lock["input_sha256"],
        "study_lock_sha256": _file_sha256(development / "study-lock.json"),
        "prediction_sha256": _file_sha256(prediction_path),
        "report_sha256": _file_sha256(report_path),
        "network": "disabled-by-container-command",
        "raw_source_published": False,
        "claim": report["primary_gate"],
    }
    study_path = output / "study.json"
    _write_json(study_path, study)
    checksums = {
        path.name: _file_sha256(path)
        for path in (prediction_path, report_path, study_path)
    }
    _write_json(
        output / "checksums.json",
        {"schema": "itcs.checksums.v1", "sha256": checksums},
    )
    return {
        "schema": "itcs.pypi-holdout-summary.v1",
        "primary_gate": report["primary_gate"],
        "candidate": report["systems"]["candidate"],
        "holdout_prediction_sha256": checksums[prediction_path.name],
    }


def _verify_preparation(
    acquisition: Path,
    directory: Path,
    plan: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, str]]:
    checksums = _read_json(directory / "checksums.json")
    hashes = checksums.get("sha256")
    expected = {
        "artifact-audit.jsonl",
        "group-manifest.jsonl",
        "split-manifest.jsonl",
        "preparation.json",
    }
    if not isinstance(hashes, dict) or set(hashes) != expected:
        raise ValueError("preparation checksum manifest is incomplete")
    for name, expected_hash in hashes.items():
        if (
            not isinstance(expected_hash, str)
            or _file_sha256(directory / name) != expected_hash
        ):
            raise ValueError(f"preparation output hash mismatch: {name}")
    preparation = _read_json(directory / "preparation.json")
    if preparation.get("study_id") != STUDY_ID:
        raise ValueError("preparation study ID mismatch")
    if preparation.get("detector_scores_computed") is not False:
        raise ValueError("preparation must be detector-score blind")
    if preparation.get("input", {}).get("plan_sha256") != plan["plan_sha256"]:
        raise ValueError("preparation/acquisition plan mismatch")
    if preparation.get("output_sha256") != {
        name: digest for name, digest in hashes.items() if name != "preparation.json"
    }:
        raise ValueError("preparation record/output checksum mismatch")
    rows = _read_jsonl(directory / "split-manifest.jsonl")
    _validate_split_manifest(rows)
    _link_split_to_acquisition(rows, acquisition)
    return rows, preparation, hashes


def _validate_split_manifest(rows: list[dict[str, Any]]) -> None:
    groups: dict[str, set[str]] = {}
    sample_ids = []
    for row in rows:
        split = row.get("split")
        group_id = row.get("group_id")
        sample_id = row.get("sample_id")
        if (
            split not in {"development", "holdout"}
            or not isinstance(group_id, str)
            or not isinstance(sample_id, str)
            or row.get("selected") is not True
            or row.get("status") != "ok"
        ):
            raise ValueError("invalid selected split row")
        sample_ids.append(sample_id)
        groups.setdefault(group_id, set()).add(split)
    if len(sample_ids) != len(set(sample_ids)):
        raise ValueError("duplicate sample ID in selected split")
    if any(len(splits) != 1 for splits in groups.values()):
        raise ValueError("group crosses preparation splits")
    counts = Counter(next(iter(splits)) for splits in groups.values())
    if counts != {
        "development": EXPECTED_GROUPS_PER_SPLIT,
        "holdout": EXPECTED_GROUPS_PER_SPLIT,
    }:
        raise ValueError("preparation split group counts are not 450/450")
    for field in (
        "archive_sha256",
        "source_set_hash",
        "normalized_ast_hash",
        "representation_hash",
        "normalized_project",
    ):
        partitions: dict[str, set[str]] = {}
        for row in rows:
            partitions.setdefault(str(row[field]), set()).add(str(row["split"]))
        if any(len(splits) != 1 for splits in partitions.values()):
            raise ValueError(f"preparation split leakage detected for {field}")


def _link_split_to_acquisition(rows: list[dict[str, Any]], acquisition: Path) -> None:
    plan_rows = _read_jsonl(acquisition / "artifacts.jsonl")
    by_storage = {str(row["storage_name"]): row for row in plan_rows}
    if len(by_storage) != len(plan_rows):
        raise ValueError("acquisition plan contains duplicate storage names")
    for row in rows:
        storage_name = str(row["storage_name"])
        plan_row = by_storage.get(storage_name)
        if plan_row is None:
            raise ValueError("selected artifact is absent from acquisition plan")
        expected = {
            "rank": plan_row["rank"],
            "project": plan_row["project"],
            "normalized_project": plan_row["normalized_project"],
            "version": plan_row["version"],
            "archive_sha256": plan_row["sha256"],
            "archive_bytes": plan_row["size"],
            "storage_name": plan_row["storage_name"],
            "packagetype": plan_row["packagetype"],
            "upload_time": plan_row["upload_time"],
        }
        if any(row.get(name) != value for name, value in expected.items()):
            raise ValueError("selected artifact metadata differs from acquisition plan")
        if row["sample_id"] != f"pypi:{plan_row['sha256'][:32]}":
            raise ValueError("selected artifact sample ID differs from its hash")


def _load_omc_audit(path: Path) -> list[dict[str, Any]]:
    if _file_sha256(path) != EXPECTED_OMC_AUDIT_SHA256:
        raise ValueError("OMCBench audit hash mismatch")
    rows = _read_jsonl(path)
    if len(rows) != 400:
        raise ValueError("OMCBench audit must contain 400 artifacts")
    support = Counter((row.get("split"), row.get("label")) for row in rows)
    if support != {
        ("validation", 0): 100,
        ("validation", 1): 100,
        ("test", 0): 100,
        ("test", 1): 100,
    }:
        raise ValueError("unexpected OMCBench split support")
    for row in rows:
        if row["split"] == "validation":
            _require_omc_validation(row)
    return rows


def _require_omc_validation(row: dict[str, Any]) -> None:
    if row.get("split") != "validation":
        raise ValueError("OMCBench test row reached the scoring boundary")
    if row.get("status") != "ok":
        raise ValueError("OMCBench validation row was not successfully prepared")


def _cross_corpus_audit(
    omc_rows: list[dict[str, Any]],
    pypi_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    results = {}
    for field in ("archive_sha256", "source_set_hash", "normalized_ast_hash"):
        omc_values = {str(row[field]) for row in omc_rows}
        development_values = {
            str(row[field]) for row in pypi_rows if row["split"] == "development"
        }
        holdout_values = {
            str(row[field]) for row in pypi_rows if row["split"] == "holdout"
        }
        holdout_overlap = omc_values & holdout_values
        if holdout_overlap:
            raise ValueError(f"OMCBench validation overlaps PyPI holdout: {field}")
        results[field] = {
            "development_overlaps": len(omc_values & development_values),
            "holdout_overlaps": 0,
        }
    return results


def _score_pypi_partition(
    acquisition: Path,
    split_rows: list[dict[str, Any]],
    partition: str,
    progress_every: int,
) -> list[dict[str, Any]]:
    selected = sorted(
        (row for row in split_rows if row["split"] == partition),
        key=lambda row: (int(row["rank"]), str(row["sample_id"])),
    )
    if len({row["group_id"] for row in selected}) != EXPECTED_GROUPS_PER_SPLIT:
        raise ValueError("partition does not contain 450 groups")
    limits = ArchiveLimits(max_archive_bytes=MAX_ARTIFACT_BYTES)
    output = []
    for index, row in enumerate(selected, 1):
        output.append(_score_pypi_artifact(acquisition, row, limits))
        if index % progress_every == 0 or index == len(selected):
            print(
                f"scored PyPI {partition} {index}/{len(selected)} artifacts",
                file=sys.stderr,
                flush=True,
            )
    return output


def _score_pypi_artifact(
    acquisition: Path,
    row: dict[str, Any],
    limits: ArchiveLimits,
) -> dict[str, Any]:
    storage_name = row.get("storage_name")
    if not isinstance(storage_name, str) or PurePath(storage_name).name != storage_name:
        raise ValueError("unsafe PyPI storage name")
    archive_path = acquisition / "artifacts" / storage_name
    started = time.perf_counter()
    contents = load_python_archive(archive_path, limits)
    load_ms = (time.perf_counter() - started) * 1_000
    if (contents.archive_sha256, contents.archive_bytes) != (
        row["archive_sha256"],
        row["archive_bytes"],
    ):
        raise ValueError("PyPI artifact changed after preparation")
    fingerprint_started = time.perf_counter()
    if source_set_hash(contents.sources) != row["source_set_hash"]:
        raise ValueError("PyPI source-set hash changed after preparation")
    if normalized_ast_hash(contents.sources) != row["normalized_ast_hash"]:
        raise ValueError("PyPI normalized-AST hash changed after preparation")
    fingerprint_ms = (time.perf_counter() - fingerprint_started) * 1_000
    analysis_started = time.perf_counter()
    analyses = analyze_sources(
        contents.sources, enable_dataflow=True, max_events=MAX_EVENTS
    )
    analysis_ms = (time.perf_counter() - analysis_started) * 1_000
    if _representation_hash(analyses) != row["representation_hash"]:
        raise ValueError("PyPI representation hash changed after preparation")
    baseline, baseline_us = _timed_decision(analyses, BASELINE)
    candidate, candidate_us = _timed_decision(analyses, CANDIDATE)
    return {
        "sample_id": row["sample_id"],
        "group_id": row["group_id"],
        "split": row["split"],
        "label": 0,
        "rank": row["rank"],
        "project": row["project"],
        "version": row["version"],
        "archive_sha256": row["archive_sha256"],
        "archive_bytes": row["archive_bytes"],
        "python_files": row["python_files"],
        "python_bytes": row["python_bytes"],
        "baseline_score": baseline.rule_score,
        "candidate_score": candidate.rule_score,
        "load_ms": round(load_ms, 6),
        "fingerprint_ms": round(fingerprint_ms, 6),
        "analysis_ms": round(analysis_ms, 6),
        "baseline_decision_us": round(baseline_us, 6),
        "candidate_decision_us": round(candidate_us, 6),
    }


def _score_omc_validation(
    root: Path,
    rows: list[dict[str, Any]],
    progress_every: int,
) -> list[dict[str, Any]]:
    limits = ArchiveLimits()
    ordered = sorted(rows, key=lambda row: str(row["sample_id"]))
    output = []
    for index, row in enumerate(ordered, 1):
        _require_omc_validation(row)
        name = row.get("archive_name")
        if not isinstance(name, str) or PurePath(name).name != name:
            raise ValueError("unsafe OMCBench archive name")
        contents = load_python_archive(root / "packages" / name, limits)
        if contents.archive_sha256 != row["archive_sha256"]:
            raise ValueError("OMCBench archive changed after published pilot")
        if source_set_hash(contents.sources) != row["source_set_hash"]:
            raise ValueError("OMCBench source-set changed after published pilot")
        if normalized_ast_hash(contents.sources) != row["normalized_ast_hash"]:
            raise ValueError("OMCBench AST changed after published pilot")
        started = time.perf_counter()
        analyses = analyze_sources(
            contents.sources, enable_dataflow=True, max_events=MAX_EVENTS
        )
        analysis_ms = (time.perf_counter() - started) * 1_000
        baseline, baseline_us = _timed_decision(analyses, BASELINE)
        candidate, candidate_us = _timed_decision(analyses, CANDIDATE)
        output.append(
            {
                "sample_id": row["sample_id"],
                "group_id": row["group_id"],
                "split": "validation",
                "label": row["label"],
                "archive_sha256": row["archive_sha256"],
                "baseline_score": baseline.rule_score,
                "candidate_score": candidate.rule_score,
                "analysis_ms": round(analysis_ms, 6),
                "baseline_decision_us": round(baseline_us, 6),
                "candidate_decision_us": round(candidate_us, 6),
            }
        )
        if index % progress_every == 0 or index == len(ordered):
            print(
                f"scored OMCBench validation {index}/{len(ordered)} artifacts",
                file=sys.stderr,
                flush=True,
            )
    return output


def _timed_decision(analyses, config: CascadeConfig):
    started = time.perf_counter_ns()
    decision = decide(analyses, config=config)
    elapsed_us = (time.perf_counter_ns() - started) / 1_000
    return decision, elapsed_us


def _development_operating_points(
    pypi_rows: list[dict[str, Any]],
    omc_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    output = {}
    for system in ("baseline", "candidate"):
        field = f"{system}_score"
        benign_rows = pypi_rows + [row for row in omc_rows if row["label"] == 0]
        benign_groups = _group_maxima(benign_rows, field)
        threshold = math.nextafter(max(benign_groups.values()), math.inf)
        malicious_groups = _group_maxima(
            [row for row in omc_rows if row["label"] == 1], field
        )
        alerts = sum(score >= threshold for score in malicious_groups.values())
        recall = alerts / len(malicious_groups)
        threshold_valid = threshold <= 100.0
        eligible = threshold_valid and (
            system != "candidate" or recall >= MIN_MALICIOUS_RECALL
        )
        output[system] = {
            "threshold": threshold,
            "threshold_policy": "nextafter(max-development-benign-score,+inf)",
            "maximum_benign_score": max(benign_groups.values()),
            "benign_groups": len(benign_groups),
            "benign_alert_groups": sum(
                score >= threshold for score in benign_groups.values()
            ),
            "omcbench_malicious_alert_groups": alerts,
            "omcbench_malicious_groups": len(malicious_groups),
            "omcbench_malicious_recall": recall,
            "threshold_valid": threshold_valid,
            "minimum_candidate_recall": (
                MIN_MALICIOUS_RECALL if system == "candidate" else None
            ),
            "eligible": eligible,
        }
    return output


def _group_maxima(rows: list[dict[str, Any]], score_field: str) -> dict[str, float]:
    output: dict[str, float] = {}
    for row in rows:
        group_id = str(row["group_id"])
        score = float(row[score_field])
        output[group_id] = max(output.get(group_id, -math.inf), score)
    if not output:
        raise ValueError("cannot calculate a group operating point without rows")
    return output


def _verify_lock(
    development: Path,
    preparation: Path,
    plan: dict[str, Any],
    prep_hashes: dict[str, str],
    *,
    repository_commit: str,
    container_image: str,
) -> dict[str, Any]:
    checksums = _read_json(development / "checksums.json").get("sha256")
    expected = {
        "pypi-development-predictions.jsonl",
        "omc-validation-predictions.jsonl",
        "development-report.json",
        "study-lock.json",
    }
    if not isinstance(checksums, dict) or set(checksums) != expected:
        raise ValueError("development checksums are incomplete")
    for name, expected_hash in checksums.items():
        if _file_sha256(development / name) != expected_hash:
            raise ValueError(f"development output hash mismatch: {name}")
    lock = _read_json(development / "study-lock.json")
    if lock.get("study_id") != STUDY_ID or lock.get("schema") != (
        "itcs.pypi-study-lock.v1"
    ):
        raise ValueError("study lock identity mismatch")
    if lock.get("holdout_authorized") is not True:
        raise ValueError("development eligibility gate did not authorize holdout")
    if lock.get("repository_commit") != repository_commit:
        raise ValueError("repository commit differs from study lock")
    if lock.get("container_image") != container_image:
        raise ValueError("worker image differs from study lock")
    if lock.get("code_sha256") != _code_hashes():
        raise ValueError("scoring code differs from study lock")
    if lock.get("configuration") != _configuration():
        raise ValueError("scoring configuration differs from study lock")
    expected_fingerprint = _canonical_hash(
        {"configuration": _configuration(), "code_sha256": _code_hashes()}
    )
    if lock.get("configuration_fingerprint") != expected_fingerprint:
        raise ValueError("configuration fingerprint differs from study lock")
    development_hashes = {
        name: digest for name, digest in checksums.items() if name != "study-lock.json"
    }
    if lock.get("development_output_sha256") != development_hashes:
        raise ValueError("development outputs differ from study lock")
    report = _read_json(development / "development-report.json")
    if (
        report.get("operating_points") != lock.get("operating_points")
        or report.get("holdout_authorized") is not True
    ):
        raise ValueError("development report differs from study lock")
    input_hashes = lock.get("input_sha256", {})
    expected_inputs = {
        "acquisition_plan": plan["plan_sha256"],
        "preparation_checksums": _file_sha256(preparation / "checksums.json"),
        "split_manifest": prep_hashes["split-manifest.jsonl"],
        "omcbench_audit": EXPECTED_OMC_AUDIT_SHA256,
    }
    if input_hashes != expected_inputs:
        raise ValueError("study inputs differ from the development lock")
    return lock


def _holdout_report(rows: list[dict[str, Any]], lock: dict[str, Any]) -> dict[str, Any]:
    systems = {}
    alerts_by_system = {}
    operating = lock["operating_points"]
    for system in ("baseline", "candidate"):
        maxima = _group_maxima(rows, f"{system}_score")
        threshold = float(operating[system]["threshold"])
        alerts = {group_id for group_id, score in maxima.items() if score >= threshold}
        alerts_by_system[system] = alerts
        upper = _clopper_pearson_upper(len(alerts), len(maxima), confidence=CONFIDENCE)
        systems[system] = {
            "threshold": threshold,
            "alert_groups": len(alerts),
            "groups": len(maxima),
            "empirical_false_positive_rate": len(alerts) / len(maxima),
            "one_sided_confidence": CONFIDENCE,
            "fpr_upper_bound": upper,
            "maximum_score": max(maxima.values()),
        }
    candidate = systems["candidate"]
    passed = (
        candidate["groups"] >= EXPECTED_GROUPS_PER_SPLIT
        and candidate["alert_groups"] == 0
        and candidate["fpr_upper_bound"] < TARGET_FPR
    )
    return {
        "schema": "itcs.pypi-holdout-report.v1",
        "study_id": STUDY_ID,
        "population": "popular-PyPI reference-benign; not ground-truth benign",
        "artifacts": len(rows),
        "groups": len({row["group_id"] for row in rows}),
        "systems": systems,
        "paired_transitions": {
            "baseline_only_alert_groups": len(
                alerts_by_system["baseline"] - alerts_by_system["candidate"]
            ),
            "candidate_only_alert_groups": len(
                alerts_by_system["candidate"] - alerts_by_system["baseline"]
            ),
            "both_alert_groups": len(
                alerts_by_system["candidate"] & alerts_by_system["baseline"]
            ),
            "neither_alert_groups": EXPECTED_GROUPS_PER_SPLIT
            - len(alerts_by_system["candidate"] | alerts_by_system["baseline"]),
        },
        "primary_gate": {
            "target_fpr": TARGET_FPR,
            "confidence": CONFIDENCE,
            "requires_zero_alert_groups": True,
            "status": "pass" if passed else "fail",
            "reason": (
                "all preregistered reference-benign FPR conditions passed"
                if passed
                else "one or more preregistered reference-benign FPR conditions failed"
            ),
            "scope": "reference-benign FPR only; no fresh malware recall claim",
        },
    }


def _clopper_pearson_upper(successes: int, total: int, *, confidence: float) -> float:
    if not 0 <= successes <= total or total < 1:
        raise ValueError("invalid binomial counts")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    if successes == total:
        return 1.0
    alpha = 1.0 - confidence
    low, high = 0.0, 1.0
    for _ in range(100):
        midpoint = (low + high) / 2.0
        cdf = _binomial_cdf(successes, total, midpoint)
        if cdf > alpha:
            low = midpoint
        else:
            high = midpoint
    return high


def _binomial_cdf(successes: int, total: int, probability: float) -> float:
    if probability <= 0.0:
        return 1.0
    if probability >= 1.0:
        return 0.0 if successes < total else 1.0
    logs = [
        math.lgamma(total + 1)
        - math.lgamma(index + 1)
        - math.lgamma(total - index + 1)
        + index * math.log(probability)
        + (total - index) * math.log1p(-probability)
        for index in range(successes + 1)
    ]
    maximum = max(logs)
    return math.exp(maximum) * sum(math.exp(value - maximum) for value in logs)


def _timing_report(
    rows: list[dict[str, Any]],
    *,
    wall_seconds: float,
    cpu_seconds: float,
) -> dict[str, Any]:
    total_ms = [
        float(row["load_ms"]) + float(row["fingerprint_ms"]) + float(row["analysis_ms"])
        for row in rows
    ]
    return {
        "wall_seconds": wall_seconds,
        "cpu_seconds": cpu_seconds,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "artifacts_per_cpu_second": len(rows) / max(cpu_seconds, 1e-12),
        "common_pipeline_ms": {
            "median": _nearest_rank(total_ms, 0.50),
            "p95": _nearest_rank(total_ms, 0.95),
            "p99": _nearest_rank(total_ms, 0.99),
        },
        "decision_us": {
            system: {
                "median": _nearest_rank(
                    [float(row[f"{system}_decision_us"]) for row in rows], 0.50
                ),
                "p95": _nearest_rank(
                    [float(row[f"{system}_decision_us"]) for row in rows], 0.95
                ),
                "p99": _nearest_rank(
                    [float(row[f"{system}_decision_us"]) for row in rows], 0.99
                ),
            }
            for system in ("baseline", "candidate")
        },
        "source": {
            "archive_bytes": sum(int(row["archive_bytes"]) for row in rows),
            "python_bytes": sum(int(row["python_bytes"]) for row in rows),
            "python_files": sum(int(row["python_files"]) for row in rows),
        },
    }


def _nearest_rank(values: list[float], quantile: float) -> float:
    if not values or not 0.0 < quantile <= 1.0:
        raise ValueError("invalid nearest-rank input")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(quantile * len(ordered)) - 1)]


def _configuration() -> dict[str, Any]:
    return {
        "dataflow": True,
        "max_events_per_file": MAX_EVENTS,
        "baseline_rule_aggregation": BASELINE.rule_aggregation,
        "candidate_rule_aggregation": CANDIDATE.rule_aggregation,
        "model": None,
        "target_fpr": TARGET_FPR,
        "confidence": CONFIDENCE,
        "minimum_candidate_malicious_recall": MIN_MALICIOUS_RECALL,
        "groups_per_pypi_split": EXPECTED_GROUPS_PER_SPLIT,
        "archive_limits": {
            "max_archive_bytes": MAX_ARTIFACT_BYTES,
            "max_members": 20_000,
            "max_member_bytes": 1_000_000,
            "max_python_bytes": 50_000_000,
            "max_total_uncompressed_bytes": 500_000_000,
            "max_compression_ratio": 250.0,
            "max_path_bytes": 512,
        },
    }


def _code_hashes() -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    names = [
        "scripts/acquire_pypi_reference.py",
        "scripts/prepare_pypi_reference.py",
        "scripts/pypi_hard_negative_study.py",
        "scripts/resplit_pypi_reference.py",
        "src/malir/archive.py",
        "src/malir/dedup.py",
        "src/malir/detector.py",
        "src/malir/extractor.py",
        "src/malir/flow.py",
        "src/malir/motifs.py",
        "src/malir/policy.py",
        "src/malir/types.py",
    ]
    return {name: _file_sha256(root / name) for name in names}


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("JSON input is not a regular non-symlinked file")
    if info.st_size > 20 * 1024 * 1024:
        raise ValueError("JSON input exceeds 20 MiB")
    try:
        result = json.loads(path.read_bytes())
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON: {path.name}") from error
    if not isinstance(result, dict):
        raise TypeError(f"JSON root must be an object: {path.name}")
    return result


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
