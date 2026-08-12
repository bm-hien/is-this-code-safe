#!/usr/bin/env python3
"""Acquire hash-verified PyPI artifacts without installing or executing them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePath
from typing import Any

STUDY_ID = "itcs-pypi-hard-negative-2026-08-12-v1"
RANKING_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
RANKING_SHA256 = "bb36eb336787975315f66eb0834073e9b0a72593c486cd2d704991046f465b04"
RANKING_LAST_UPDATE = "2026-08-01 06:34:08"
RANKING_ROWS = 15_000
PYPI_URL = "https://pypi.org/pypi/{project}/json"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
USER_AGENT = "ITCS-research/0.6 (+https://github.com/bm-hien/is-this-code-safe)"
TARGET_ARTIFACTS = 1_050
CANDIDATE_BUFFER = 100
MAX_ARTIFACT_BYTES = 25 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 20 * 1024 * 1024


class ResponseLimitError(ValueError):
    """A remote response exceeded a frozen acquisition byte limit."""


@dataclass(frozen=True, slots=True)
class Artifact:
    rank: int
    project: str
    normalized_project: str
    version: str
    filename: str
    url: str
    sha256: str
    size: int
    packagetype: str
    upload_time: str | None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("plan", "download", "verify"):
        child = subparsers.add_parser(command)
        child.add_argument("output_dir")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output = _prepare_output(Path(args.output_dir))
    if args.command == "plan":
        summary = create_plan(output)
    elif args.command == "download":
        summary = download_plan(output)
    else:
        summary = verify_downloads(output)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def create_plan(output: Path) -> dict[str, Any]:
    plan_path = output / "artifacts.jsonl"
    collection_path = output / "collection.json"
    if plan_path.exists() or collection_path.exists():
        if not plan_path.is_file() or not collection_path.is_file():
            raise ValueError("finalized plan files must both be regular files")
        return _verify_plan(output)

    ranking_payload, ranking = _ranking_snapshot(output)
    rows = ranking["rows"]
    metadata_path = output / "metadata-journal.jsonl"
    metadata = _read_jsonl(metadata_path) if metadata_path.exists() else []
    _validate_metadata_journal(metadata)
    processed = {int(row["rank"]) for row in metadata}
    candidates = _journal_candidates(metadata)
    fetch_goal = TARGET_ARTIFACTS + CANDIDATE_BUFFER
    while True:
        for rank, ranking_row in enumerate(rows, 1):
            if len(candidates) >= fetch_goal:
                break
            if rank in processed:
                continue
            record = _inspect_project(rank, ranking_row)
            metadata.append(record)
            processed.add(rank)
            if record["status"] == "candidate":
                candidates.append(_artifact_from_dict(record["artifact"]))
            if len(metadata) % 25 == 0:
                _write_jsonl(metadata_path, metadata)
                print(
                    f"inspected {len(metadata)} ranked projects; "
                    f"{len(candidates)} candidates",
                    file=sys.stderr,
                    flush=True,
                )
            time.sleep(0.10)
        _write_jsonl(metadata_path, metadata)
        if len(candidates) < fetch_goal:
            raise ValueError("ranking exhausted before the candidate target")

        osv = _complete_osv_audit(output, candidates)
        clean = [
            item
            for item in sorted(candidates, key=lambda value: value.rank)
            if not osv[item.sha256]["known_malicious"]
        ]
        if len(clean) >= TARGET_ARTIFACTS:
            break
        fetch_goal = len(candidates) + CANDIDATE_BUFFER

    selected: list[Artifact] = []
    declared_bytes = 0
    for artifact in clean:
        if declared_bytes + artifact.size > MAX_TOTAL_BYTES:
            break
        selected.append(artifact)
        declared_bytes += artifact.size
        if len(selected) == TARGET_ARTIFACTS:
            break
    if len(selected) != TARGET_ARTIFACTS:
        raise ValueError("four-GiB cap reached before 1,050 artifacts")

    plan_rows = []
    storage_names: set[str] = set()
    for artifact in selected:
        row = asdict(artifact)
        row["storage_name"] = _storage_name(artifact)
        if row["storage_name"] in storage_names:
            raise ValueError("derived artifact storage-name collision")
        storage_names.add(row["storage_name"])
        plan_rows.append(row)
    _write_jsonl(plan_path, plan_rows)
    metadata_sha = _file_sha256(metadata_path)
    osv_path = output / "osv-audit.jsonl"
    collection = {
        "schema": "itcs.pypi-collection.v1",
        "study_id": STUDY_ID,
        "created_at": datetime.now(UTC).isoformat(),
        "ranking": {
            "url": RANKING_URL,
            "sha256": hashlib.sha256(ranking_payload).hexdigest(),
            "last_update": ranking["last_update"],
            "rows": len(rows),
        },
        "selection": {
            "artifacts": len(plan_rows),
            "declared_bytes": declared_bytes,
            "max_artifact_bytes": MAX_ARTIFACT_BYTES,
            "max_total_bytes": MAX_TOTAL_BYTES,
            "known_osv_malicious_excluded": sum(
                row["known_malicious"] for row in osv.values()
            ),
        },
        "sha256": {
            "metadata_journal": metadata_sha,
            "osv_audit": _file_sha256(osv_path),
            "artifacts": _file_sha256(plan_path),
        },
    }
    _write_json(collection_path, collection)
    return _verify_plan(output)


def _ranking_snapshot(output: Path) -> tuple[bytes, dict[str, Any]]:
    path = output / "ranking.json"
    if path.exists():
        payload = _read_regular(path, 2 * 1024 * 1024)
    else:
        payload = _request_bytes(RANKING_URL, 2 * 1024 * 1024)
        _atomic_write(path, payload)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != RANKING_SHA256:
        raise ValueError(f"ranking SHA-256 mismatch: {digest}")
    try:
        ranking = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValueError("ranking snapshot is not valid JSON") from error
    if not isinstance(ranking, dict):
        raise TypeError("ranking snapshot must be an object")
    if ranking.get("last_update") != RANKING_LAST_UPDATE:
        raise ValueError("unexpected ranking last_update")
    rows = ranking.get("rows")
    if not isinstance(rows, list) or len(rows) != RANKING_ROWS:
        raise ValueError("unexpected ranking row count")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("project"), str):
            raise TypeError("invalid ranking row")
        normalized = _normalize_project(row["project"])
        if not normalized or normalized in seen:
            raise ValueError("duplicate or invalid ranked project")
        seen.add(normalized)
    return payload, ranking


def _inspect_project(rank: int, ranking_row: dict[str, Any]) -> dict[str, Any]:
    project = ranking_row["project"]
    encoded = urllib.parse.quote(project, safe="")
    try:
        payload = _request_json(PYPI_URL.format(project=encoded))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return _exclusion(rank, project, "pypi-project-not-found")
        raise
    except ResponseLimitError:
        return _exclusion(rank, project, "pypi-metadata-response-too-large")
    artifact, reason = _select_artifact(payload, rank, project)
    if artifact is None:
        return _exclusion(rank, project, reason)
    return {
        "rank": rank,
        "ranking_project": project,
        "status": "candidate",
        "artifact": asdict(artifact),
    }


def _select_artifact(
    payload: Any, rank: int, ranking_project: str
) -> tuple[Artifact | None, str]:
    if not isinstance(payload, dict):
        return None, "pypi-response-not-object"
    info = payload.get("info")
    urls = payload.get("urls")
    if not isinstance(info, dict) or not isinstance(urls, list):
        return None, "pypi-response-missing-info-or-urls"
    project = info.get("name")
    version = info.get("version")
    if not isinstance(project, str) or not isinstance(version, str):
        return None, "pypi-response-invalid-name-or-version"
    if _normalize_project(project) != _normalize_project(ranking_project):
        return None, "pypi-project-name-mismatch"
    if not version or len(version) > 200:
        return None, "pypi-version-invalid"

    eligible: list[tuple[int, str, str, dict[str, Any]]] = []
    for item in urls:
        if not isinstance(item, dict) or item.get("yanked") is not False:
            continue
        filename = item.get("filename")
        packagetype = item.get("packagetype")
        size = item.get("size")
        url = item.get("url")
        digests = item.get("digests")
        sha256 = digests.get("sha256") if isinstance(digests, dict) else None
        if not _valid_file_metadata(filename, url, sha256, size):
            continue
        preference = _artifact_preference(str(filename), str(packagetype))
        if preference is None:
            continue
        eligible.append((preference, str(filename), str(sha256), item))
    if not eligible:
        return None, "no-supported-non-yanked-artifact"
    chosen = min(eligible, key=lambda value: value[:3])[3]
    return Artifact(
        rank=rank,
        project=project,
        normalized_project=_normalize_project(project),
        version=version,
        filename=chosen["filename"],
        url=chosen["url"],
        sha256=chosen["digests"]["sha256"],
        size=chosen["size"],
        packagetype=chosen["packagetype"],
        upload_time=chosen.get("upload_time_iso_8601"),
    ), ""


def _valid_file_metadata(filename: Any, url: Any, sha256: Any, size: Any) -> bool:
    if not all(isinstance(value, str) for value in (filename, url, sha256)):
        return False
    if PurePath(filename).name != filename or len(filename.encode()) > 512:
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in filename):
        return False
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        return False
    if not isinstance(size, int) or not 0 < size <= MAX_ARTIFACT_BYTES:
        return False
    parsed = urllib.parse.urlsplit(url)
    return (
        parsed.scheme == "https"
        and parsed.hostname == "files.pythonhosted.org"
        and parsed.username is None
        and parsed.password is None
        and parsed.port in (None, 443)
    )


def _artifact_preference(filename: str, packagetype: str) -> int | None:
    lower = filename.lower()
    if packagetype == "sdist" and lower.endswith(".tar.gz"):
        return 0
    if packagetype == "sdist" and lower.endswith(".zip"):
        return 1
    if packagetype == "bdist_wheel" and lower.endswith(
        ("-py3-none-any.whl", "-py2.py3-none-any.whl")
    ):
        return 2
    if packagetype == "bdist_wheel" and lower.endswith(".whl"):
        return 3
    return None


def _complete_osv_audit(
    output: Path, candidates: list[Artifact]
) -> dict[str, dict[str, Any]]:
    path = output / "osv-audit.jsonl"
    rows = _read_jsonl(path) if path.exists() else []
    audited = {str(row["sha256"]): row for row in rows}
    pending = [item for item in candidates if item.sha256 not in audited]
    for start in range(0, len(pending), 100):
        batch = pending[start : start + 100]
        body = {
            "queries": [
                {
                    "package": {"ecosystem": "PyPI", "name": item.project},
                    "version": item.version,
                }
                for item in batch
            ]
        }
        response = _request_json(OSV_BATCH_URL, body)
        results = response.get("results") if isinstance(response, dict) else None
        if not isinstance(results, list) or len(results) != len(batch):
            raise ValueError("OSV batch response is not aligned")
        for artifact, result in zip(batch, results, strict=True):
            identifiers = _osv_identifiers(result)
            row = {
                "sha256": artifact.sha256,
                "project": artifact.project,
                "version": artifact.version,
                "ids": sorted(identifiers),
                "known_malicious": any(
                    value.startswith("MAL-") for value in identifiers
                ),
            }
            rows.append(row)
            audited[artifact.sha256] = row
        _write_jsonl(path, rows)
        print(
            f"OSV-audited {len(audited)} candidate artifacts",
            file=sys.stderr,
            flush=True,
        )
        time.sleep(0.10)
    return audited


def _osv_identifiers(result: Any) -> set[str]:
    if result in ({}, None):
        return set()
    if not isinstance(result, dict):
        raise TypeError("OSV result is not an object")
    vulns = result.get("vulns", [])
    if not isinstance(vulns, list):
        raise TypeError("OSV vulns is not a list")
    output: set[str] = set()
    for vuln in vulns:
        if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
            raise TypeError("OSV vulnerability is malformed")
        output.add(vuln["id"])
        aliases = vuln.get("aliases", [])
        if aliases is not None:
            if not isinstance(aliases, list) or not all(
                isinstance(alias, str) for alias in aliases
            ):
                raise ValueError("OSV aliases are malformed")
            output.update(aliases)
    return output


def download_plan(output: Path) -> dict[str, Any]:
    plan_summary = _verify_plan(output)
    rows = _read_jsonl(output / "artifacts.jsonl")
    artifacts_dir = output / "artifacts"
    _ensure_directory(artifacts_dir)
    audit = []
    for index, row in enumerate(rows, 1):
        artifact = _artifact_from_dict(row)
        target = artifacts_dir / row["storage_name"]
        if target.exists():
            _verify_artifact_file(target, artifact)
        else:
            _download_artifact(target, artifact)
        audit.append(
            {
                "rank": artifact.rank,
                "project": artifact.project,
                "version": artifact.version,
                "storage_name": target.name,
                "sha256": artifact.sha256,
                "size": artifact.size,
            }
        )
        if index % 25 == 0 or index == len(rows):
            print(
                f"downloaded or verified {index}/{len(rows)} artifacts",
                file=sys.stderr,
                flush=True,
            )
    _write_jsonl(output / "download-audit.jsonl", audit)
    verified = verify_downloads(output)
    verified["plan"] = plan_summary
    return verified


def verify_downloads(output: Path) -> dict[str, Any]:
    plan = _verify_plan(output)
    rows = _read_jsonl(output / "artifacts.jsonl")
    artifacts_dir = output / "artifacts"
    if not artifacts_dir.is_dir() or artifacts_dir.is_symlink():
        raise ValueError("artifact directory is missing or unsafe")
    declared_names = {str(row["storage_name"]) for row in rows}
    actual_names = {path.name for path in artifacts_dir.iterdir()}
    if actual_names != declared_names:
        raise ValueError("artifact directory differs from the frozen plan")
    total_bytes = 0
    for row in rows:
        artifact = _artifact_from_dict(row)
        _verify_artifact_file(artifacts_dir / row["storage_name"], artifact)
        total_bytes += artifact.size
    return {
        "schema": "itcs.pypi-acquisition-summary.v1",
        "study_id": STUDY_ID,
        "artifacts": len(rows),
        "bytes": total_bytes,
        "plan_sha256": plan["plan_sha256"],
        "verified": True,
    }


def _verify_plan(output: Path) -> dict[str, Any]:
    collection = _read_json(output / "collection.json", MAX_JSON_BYTES)
    if collection.get("study_id") != STUDY_ID:
        raise ValueError("collection study ID mismatch")
    ranking = collection.get("ranking")
    hashes = collection.get("sha256")
    if not isinstance(ranking, dict) or not isinstance(hashes, dict):
        raise TypeError("collection provenance is malformed")
    if (ranking.get("url"), ranking.get("sha256")) != (
        RANKING_URL,
        RANKING_SHA256,
    ):
        raise ValueError("collection ranking provenance mismatch")
    provenance_files = {
        "metadata_journal": output / "metadata-journal.jsonl",
        "osv_audit": output / "osv-audit.jsonl",
        "artifacts": output / "artifacts.jsonl",
    }
    for name, path in provenance_files.items():
        if hashes.get(name) != _file_sha256(path):
            raise ValueError(f"collection provenance hash mismatch: {name}")
    if _file_sha256(output / "ranking.json") != RANKING_SHA256:
        raise ValueError("stored ranking snapshot hash mismatch")
    plan_path = provenance_files["artifacts"]
    plan_sha = _file_sha256(plan_path)
    rows = _read_jsonl(plan_path)
    if len(rows) != TARGET_ARTIFACTS:
        raise ValueError("artifact plan count mismatch")
    ranks = [int(row["rank"]) for row in rows]
    names = [str(row["storage_name"]) for row in rows]
    projects = [str(row["normalized_project"]) for row in rows]
    if ranks != sorted(ranks) or len(names) != len(set(names)):
        raise ValueError("artifact plan is unordered or has duplicate names")
    if len(projects) != len(set(projects)):
        raise ValueError("artifact plan has duplicate projects")
    total = 0
    for row in rows:
        artifact = _artifact_from_dict(row)
        if row["storage_name"] != _storage_name(artifact):
            raise ValueError("artifact storage name mismatch")
        if not _valid_file_metadata(
            artifact.filename, artifact.url, artifact.sha256, artifact.size
        ):
            raise ValueError("artifact plan contains invalid metadata")
        total += artifact.size
    if total > MAX_TOTAL_BYTES:
        raise ValueError("artifact plan exceeds total byte cap")
    return {
        "schema": "itcs.pypi-plan-summary.v1",
        "study_id": STUDY_ID,
        "artifacts": len(rows),
        "declared_bytes": total,
        "plan_sha256": plan_sha,
    }


def _download_artifact(target: Path, artifact: Artifact) -> None:
    part = target.with_suffix(target.suffix + ".part")
    if part.exists():
        info = part.lstat()
        if part.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise ValueError("unsafe partial-download path")
        part.unlink()
    request = urllib.request.Request(
        artifact.url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "files.pythonhosted.org":
                raise ValueError("artifact download redirected to an unsafe host")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) != artifact.size:
                raise ValueError("artifact HTTP size differs from PyPI metadata")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(part, flags, 0o600)
            digest = hashlib.sha256()
            received = 0
            with os.fdopen(descriptor, "wb") as handle:
                while True:
                    block = response.read(min(1 << 20, artifact.size + 1 - received))
                    if not block:
                        break
                    received += len(block)
                    if received > artifact.size:
                        raise ValueError("artifact download exceeded declared size")
                    digest.update(block)
                    handle.write(block)
                handle.flush()
                os.fsync(handle.fileno())
        if received != artifact.size or digest.hexdigest() != artifact.sha256:
            raise ValueError("artifact size or SHA-256 mismatch")
        os.replace(part, target)
    except BaseException:
        if part.exists() and part.is_file() and not part.is_symlink():
            part.unlink()
        raise


def _verify_artifact_file(path: Path, artifact: Artifact) -> None:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("artifact path is not a regular non-symlinked file")
    if info.st_size != artifact.size or _file_sha256(path) != artifact.sha256:
        raise ValueError("stored artifact size or SHA-256 mismatch")


def _request_json(url: str, body: Any | None = None) -> Any:
    data = None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    payload = _request_bytes(url, MAX_JSON_BYTES, data=data, headers=headers)
    try:
        return json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValueError("remote endpoint returned invalid JSON") from error


def _request_bytes(
    url: str,
    limit: int,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> bytes:
    origin = urllib.parse.urlsplit(url)
    allowed_hosts = {"hugovk.dev", "pypi.org", "api.osv.dev"}
    if origin.scheme != "https" or origin.hostname not in allowed_hosts:
        raise ValueError("remote metadata URL is outside the host allowlist")
    request = urllib.request.Request(
        url, data=data, headers=headers or {"User-Agent": USER_AGENT}
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                final = urllib.parse.urlsplit(response.geturl())
                if final.scheme != "https" or final.hostname != origin.hostname:
                    raise ValueError("remote metadata redirected outside its host")
                declared = response.headers.get("Content-Length")
                if declared is not None and int(declared) > limit:
                    raise ResponseLimitError("remote response exceeds byte limit")
                payload = response.read(limit + 1)
                if len(payload) > limit:
                    raise ResponseLimitError("remote response exceeds byte limit")
                return payload
        except urllib.error.HTTPError as error:
            if error.code == 404 or error.code < 500 and error.code != 429:
                raise
            if attempt == 2:
                raise
        except (OSError, TimeoutError):
            if attempt == 2:
                raise
        time.sleep(2**attempt)
    raise AssertionError("unreachable retry state")


def _prepare_output(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("output cannot be a symlink")
    path = Path(os.path.abspath(path))
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise ValueError("output must be a regular directory")
    else:
        path.mkdir(parents=True)
    allowed = {
        "ranking.json",
        "metadata-journal.jsonl",
        "osv-audit.jsonl",
        "artifacts.jsonl",
        "collection.json",
        "artifacts",
        "download-audit.jsonl",
    }
    unexpected = {item.name for item in path.iterdir()} - allowed
    if unexpected:
        raise ValueError(f"unexpected acquisition output entries: {sorted(unexpected)}")
    return path


def _ensure_directory(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise ValueError("unsafe artifact directory")
    else:
        path.mkdir(mode=0o700)


def _storage_name(artifact: Artifact) -> str:
    lower = artifact.filename.lower()
    suffix = next(
        value for value in (".tar.gz", ".whl", ".zip") if lower.endswith(value)
    )
    return f"{artifact.rank:05d}-{artifact.sha256[:20]}{suffix}"


def _normalize_project(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower().strip("-")


def _exclusion(rank: int, project: str, reason: str) -> dict[str, Any]:
    return {
        "rank": rank,
        "ranking_project": project,
        "status": "excluded",
        "reason": reason,
    }


def _artifact_from_dict(row: dict[str, Any]) -> Artifact:
    keys = Artifact.__dataclass_fields__
    try:
        return Artifact(**{name: row[name] for name in keys})
    except (KeyError, TypeError) as error:
        raise ValueError("invalid artifact record") from error


def _journal_candidates(rows: list[dict[str, Any]]) -> list[Artifact]:
    return [
        _artifact_from_dict(row["artifact"])
        for row in rows
        if row.get("status") == "candidate"
    ]


def _validate_metadata_journal(rows: list[dict[str, Any]]) -> None:
    ranks = []
    for row in rows:
        if row.get("status") not in {"candidate", "excluded"}:
            raise ValueError("invalid metadata journal status")
        ranks.append(int(row["rank"]))
        if row["status"] == "candidate":
            _artifact_from_dict(row["artifact"])
    if len(ranks) != len(set(ranks)) or any(rank < 1 for rank in ranks):
        raise ValueError("invalid metadata journal ranks")


def _read_regular(path: Path, limit: int) -> bytes:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("input is not a regular non-symlinked file")
    if info.st_size > limit:
        raise ValueError("input exceeds byte limit")
    return path.read_bytes()


def _read_json(path: Path, limit: int) -> dict[str, Any]:
    try:
        result = json.loads(_read_regular(path, limit))
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON: {path.name}") from error
    if not isinstance(result, dict):
        raise TypeError(f"JSON root must be an object: {path.name}")
    return result


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    payload = _read_regular(path, 20 * 1024 * 1024)
    rows = []
    for line_number, line in enumerate(payload.splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"invalid JSONL line {line_number}: {path.name}"
            ) from error
        if not isinstance(row, dict):
            raise TypeError(f"JSONL row is not an object: {path.name}")
        rows.append(row)
    return rows


def _atomic_write(path: Path, payload: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        info = temporary.lstat()
        if temporary.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise ValueError("unsafe temporary output")
        temporary.unlink()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        if temporary.exists() and temporary.is_file() and not temporary.is_symlink():
            temporary.unlink()
        raise


def _write_json(path: Path, value: Any) -> None:
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()
    _atomic_write(path, payload)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    payload = b"".join(
        (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
        for row in rows
    )
    _atomic_write(path, payload)


def _file_sha256(path: Path) -> str:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("hash input is not a regular non-symlinked file")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
