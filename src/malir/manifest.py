"""Metadata-only dataset manifest validation and leakage auditing."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
from typing import Any

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SPLITS = {"train", "validation", "test"}
_MANIFEST_FIELDS = {
    "campaign",
    "content_kind",
    "ecosystem",
    "family",
    "first_seen",
    "group_id",
    "label",
    "license",
    "package",
    "provenance",
    "representation_hash",
    "sample_id",
    "sha256",
    "split",
    "version",
}
_PAYLOAD_FIELDS = {
    "archive",
    "archive_path",
    "bytes",
    "content",
    "path",
    "payload",
    "source",
    "tokens",
}
_POSITIVE = {1, "1", "malicious", "suspicious", "positive"}
_NEGATIVE = {0, "0", "benign", "clean", "negative"}


@dataclass(frozen=True)
class ManifestRow:
    """One artifact identity; never a path to executable sample content."""

    sample_id: str
    label: int
    ecosystem: str
    package: str
    version: str
    sha256: str
    first_seen: date
    group_id: str
    provenance: str
    license: str
    content_kind: str
    split: str | None = None
    representation_hash: str | None = None
    family: str | None = None
    campaign: str | None = None

    def canonical(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["first_seen"] = self.first_seen.isoformat()
        return payload


@dataclass(frozen=True)
class AuditIssue:
    severity: str
    code: str
    message: str
    sample_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "sample_ids": list(self.sample_ids),
        }


def hash_representation(tokens: Iterable[str]) -> str:
    """Hash an ordered token stream without delimiter ambiguity."""

    digest = hashlib.sha256()
    for token in tokens:
        if not isinstance(token, str):
            raise TypeError("representation tokens must be text")
        encoded = token.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def load_manifest(
    path: str | Path,
    *,
    max_bytes: int = 20_000_000,
    max_rows: int = 100_000,
    max_line_bytes: int = 1_000_000,
) -> list[ManifestRow]:
    """Load bounded JSONL metadata without touching any referenced artifact."""

    _validate_limits(max_bytes, max_rows, max_line_bytes)
    manifest_path = Path(path)
    if manifest_path.is_symlink():
        raise ValueError("manifest cannot be a symlink")
    if manifest_path.stat().st_size > max_bytes:
        raise ValueError(f"manifest exceeds {max_bytes} bytes")
    rows: list[ManifestRow] = []
    total_bytes = 0
    with manifest_path.open(encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            line_bytes = len(raw_line.encode("utf-8"))
            total_bytes += line_bytes
            if total_bytes > max_bytes:
                raise ValueError(f"manifest exceeds {max_bytes} bytes")
            if line_bytes > max_line_bytes:
                raise ValueError(f"manifest row {line_number} is too large")
            if not raw_line.strip():
                continue
            if len(rows) >= max_rows:
                raise ValueError(f"manifest exceeds {max_rows} rows")
            try:
                record = json.loads(raw_line, parse_constant=_reject_constant)
                rows.append(_parse_row(record))
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(
                    f"invalid manifest row {line_number}: {error}"
                ) from error
    if not rows:
        raise ValueError("manifest contains no rows")
    return rows


def _validate_limits(max_bytes: int, max_rows: int, max_line_bytes: int) -> None:
    if max_bytes < 1 or max_rows < 1 or max_line_bytes < 1:
        raise ValueError("manifest limits must be positive")


def _parse_row(record: Any) -> ManifestRow:
    if not isinstance(record, dict):
        raise TypeError("row must be a JSON object")
    payload_fields = sorted(_PAYLOAD_FIELDS.intersection(record))
    if payload_fields:
        joined = ", ".join(payload_fields)
        raise ValueError(f"manifest must be metadata-only; remove: {joined}")
    unknown_fields = sorted(set(record).difference(_MANIFEST_FIELDS))
    if unknown_fields:
        joined = ", ".join(unknown_fields)
        raise ValueError(f"unsupported manifest fields: {joined}")
    split = _optional_text(record, "split")
    if split is not None and split not in _SPLITS:
        raise ValueError("split must be train, validation, or test")
    first_seen = _required_text(record, "first_seen")
    try:
        seen_date = date.fromisoformat(first_seen)
    except ValueError as error:
        raise ValueError("first_seen must be an ISO date") from error
    sha256 = _hash(record, "sha256", required=True)
    return ManifestRow(
        sample_id=_required_text(record, "sample_id"),
        label=_label(record["label"]),
        ecosystem=_required_text(record, "ecosystem"),
        package=_required_text(record, "package"),
        version=_required_text(record, "version"),
        sha256=sha256,
        first_seen=seen_date,
        group_id=_required_text(record, "group_id"),
        provenance=_required_text(record, "provenance"),
        license=_required_text(record, "license"),
        content_kind=_required_text(record, "content_kind"),
        split=split,
        representation_hash=_hash(record, "representation_hash"),
        family=_optional_text(record, "family"),
        campaign=_optional_text(record, "campaign"),
    )


def _required_text(record: dict[str, Any], key: str) -> str:
    if key not in record:
        raise KeyError(key)
    value = record[key]
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{key} must be non-empty text")
    if len(value) > 2_048:
        raise ValueError(f"{key} is too long")
    return value


def _optional_text(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{key} must be non-empty text when present")
    if len(value) > 2_048:
        raise ValueError(f"{key} is too long")
    return value


def _hash(
    record: dict[str, Any],
    key: str,
    *,
    required: bool = False,
) -> str | None:
    value = _required_text(record, key) if required else _optional_text(record, key)
    if value is not None and not _SHA256.fullmatch(value):
        raise ValueError(f"{key} must be a lowercase SHA-256 hex digest")
    return value


def _label(value: Any) -> int:
    if isinstance(value, bool):
        raise TypeError("label must identify benign or malicious")
    normalized = value.lower() if isinstance(value, str) else value
    if normalized in _POSITIVE:
        return 1
    if normalized in _NEGATIVE:
        return 0
    raise ValueError(f"unsupported label: {value!r}")


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def audit_manifest(
    rows: list[ManifestRow],
    *,
    max_issues: int = 1_000,
) -> dict[str, Any]:
    """Return reproducibility metadata and actionable leakage findings."""

    if not rows:
        raise ValueError("manifest contains no rows")
    if max_issues < 0:
        raise ValueError("max_issues cannot be negative")
    issues: list[AuditIssue] = []
    severity_counts: Counter[str] = Counter()
    truncated = 0

    def add(issue: AuditIssue) -> None:
        nonlocal truncated
        severity_counts[issue.severity] += 1
        if len(issues) < max_issues:
            issues.append(issue)
        else:
            truncated += 1

    _audit_duplicates(rows, add)
    _audit_split_overlap(rows, add)
    _audit_temporal_order(rows, add)

    missing_split = [row.sample_id for row in rows if row.split is None]
    if missing_split:
        add(
            AuditIssue(
                "warning",
                "missing-split",
                f"{len(missing_split)} rows have no split assignment",
                tuple(sorted(missing_split)[:10]),
            )
        )
    missing_repr = [row.sample_id for row in rows if row.representation_hash is None]
    if missing_repr:
        add(
            AuditIssue(
                "warning",
                "missing-representation-hash",
                f"{len(missing_repr)} rows cannot be checked for representation leakage",
                tuple(sorted(missing_repr)[:10]),
            )
        )

    canonical = [
        row.canonical() for row in sorted(rows, key=lambda item: item.sample_id)
    ]
    fingerprint = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    errors = severity_counts["error"]
    warnings = severity_counts["warning"]
    return {
        "schema": "itcs.manifest-audit.v1",
        "manifest_fingerprint": fingerprint,
        "rows": len(rows),
        "counts": _counts(rows),
        "valid": errors == 0,
        "errors": errors,
        "warnings": warnings,
        "issues_truncated": truncated,
        "issues": [issue.to_dict() for issue in issues],
    }


def _audit_duplicates(rows: list[ManifestRow], add) -> None:
    by_id = _group(rows, "sample_id")
    for sample_id, members in by_id.items():
        if len(members) > 1:
            add(
                AuditIssue(
                    "error",
                    "duplicate-sample-id",
                    f"sample_id {sample_id!r} appears {len(members)} times",
                    (sample_id,),
                )
            )
    by_sha = _group(rows, "sha256")
    for digest, members in by_sha.items():
        if len(members) < 2:
            continue
        labels = {row.label for row in members}
        code = "conflicting-label-duplicate" if len(labels) > 1 else "exact-duplicate"
        severity = (
            "error" if len(labels) > 1 or _split_count(members) > 1 else "warning"
        )
        add(
            AuditIssue(
                severity,
                code,
                f"SHA-256 {digest[:12]}… is shared by {len(members)} rows",
                _sample_ids(members),
            )
        )


def _audit_split_overlap(rows: list[ManifestRow], add) -> None:
    packages: dict[tuple[str, str], list[ManifestRow]] = defaultdict(list)
    for row in rows:
        packages[_package_key(row)].append(row)
    for key, members in packages.items():
        splits = sorted({row.split for row in members if row.split})
        groups = {row.group_id for row in members}
        if len(splits) > 1:
            add(
                AuditIssue(
                    "error",
                    "package-split-leakage",
                    f"package {key[0]}:{key[1]} crosses splits: {', '.join(splits)}",
                    _sample_ids(members),
                )
            )
        if len(groups) > 1:
            add(
                AuditIssue(
                    "warning",
                    "package-group-fragmentation",
                    f"package {key[0]}:{key[1]} uses {len(groups)} group IDs",
                    _sample_ids(members),
                )
            )
    checks = (
        ("group_id", "group-split-leakage", "error"),
        ("representation_hash", "representation-split-leakage", "error"),
        ("family", "family-split-overlap", "warning"),
        ("campaign", "campaign-split-overlap", "warning"),
    )
    for field, code, severity in checks:
        for value, members in _group(rows, field, skip_none=True).items():
            splits = sorted({row.split for row in members if row.split})
            if len(splits) > 1:
                add(
                    AuditIssue(
                        severity,
                        code,
                        f"{field} {value!r} crosses splits: {', '.join(splits)}",
                        _sample_ids(members),
                    )
                )


def _audit_temporal_order(rows: list[ManifestRow], add) -> None:
    dated = {split: [row for row in rows if row.split == split] for split in _SPLITS}
    pairs = (("train", "validation"), ("validation", "test"), ("train", "test"))
    for earlier, later in pairs:
        if not dated[earlier] or not dated[later]:
            continue
        latest_earlier = max(row.first_seen for row in dated[earlier])
        earliest_later = min(row.first_seen for row in dated[later])
        if latest_earlier >= earliest_later:
            add(
                AuditIssue(
                    "warning",
                    "non-forward-time-split",
                    f"{earlier} ends {latest_earlier}; {later} starts {earliest_later}",
                )
            )


def _group(
    rows: list[ManifestRow],
    field: str,
    *,
    skip_none: bool = False,
) -> dict[Any, list[ManifestRow]]:
    grouped: dict[Any, list[ManifestRow]] = defaultdict(list)
    for row in rows:
        value = getattr(row, field)
        if skip_none and value is None:
            continue
        grouped[value].append(row)
    return grouped


def _package_key(row: ManifestRow) -> tuple[str, str]:
    ecosystem = row.ecosystem.casefold()
    package = row.package.casefold()
    if ecosystem in {"pypi", "python"}:
        package = re.sub(r"[-_.]+", "-", package)
    return ecosystem, package


def _sample_ids(rows: list[ManifestRow]) -> tuple[str, ...]:
    return tuple(sorted({row.sample_id for row in rows})[:10])


def _split_count(rows: list[ManifestRow]) -> int:
    return len({row.split for row in rows if row.split})


def _counts(rows: list[ManifestRow]) -> dict[str, dict[str, int]]:
    labels = Counter("malicious" if row.label else "benign" for row in rows)
    splits = Counter(row.split or "unassigned" for row in rows)
    ecosystems = Counter(row.ecosystem for row in rows)
    return {
        "labels": dict(sorted(labels.items())),
        "splits": dict(sorted(splits.items())),
        "ecosystems": dict(sorted(ecosystems.items())),
    }


def audit_manifest_path(path: str | Path) -> dict[str, Any]:
    return audit_manifest(load_manifest(path))
