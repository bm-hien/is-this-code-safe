"""JSONL datasets for sparse and micro behavior models."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .extractor import PythonExtractor
from .model_tokens import canonicalize_model_tokens

POSITIVE_LABELS = {1, "1", "malicious", "suspicious", "positive"}
NEGATIVE_LABELS = {0, "0", "benign", "clean", "negative"}
_ALLOWED_SPLITS = {"train", "validation"}


@dataclass(frozen=True, slots=True)
class DatasetExample:
    sample_id: str
    group_id: str
    split: str
    role: str
    tokens: tuple[str, ...]
    label: int
    representation_hash: str
    pair_id: str | None = None

    def as_pair(self) -> tuple[list[str], int]:
        return list(self.tokens), self.label


@dataclass(frozen=True, slots=True)
class TrainingDataset:
    train: tuple[DatasetExample, ...]
    validation: tuple[DatasetExample, ...]
    dataset_sha256: str
    split_fingerprint: str

    @property
    def all_examples(self) -> tuple[DatasetExample, ...]:
        return self.train + self.validation


def load_examples(path: str | Path) -> list[tuple[list[str], int]]:
    """Load training rows for backwards-compatible sparse or smoke training."""

    return [
        example.as_pair() for example in _load_records(path) if example.split == "train"
    ]


def load_training_dataset(path: str | Path) -> TrainingDataset:
    """Load and audit an explicit group-disjoint train/validation dataset."""

    dataset_path = Path(path)
    records = _load_records(dataset_path, require_metadata=True)
    train = tuple(record for record in records if record.split == "train")
    validation = tuple(record for record in records if record.split == "validation")
    if not train or not validation:
        raise ValueError("dataset needs non-empty train and validation splits")
    for name, split in (("train", train), ("validation", validation)):
        if {record.label for record in split} != {0, 1}:
            raise ValueError(f"{name} split must contain both label classes")
    _audit_split_isolation(records)
    fingerprint_rows = [
        (
            record.sample_id,
            record.group_id,
            record.split,
            record.label,
            record.representation_hash,
        )
        for record in sorted(records, key=lambda item: item.sample_id)
    ]
    fingerprint = hashlib.sha256(
        json.dumps(
            fingerprint_rows,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return TrainingDataset(
        train=train,
        validation=validation,
        dataset_sha256=_sha256(dataset_path),
        split_fingerprint=fingerprint,
    )


def _load_records(
    path: str | Path,
    *,
    require_metadata: bool = False,
) -> list[DatasetExample]:
    dataset_path = Path(path)
    extractor = PythonExtractor()
    examples: list[DatasetExample] = []
    sample_ids: set[str] = set()
    with dataset_path.open(encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            if not raw_line.strip():
                continue
            try:
                record = json.loads(raw_line)
                label = _parse_label(record["label"])
                tokens = tuple(
                    canonicalize_model_tokens(
                        _tokens_for_record(record, dataset_path.parent, extractor)
                    )
                )
                sample_id = _metadata_value(
                    record,
                    "sample_id",
                    f"row-{line_number}",
                    require_metadata,
                )
                group_id = _metadata_value(
                    record,
                    "group_id",
                    sample_id,
                    require_metadata,
                )
                split = str(record.get("split", "train")).strip().lower()
                if split not in _ALLOWED_SPLITS:
                    raise ValueError(f"unsupported split: {split!r}")
                role = str(record.get("role", "unspecified")).strip()
                pair_value = record.get("pair_id")
                pair_id = str(pair_value).strip() if pair_value is not None else None
            except (KeyError, TypeError, ValueError, OSError) as error:
                raise ValueError(
                    f"invalid dataset row {line_number}: {error}"
                ) from error
            if sample_id in sample_ids:
                raise ValueError(f"duplicate sample_id: {sample_id}")
            sample_ids.add(sample_id)
            representation_hash = hashlib.sha256(
                json.dumps(
                    tokens,
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            examples.append(
                DatasetExample(
                    sample_id=sample_id,
                    group_id=group_id,
                    split=split,
                    role=role,
                    tokens=tokens,
                    label=label,
                    representation_hash=representation_hash,
                    pair_id=pair_id,
                )
            )
    if not examples:
        raise ValueError("dataset contains no examples")
    labels = {example.label for example in examples}
    if labels != {0, 1}:
        raise ValueError("dataset must contain both label classes")
    return examples


def _metadata_value(
    record: dict,
    key: str,
    fallback: str,
    required: bool,
) -> str:
    if required and key not in record:
        raise ValueError(f"dataset row needs {key}")
    value = str(record.get(key, fallback)).strip()
    if not value:
        raise ValueError(f"{key} cannot be empty")
    return value


def _audit_split_isolation(records: list[DatasetExample]) -> None:
    group_splits: dict[str, set[str]] = {}
    representation_splits: dict[str, set[str]] = {}
    representation_labels: dict[str, set[int]] = {}
    for record in records:
        group_splits.setdefault(record.group_id, set()).add(record.split)
        representation_splits.setdefault(record.representation_hash, set()).add(
            record.split
        )
        representation_labels.setdefault(record.representation_hash, set()).add(
            record.label
        )
    crossed_groups = sorted(
        group for group, splits in group_splits.items() if len(splits) > 1
    )
    if crossed_groups:
        raise ValueError(
            "group_id crosses train/validation: " + ", ".join(crossed_groups[:5])
        )
    crossed_representations = sum(
        len(splits) > 1 for splits in representation_splits.values()
    )
    if crossed_representations:
        raise ValueError(
            "model-visible representation crosses train/validation: "
            f"{crossed_representations}"
        )
    conflicting = sum(len(labels) > 1 for labels in representation_labels.values())
    if conflicting:
        raise ValueError(
            f"model-visible representation has conflicting labels: {conflicting}"
        )


def _tokens_for_record(
    record: dict,
    base: Path,
    extractor: PythonExtractor,
) -> list[str]:
    if "tokens" in record:
        if not isinstance(record["tokens"], list):
            raise TypeError("tokens must be a list")
        return [str(token) for token in record["tokens"]]
    if "source" in record:
        if not isinstance(record["source"], str):
            raise TypeError("source must be text")
        source_path = str(record.get("source_path", "<dataset>"))
        return extractor.analyze_source(record["source"], source_path).tokens
    if "path" in record:
        raw_path = base / str(record["path"])
        source_path = raw_path.resolve()
        dataset_root = base.resolve()
        if raw_path.is_symlink() or not source_path.is_relative_to(dataset_root):
            raise ValueError("dataset path escapes its directory")
        return extractor.analyze_file(source_path, source_path.name).tokens
    raise ValueError("row needs tokens, source, or path")


def _parse_label(value: object) -> int:
    normalized = value.lower() if isinstance(value, str) else value
    if normalized in POSITIVE_LABELS:
        return 1
    if normalized in NEGATIVE_LABELS:
        return 0
    raise ValueError(f"unsupported label: {value!r}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()
