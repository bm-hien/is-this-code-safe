"""JSONL datasets for sparse and micro behavior models."""

from __future__ import annotations

import json
from pathlib import Path

from .extractor import PythonExtractor
from .model_tokens import canonicalize_model_tokens

POSITIVE_LABELS = {1, "1", "malicious", "suspicious", "positive"}
NEGATIVE_LABELS = {0, "0", "benign", "clean", "negative"}


def load_examples(path: str | Path) -> list[tuple[list[str], int]]:
    dataset_path = Path(path)
    extractor = PythonExtractor()
    examples: list[tuple[list[str], int]] = []
    with dataset_path.open(encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            if not raw_line.strip():
                continue
            try:
                record = json.loads(raw_line)
                label = _parse_label(record["label"])
                tokens = canonicalize_model_tokens(
                    _tokens_for_record(record, dataset_path.parent, extractor)
                )
            except (KeyError, TypeError, ValueError, OSError) as error:
                raise ValueError(
                    f"invalid dataset row {line_number}: {error}"
                ) from error
            examples.append((tokens, label))
    if not examples:
        raise ValueError("dataset contains no examples")
    labels = {label for _, label in examples}
    if labels != {0, 1}:
        raise ValueError("dataset must contain both label classes")
    return examples


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
        return extractor.analyze_source(record["source"]).tokens
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
