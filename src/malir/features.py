"""Stable, dependency-free feature hashing for MalIR sequences."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable


def behavior_ngrams(
    tokens: list[str],
    min_n: int = 1,
    max_n: int = 3,
) -> Iterable[str]:
    cleaned = ["BOS", *tokens, "EOS"]
    for size in range(min_n, max_n + 1):
        for index in range(len(cleaned) - size + 1):
            yield "→".join(cleaned[index : index + size])


def stable_bucket(feature: str, dimensions: int) -> tuple[int, float]:
    digest = hashlib.blake2b(
        feature.encode("utf-8"),
        digest_size=8,
        person=b"malir-v1",
    ).digest()
    value = int.from_bytes(digest, "little")
    index = value % dimensions
    sign = -1.0 if value & (1 << 63) else 1.0
    return index, sign


def vectorize(
    tokens: list[str],
    dimensions: int = 1 << 16,
    min_n: int = 1,
    max_n: int = 3,
) -> dict[int, float]:
    values: dict[int, float] = {}
    for feature in behavior_ngrams(tokens, min_n, max_n):
        index, sign = stable_bucket(feature, dimensions)
        values[index] = values.get(index, 0.0) + sign
    norm = math.sqrt(sum(value * value for value in values.values()))
    if norm:
        return {index: value / norm for index, value in values.items()}
    return values
