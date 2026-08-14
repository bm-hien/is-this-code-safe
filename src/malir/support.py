"""Conservative training-support checks for advisory µMal inference."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any

SUPPORT_SCHEMA = "malir.support-profile.v1"


@dataclass(frozen=True, slots=True)
class SupportAssessment:
    supported: bool
    token_coverage: float
    nearest_similarity: float
    unknown_tokens: tuple[str, ...] = ()

    @property
    def abstained(self) -> bool:
        return not self.supported

    def to_dict(self) -> dict[str, Any]:
        output = asdict(self)
        output["unknown_tokens"] = list(self.unknown_tokens)
        output["abstained"] = self.abstained
        return output


def build_support_profile(
    token_sequences: Iterable[Iterable[str]],
    group_ids: Iterable[str],
    *,
    min_token_coverage: float = 1.0,
    min_nearest_jaccard: float = 0.2,
) -> dict[str, Any]:
    sequences = [tuple(dict.fromkeys(map(str, tokens))) for tokens in token_sequences]
    identifiers = [str(group_id) for group_id in group_ids]
    if not sequences or len(sequences) != len(identifiers):
        raise ValueError("support profile needs aligned, non-empty examples")
    _validate_threshold(min_token_coverage, "min_token_coverage")
    _validate_threshold(min_nearest_jaccard, "min_nearest_jaccard")

    prototypes = []
    seen_groups: set[str] = set()
    for tokens, group_id in zip(sequences, identifiers, strict=True):
        if group_id in seen_groups:
            continue
        seen_groups.add(group_id)
        prototypes.append({"group_id": group_id, "tokens": sorted(set(tokens))})
    profile = {
        "schema": SUPPORT_SCHEMA,
        "known_tokens": sorted({token for tokens in sequences for token in tokens}),
        "prototypes": prototypes,
        "min_token_coverage": float(min_token_coverage),
        "min_nearest_jaccard": float(min_nearest_jaccard),
    }
    validate_support_profile(profile)
    return profile


def assess_model_support(
    tokens: Iterable[str],
    profile: dict[str, Any] | None,
) -> SupportAssessment:
    if profile is None:
        return SupportAssessment(True, 1.0, 1.0)
    validate_support_profile(profile)
    observed = set(map(str, tokens))
    known = set(profile["known_tokens"])
    unknown = tuple(sorted(observed - known))
    coverage = (len(observed) - len(unknown)) / len(observed) if observed else 0.0
    nearest = max(
        (
            _jaccard(observed, set(prototype["tokens"]))
            for prototype in profile["prototypes"]
        ),
        default=0.0,
    )
    supported = bool(observed) and (
        coverage >= float(profile["min_token_coverage"])
        and nearest >= float(profile["min_nearest_jaccard"])
    )
    return SupportAssessment(supported, coverage, nearest, unknown)


def validate_support_profile(profile: dict[str, Any]) -> None:
    if not isinstance(profile, dict) or profile.get("schema") != SUPPORT_SCHEMA:
        raise ValueError("unsupported µMal support profile schema")
    known = profile.get("known_tokens")
    prototypes = profile.get("prototypes")
    if (
        not isinstance(known, list)
        or not known
        or not all(isinstance(token, str) and token for token in known)
    ):
        raise ValueError("support profile known_tokens are invalid")
    if not isinstance(prototypes, list) or not prototypes:
        raise ValueError("support profile prototypes are invalid")
    for prototype in prototypes:
        if (
            not isinstance(prototype, dict)
            or not isinstance(prototype.get("group_id"), str)
            or not prototype["group_id"]
            or not isinstance(prototype.get("tokens"), list)
            or not prototype["tokens"]
            or not all(
                isinstance(token, str) and token for token in prototype["tokens"]
            )
        ):
            raise ValueError("support profile prototype is invalid")
    _validate_threshold(profile.get("min_token_coverage"), "min_token_coverage")
    _validate_threshold(profile.get("min_nearest_jaccard"), "min_nearest_jaccard")


def _validate_threshold(value: object, name: str) -> None:
    if not isinstance(value, (int, float)) or not 0.0 <= float(value) <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0
