"""Typed data structures shared by the extractor and detector."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


def _effect_token(value: str) -> str:
    return value.lower().replace("-", "_").replace(" ", "_")


@dataclass(frozen=True, slots=True)
class PurposeCandidate:
    label: str
    confidence: str
    reason: str
    lines: tuple[int, ...] = ()

    def token(self) -> str:
        return f"PURPOSE:{_effect_token(self.label)}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "confidence": self.confidence,
            "reason": self.reason,
            "lines": list(self.lines),
        }


@dataclass(frozen=True, slots=True)
class EffectSummary:
    entrypoints: tuple[str, ...] = ()
    data_origins: tuple[str, ...] = ()
    data_destinations: tuple[str, ...] = ()
    transformations: tuple[str, ...] = ()
    flows: tuple[str, ...] = ()
    purpose_candidates: tuple[PurposeCandidate, ...] = ()

    @property
    def primary_purpose(self) -> str:
        if not self.purpose_candidates:
            return "unknown"
        return self.purpose_candidates[0].label

    @property
    def tokens(self) -> list[str]:
        output = [f"EFFECT:ENTRY:{_effect_token(value)}" for value in self.entrypoints]
        output.extend(
            f"EFFECT:ORIGIN:{_effect_token(value)}" for value in self.data_origins
        )
        output.extend(
            f"EFFECT:DESTINATION:{_effect_token(value)}"
            for value in self.data_destinations
        )
        output.extend(f"EFFECT:FLOW:{_effect_token(value)}" for value in self.flows)
        output.extend(
            f"EFFECT:TRANSFORM:{_effect_token(value)}" for value in self.transformations
        )
        output.extend(item.token() for item in self.purpose_candidates)
        return output

    def to_dict(self) -> dict[str, Any]:
        return {
            "entrypoints": list(self.entrypoints),
            "data_origins": list(self.data_origins),
            "data_destinations": list(self.data_destinations),
            "transformations": list(self.transformations),
            "flows": list(self.flows),
            "primary_purpose": self.primary_purpose,
            "purpose_candidates": [item.to_dict() for item in self.purpose_candidates],
        }


@dataclass(frozen=True, slots=True)
class Event:
    op: str
    category: str
    target: str
    path: str
    line: int
    column: int
    function: str
    phase: str
    detail: str = ""

    def token(self) -> str:
        target = self.target.lower().replace(" ", "_")
        return f"P:{self.phase}|C:{self.category}|O:{self.op}|T:{target}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class BehaviorPath:
    motif: str
    score: float
    reason: str
    event_indexes: tuple[int, ...]
    evidence_kind: str = "proximity"
    confidence: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "motif": self.motif,
            "score": round(self.score, 3),
            "reason": self.reason,
            "event_indexes": list(self.event_indexes),
            "evidence_kind": self.evidence_kind,
            "confidence": self.confidence,
        }


@dataclass(slots=True)
class FileAnalysis:
    path: str
    sha256: str
    bytes_read: int
    events: list[Event] = field(default_factory=list)
    behavior_paths: list[BehaviorPath] = field(default_factory=list)
    effect_summary: EffectSummary = field(default_factory=EffectSummary)
    parse_error: str | None = None
    truncated: bool = False
    event_limit_reached: bool = False

    @property
    def tokens(self) -> list[str]:
        tokens = [event.token() for event in self.events]
        tokens.extend(f"MOTIF:{item.motif}" for item in self.behavior_paths)
        tokens.extend(self.effect_summary.tokens)
        return tokens

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "bytes_read": self.bytes_read,
            "truncated": self.truncated,
            "event_limit_reached": self.event_limit_reached,
            "parse_error": self.parse_error,
            "events": [event.to_dict() for event in self.events],
            "behavior_paths": [item.to_dict() for item in self.behavior_paths],
            "effect_summary": self.effect_summary.to_dict(),
            "tokens": self.tokens,
        }


@dataclass(slots=True)
class Evidence:
    score: float
    reason: str
    path: str
    line: int
    op: str
    motif: str | None = None
    evidence_kind: str | None = None
    confidence: str | None = None
    occurrences: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanReport:
    target: str
    verdict: str
    risk_score: float
    rule_score: float
    model_probability: float | None
    model_consulted: bool
    model_used: bool
    model_supported: bool | None
    model_abstained: bool
    model_token_coverage: float | None
    model_nearest_similarity: float | None
    model_unknown_tokens: list[str]
    files_scanned: int
    files_skipped: int
    elapsed_ms: float
    evidence: list[Evidence]
    files: list[FileAnalysis]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "malir.scan.v1",
            "target": self.target,
            "assessment": {
                "low-signal": "no-malware-evidence",
                "review": "needs-review",
                "suspicious": "malware-like",
                "high-risk": "malware-like",
            }[self.verdict],
            "verdict": self.verdict,
            "risk_score": round(self.risk_score, 3),
            "capability_score": round(self.rule_score, 3),
            "rule_score": round(self.rule_score, 3),
            "model_probability": (
                None
                if self.model_probability is None
                else round(self.model_probability, 6)
            ),
            "model_consulted": self.model_consulted,
            "model_used": self.model_used,
            "model_supported": self.model_supported,
            "model_abstained": self.model_abstained,
            "model_token_coverage": (
                None
                if self.model_token_coverage is None
                else round(self.model_token_coverage, 6)
            ),
            "model_nearest_similarity": (
                None
                if self.model_nearest_similarity is None
                else round(self.model_nearest_similarity, 6)
            ),
            "model_unknown_tokens": self.model_unknown_tokens,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "evidence": [item.to_dict() for item in self.evidence],
            "warnings": self.warnings,
            "files": [item.to_dict() for item in self.files],
        }
