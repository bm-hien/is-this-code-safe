"""Typed data structures shared by the extractor and detector."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "motif": self.motif,
            "score": round(self.score, 3),
            "reason": self.reason,
            "event_indexes": list(self.event_indexes),
        }


@dataclass(slots=True)
class FileAnalysis:
    path: str
    sha256: str
    bytes_read: int
    events: list[Event] = field(default_factory=list)
    behavior_paths: list[BehaviorPath] = field(default_factory=list)
    parse_error: str | None = None
    truncated: bool = False
    event_limit_reached: bool = False

    @property
    def tokens(self) -> list[str]:
        tokens = [event.token() for event in self.events]
        tokens.extend(f"MOTIF:{item.motif}" for item in self.behavior_paths)
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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanReport:
    target: str
    verdict: str
    risk_score: float
    rule_score: float
    model_probability: float | None
    model_used: bool
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
            "rule_score": round(self.rule_score, 3),
            "model_probability": (
                None
                if self.model_probability is None
                else round(self.model_probability, 6)
            ),
            "model_used": self.model_used,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "evidence": [item.to_dict() for item in self.evidence],
            "warnings": self.warnings,
            "files": [item.to_dict() for item in self.files],
        }
