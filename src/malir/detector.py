"""Evidence-first scoring and conditional model execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .types import Evidence, FileAnalysis


class ProbabilityModel(Protocol):
    def predict_proba(self, tokens: list[str]) -> float: ...


EVENT_WEIGHTS = {
    "DYNAMIC_EXEC": 27.0,
    "PROCESS_EXEC": 18.0,
    "UNSAFE_DESERIALIZE": 17.0,
    "NETWORK_SEND": 15.0,
    "NETWORK_RECEIVE": 7.0,
    "PERSISTENCE_WRITE": 24.0,
    "SENSITIVE_FILE_READ": 12.0,
    "ENV_READ": 7.0,
    "SYSTEM_DISCOVERY": 5.0,
    "DYNAMIC_IMPORT": 7.0,
    "DECODE": 7.0,
    "ENCODE": 4.0,
    "FILE_DELETE": 10.0,
    "FILE_WRITE": 1.0,
}


@dataclass(frozen=True, slots=True)
class CascadeConfig:
    low_gate: float = 20.0
    high_gate: float = 80.0
    rule_weight: float = 0.65
    max_evidence: int = 12


@dataclass(slots=True)
class Decision:
    risk_score: float
    rule_score: float
    model_probability: float | None
    model_used: bool
    verdict: str
    evidence: list[Evidence]


def decide(
    files: list[FileAnalysis],
    model: ProbabilityModel | None = None,
    config: CascadeConfig | None = None,
) -> Decision:
    config = config or CascadeConfig()
    evidence: list[Evidence] = []
    for item in files:
        if item.event_limit_reached:
            evidence.append(
                Evidence(
                    score=25.0,
                    reason="analysis event limit was reached",
                    path=item.path,
                    line=0,
                    op="ANALYSIS_LIMIT",
                )
            )
        for event in item.events:
            weight = EVENT_WEIGHTS.get(event.op, 0.0)
            if weight:
                evidence.append(
                    Evidence(
                        score=weight,
                        reason=event.detail,
                        path=event.path,
                        line=event.line,
                        op=event.op,
                    )
                )
        for path in item.behavior_paths:
            first = item.events[path.event_indexes[0]]
            evidence.append(
                Evidence(
                    score=path.score,
                    reason=path.reason,
                    path=first.path,
                    line=first.line,
                    op="BEHAVIOR_PATH",
                    motif=path.motif,
                )
            )

    ranked = sorted(
        evidence,
        key=lambda item: (-item.score, item.path, item.line, item.op),
    )
    rule_score = min(100.0, sum(item.score for item in ranked[:8]))
    tokens: list[str] = []
    for item in files:
        tokens.append(f"FILE:{item.path}")
        tokens.extend(item.tokens)

    probability: float | None = None
    model_used = False
    risk_score = rule_score
    if model is not None and config.low_gate <= rule_score <= config.high_gate:
        probability = model.predict_proba(tokens)
        risk_score = 100.0 * (
            config.rule_weight * (rule_score / 100.0)
            + (1.0 - config.rule_weight) * probability
        )
        model_used = True

    return Decision(
        risk_score=risk_score,
        rule_score=rule_score,
        model_probability=probability,
        model_used=model_used,
        verdict=_verdict(risk_score),
        evidence=ranked[: config.max_evidence],
    )


def _verdict(score: float) -> str:
    if score >= 75.0:
        return "high-risk"
    if score >= 50.0:
        return "suspicious"
    if score >= 25.0:
        return "review"
    return "low-signal"
