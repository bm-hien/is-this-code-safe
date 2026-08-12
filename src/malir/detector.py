"""Evidence-first scoring and conditional model execution."""

from __future__ import annotations

from dataclasses import dataclass
from heapq import nlargest
from typing import Literal, Protocol

from .types import Evidence, FileAnalysis


class ProbabilityModel(Protocol):
    def predict_proba(self, tokens: list[str]) -> float: ...


RuleAggregation = Literal["legacy-top8", "context-max-v1"]


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
    rule_aggregation: RuleAggregation = "legacy-top8"


@dataclass(slots=True)
class Decision:
    risk_score: float
    rule_score: float
    model_probability: float | None
    model_used: bool
    verdict: str
    evidence: list[Evidence]


@dataclass(frozen=True, slots=True)
class _ContextEvidence:
    evidence: Evidence
    context: tuple[str, str]
    dedup_key: tuple[str, ...]


def decide(
    files: list[FileAnalysis],
    model: ProbabilityModel | None = None,
    config: CascadeConfig | None = None,
) -> Decision:
    config = config or CascadeConfig()
    contextual: list[_ContextEvidence] = []
    for item in files:
        if item.event_limit_reached:
            contextual.append(
                _ContextEvidence(
                    evidence=Evidence(
                        score=25.0,
                        reason="analysis event limit was reached",
                        path=item.path,
                        line=0,
                        op="ANALYSIS_LIMIT",
                    ),
                    context=(item.path, "<module>"),
                    dedup_key=("event", "ANALYSIS_LIMIT"),
                )
            )
        for event in item.events:
            weight = EVENT_WEIGHTS.get(event.op, 0.0)
            if weight:
                contextual.append(
                    _ContextEvidence(
                        evidence=Evidence(
                            score=weight,
                            reason=event.detail,
                            path=event.path,
                            line=event.line,
                            op=event.op,
                        ),
                        context=(event.path, event.function),
                        dedup_key=("event", event.op),
                    )
                )
        for path in item.behavior_paths:
            first = item.events[path.event_indexes[0]]
            contextual.append(
                _ContextEvidence(
                    evidence=Evidence(
                        score=path.score,
                        reason=path.reason,
                        path=first.path,
                        line=first.line,
                        op="BEHAVIOR_PATH",
                        motif=path.motif,
                        evidence_kind=path.evidence_kind,
                        confidence=path.confidence,
                    ),
                    context=(first.path, first.function),
                    dedup_key=("motif", path.motif, path.evidence_kind),
                )
            )

    ranked = sorted(
        (item.evidence for item in contextual),
        key=lambda item: (-item.score, item.path, item.line, item.op),
    )
    rule_score = _aggregate_rule_score(
        contextual,
        ranked,
        config.rule_aggregation,
    )
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


def _aggregate_rule_score(
    contextual: list[_ContextEvidence],
    ranked: list[Evidence],
    strategy: RuleAggregation,
) -> float:
    if strategy == "legacy-top8":
        return min(100.0, sum(item.score for item in ranked[:8]))
    if strategy != "context-max-v1":
        raise ValueError(f"unsupported rule aggregation: {strategy}")

    contexts: dict[tuple[str, str], dict[tuple[str, ...], float]] = {}
    for item in contextual:
        retained = contexts.setdefault(item.context, {})
        retained[item.dedup_key] = max(
            retained.get(item.dedup_key, 0.0),
            item.evidence.score,
        )
    return min(
        100.0,
        max(
            (sum(nlargest(4, retained.values())) for retained in contexts.values()),
            default=0.0,
        ),
    )


def _verdict(score: float) -> str:
    if score >= 75.0:
        return "high-risk"
    if score >= 50.0:
        return "suspicious"
    if score >= 25.0:
        return "review"
    return "low-signal"
