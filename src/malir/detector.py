"""Evidence-first scoring, semantic saturation, and conditional model fusion."""

from __future__ import annotations

from dataclasses import dataclass, field
from heapq import nlargest
from typing import Literal, Protocol

from .model_tokens import model_event_token
from .types import Evidence, FileAnalysis


class ProbabilityModel(Protocol):
    def predict_proba(self, tokens: list[str]) -> float: ...


RuleAggregation = Literal[
    "semantic-top8-v1",
    "legacy-top8",
    "context-max-v1",
    "context-cover-v2",
    "context-causal-v6",
]


V6_CONTEXT_ONLY_OPS = {
    "BROWSER_COOKIE_READ",
    "ENV_READ",
    "SYSTEM_DISCOVERY",
    "DYNAMIC_IMPORT",
    "DECODE",
    "ENCODE",
    "FILE_WRITE",
    "UNSAFE_DESERIALIZE",
}


AUXILIARY_PATH_SEGMENTS = {
    "test",
    "tests",
    "testing",
    "doc",
    "docs",
    "example",
    "examples",
    "benchmark",
    "benchmarks",
}


EVENT_WEIGHTS = {
    "BROWSER_COOKIE_READ": 12.0,
    "DYNAMIC_EXEC": 27.0,
    "CODE_COMPILE": 2.0,
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
    rule_aggregation: RuleAggregation = "semantic-top8-v1"


@dataclass(slots=True)
class Decision:
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
    verdict: str
    evidence: list[Evidence]


@dataclass(frozen=True, slots=True)
class _ContextEvidence:
    evidence: Evidence
    context: tuple[str, str]
    dedup_key: tuple[str, ...]
    event_key: tuple[str, int] | None = None
    covered_event_keys: frozenset[tuple[str, int]] = frozenset()


@dataclass(slots=True)
class _EventGroup:
    score: float = 0.0
    event_keys: set[tuple[str, int]] = field(default_factory=set)


@dataclass(slots=True)
class _PathGroup:
    score: float = 0.0
    covered: set[tuple[str, int]] = field(default_factory=set)
    high_confidence: bool = False


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
        for event_index, event in enumerate(item.events):
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
                        event_key=(item.path, event_index),
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
                    covered_event_keys=frozenset(
                        (item.path, event_index) for event_index in path.event_indexes
                    ),
                )
            )

    ranked = _rank_evidence(contextual)
    rule_score = _aggregate_rule_score(
        contextual,
        config.rule_aggregation,
    )
    tokens = _model_tokens(files)

    probability: float | None = None
    model_consulted = False
    model_used = False
    model_supported: bool | None = None
    model_abstained = False
    model_token_coverage: float | None = None
    model_nearest_similarity: float | None = None
    model_unknown_tokens: list[str] = []
    risk_score = rule_score
    if model is not None:
        details_method = getattr(model, "predict_details", None)
        if callable(details_method):
            details = details_method(tokens)
            probability = float(details["probability"])
            supported = bool(details.get("supported", True))
            model_abstained = not supported
            model_token_coverage = float(details.get("token_coverage", 1.0))
            model_nearest_similarity = float(details.get("nearest_similarity", 1.0))
            model_unknown_tokens = [
                str(token) for token in details.get("unknown_tokens", ())
            ]
        else:
            probability = model.predict_proba(tokens)
            supported = True
        model_consulted = True
        model_supported = supported
        if supported and config.low_gate <= rule_score <= config.high_gate:
            fused_score = 100.0 * (
                config.rule_weight * (rule_score / 100.0)
                + (1.0 - config.rule_weight) * probability
            )
            risk_score = max(rule_score, fused_score)
            model_used = True

    return Decision(
        risk_score=risk_score,
        rule_score=rule_score,
        model_probability=probability,
        model_consulted=model_consulted,
        model_used=model_used,
        model_supported=model_supported,
        model_abstained=model_abstained,
        model_token_coverage=model_token_coverage,
        model_nearest_similarity=model_nearest_similarity,
        model_unknown_tokens=model_unknown_tokens,
        verdict=_verdict(risk_score),
        evidence=ranked[: config.max_evidence],
    )


def _aggregate_rule_score(
    contextual: list[_ContextEvidence],
    strategy: RuleAggregation,
) -> float:
    if strategy == "semantic-top8-v1":
        return _aggregate_semantic_top8(contextual)
    if strategy == "legacy-top8":
        return _aggregate_legacy_with_summary_cover(contextual)
    if strategy == "context-max-v1":
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
    if strategy == "context-cover-v2":
        return _aggregate_context_cover(contextual)
    if strategy == "context-causal-v6":
        return _aggregate_context_causal_v6(contextual)
    raise ValueError(f"unsupported rule aggregation: {strategy}")


def _aggregate_semantic_top8(
    contextual: list[_ContextEvidence],
) -> float:
    """Score semantic novelty rather than repeated source occurrences."""
    covered = {
        event_key
        for item in contextual
        if item.evidence.evidence_kind == "summary"
        for event_key in item.covered_event_keys
    }
    retained: dict[tuple[str, ...], float] = {}
    for item in contextual:
        if item.event_key is not None and item.event_key in covered:
            continue
        retained[item.dedup_key] = max(
            retained.get(item.dedup_key, 0.0),
            item.evidence.score,
        )
    return min(100.0, sum(nlargest(8, retained.values())))


def _rank_evidence(contextual: list[_ContextEvidence]) -> list[Evidence]:
    """Collapse equivalent evidence while retaining its occurrence count."""
    groups: dict[tuple[str, ...], list[_ContextEvidence]] = {}
    for item in contextual:
        groups.setdefault(item.dedup_key, []).append(item)

    ranked: list[Evidence] = []
    for items in groups.values():
        representative = min(
            items,
            key=lambda item: (
                -item.evidence.score,
                item.evidence.path,
                item.evidence.line,
                item.evidence.op,
            ),
        ).evidence
        ranked.append(
            Evidence(
                score=representative.score,
                reason=representative.reason,
                path=representative.path,
                line=representative.line,
                op=representative.op,
                motif=representative.motif,
                evidence_kind=representative.evidence_kind,
                confidence=representative.confidence,
                occurrences=sum(item.evidence.occurrences for item in items),
            )
        )
    return sorted(
        ranked,
        key=lambda item: (-item.score, item.path, item.line, item.op),
    )


def _aggregate_legacy_with_summary_cover(
    contextual: list[_ContextEvidence],
) -> float:
    """Preserve legacy ranking while preventing new summary self-stacking."""
    covered = {
        event_key
        for item in contextual
        if item.evidence.evidence_kind == "summary"
        for event_key in item.covered_event_keys
    }
    scores = [
        item.evidence.score
        for item in contextual
        if item.event_key is None or item.event_key not in covered
    ]
    return min(100.0, sum(nlargest(8, scores)))


def _aggregate_context_cover(contextual: list[_ContextEvidence]) -> float:
    contexts: dict[tuple[str, str], list[_ContextEvidence]] = {}
    for item in contextual:
        contexts.setdefault(item.context, []).append(item)

    maximum = 0.0
    for items in contexts.values():
        event_scores = {
            item.event_key: item.evidence.score
            for item in items
            if item.event_key is not None
        }
        event_groups: dict[tuple[str, ...], _EventGroup] = {}
        path_groups: dict[tuple[str, ...], _PathGroup] = {}
        for item in items:
            if item.dedup_key[0] == "event":
                group = event_groups.setdefault(item.dedup_key, _EventGroup())
                group.score = max(group.score, item.evidence.score)
                if item.event_key is not None:
                    group.event_keys.add(item.event_key)
                continue
            group = path_groups.setdefault(item.dedup_key, _PathGroup())
            group.score = max(group.score, item.evidence.score)
            if item.evidence.evidence_kind in {"dataflow", "summary", "structural"}:
                group.high_confidence = True
                group.covered.update(item.covered_event_keys)

        covered: set[tuple[str, int]] = set()
        retained: list[float] = []
        for group in path_groups.values():
            score = group.score
            if group.high_confidence:
                covered.update(group.covered)
                covered_scores = [
                    event_scores[event_key]
                    for event_key in group.covered
                    if event_key in event_scores
                ]
                if covered_scores:
                    score = max(score, max(covered_scores))
            retained.append(score)

        for group in event_groups.values():
            if not group.event_keys or any(
                event_key not in covered for event_key in group.event_keys
            ):
                retained.append(group.score)
        maximum = max(maximum, sum(nlargest(4, retained)))
    return min(100.0, maximum)


def _aggregate_context_causal_v6(contextual: list[_ContextEvidence]) -> float:
    contexts: dict[tuple[str, str], list[_ContextEvidence]] = {}
    for item in contextual:
        contexts.setdefault(item.context, []).append(item)

    maximum = 0.0
    for (path, _function), items in contexts.items():
        contributions = _causal_contributions(items)
        if _is_auxiliary_path(path):
            context_score = max((score for score, *_ in contributions), default=0.0)
        elif _is_orchestration_path(path):
            causal = [
                score
                for score, kind, name in contributions
                if kind in {"dataflow", "summary"}
                or (
                    kind == "structural"
                    and name
                    in {
                        "install_time_execution",
                        "persistence_write",
                    }
                )
            ]
            has_dataflow = any(
                kind in {"dataflow", "summary"} for _, kind, _ in contributions
            )
            if has_dataflow:
                context_score = sum(nlargest(2, causal))
            else:
                context_score = max(
                    (score for score, *_ in contributions),
                    default=0.0,
                )
        else:
            contextual_scores = [
                score
                for score, kind, name in contributions
                if kind == "event" and name in V6_CONTEXT_ONLY_OPS
            ]
            retained = [
                score
                for score, kind, name in contributions
                if not (kind == "event" and name in V6_CONTEXT_ONLY_OPS)
            ]
            if contextual_scores:
                retained.append(max(contextual_scores))
            context_score = sum(nlargest(4, retained))
        maximum = max(maximum, context_score)
    return min(100.0, maximum)


def _causal_contributions(
    items: list[_ContextEvidence],
) -> list[tuple[float, str, str]]:
    event_scores = {
        item.event_key: item.evidence.score
        for item in items
        if item.event_key is not None
    }
    event_groups: dict[tuple[str, ...], _EventGroup] = {}
    path_groups: dict[tuple[str, ...], _PathGroup] = {}
    for item in items:
        if item.dedup_key[0] == "event":
            group = event_groups.setdefault(item.dedup_key, _EventGroup())
            group.score = max(group.score, item.evidence.score)
            if item.event_key is not None:
                group.event_keys.add(item.event_key)
            continue
        group = path_groups.setdefault(item.dedup_key, _PathGroup())
        group.score = max(group.score, item.evidence.score)
        group.covered.update(item.covered_event_keys)
        if item.evidence.evidence_kind in {"dataflow", "summary", "structural"}:
            group.high_confidence = True

    exact_motifs = {
        key[1]
        for key in path_groups
        if len(key) > 2 and key[2] in {"dataflow", "summary"}
    }
    covered: set[tuple[str, int]] = set()
    output: list[tuple[float, str, str]] = []
    for key, group in path_groups.items():
        motif = key[1]
        evidence_kind = key[2] if len(key) > 2 else ""
        if evidence_kind == "proximity" and motif in exact_motifs:
            covered.update(group.covered)
            continue
        covered_scores = [
            event_scores[event_key]
            for event_key in group.covered
            if event_key in event_scores
        ]
        strongest_event = max(covered_scores, default=0.0)
        covered.update(group.covered)
        if evidence_kind == "proximity":
            score = strongest_event + group.score
            output.append((score, "proximity", motif))
            continue
        if evidence_kind == "structural" and motif == "destructive_file_action":
            score = strongest_event or group.score
        else:
            score = max(group.score, strongest_event)
        output.append((score, evidence_kind or "path", motif))

    for key, group in event_groups.items():
        if not group.event_keys or any(
            event_key not in covered for event_key in group.event_keys
        ):
            output.append((group.score, "event", key[1]))
    return output


def _model_tokens(files: list[FileAnalysis]) -> list[str]:
    """Build a bounded semantic sequence that repeated syntax cannot flood."""
    tokens: list[str] = []
    seen: set[tuple[str, ...]] = set()
    for item in files:
        file_tokens: list[str] = []
        for event in item.events:
            token = model_event_token(event)
            key = ("event", token)
            if key in seen:
                continue
            seen.add(key)
            file_tokens.append(token)
        for path in item.behavior_paths:
            token = path.token()
            key = ("path", token)
            if key in seen:
                continue
            seen.add(key)
            file_tokens.append(token)
        for token in item.effect_summary.tokens:
            key = ("effect", token)
            if key in seen:
                continue
            seen.add(key)
            file_tokens.append(token)
        if file_tokens:
            tokens.append("FILE")
            tokens.extend(file_tokens)
    return tokens


def _is_auxiliary_path(path: str) -> bool:
    normalized = path.lower().replace("\\", "/")
    parts = normalized.split("/")
    filename = parts[-1] if parts else normalized
    if any(part in AUXILIARY_PATH_SEGMENTS for part in parts[:-1]):
        return True
    return (
        filename == "conftest.py"
        or filename.startswith("test_")
        or filename.endswith("_test.py")
    )


def _is_orchestration_path(path: str) -> bool:
    if _is_auxiliary_path(path):
        return True
    normalized = path.lower().replace("\\", "/")
    parts = normalized.split("/")
    filename = parts[-1] if parts else normalized
    if any(part in {"scripts", "script", "action", "actions"} for part in parts[:-1]):
        return True
    return filename in {"setup.py", "configure.py"}


def _verdict(score: float) -> str:
    if score >= 75.0:
        return "high-risk"
    if score >= 50.0:
        return "suspicious"
    if score >= 25.0:
        return "review"
    return "low-signal"
