import pytest

from malir.detector import CascadeConfig, decide
from malir.types import BehaviorPath, Event, FileAnalysis


def _event(op: str, line: int, function: str = "scan") -> Event:
    return Event(
        op=op,
        category="sink",
        target="x",
        path="pkg.py",
        line=line,
        column=0,
        function=function,
        phase="runtime",
        detail=op.lower(),
    )


def _analysis(
    events: list[Event],
    paths: list[BehaviorPath] | None = None,
) -> FileAnalysis:
    return FileAnalysis(
        path="pkg.py",
        sha256="0" * 64,
        bytes_read=1,
        events=events,
        behavior_paths=paths or [],
    )


def test_context_max_deduplicates_and_does_not_sum_functions():
    events = [
        _event("SENSITIVE_FILE_READ", 1, "upload"),
        _event("SENSITIVE_FILE_READ", 2, "upload"),
        _event("NETWORK_SEND", 3, "upload"),
        _event("ENCODE", 4, "upload"),
        _event("DYNAMIC_EXEC", 20, "runner"),
        _event("PROCESS_EXEC", 21, "runner"),
    ]
    paths = [
        BehaviorPath(
            motif="credential_or_file_exfil",
            score=36.0,
            reason="exact exfiltration flow",
            event_indexes=(0, 2),
            evidence_kind="dataflow",
            confidence="high",
        ),
        BehaviorPath(
            motif="credential_or_file_exfil",
            score=36.0,
            reason="duplicate exact flow",
            event_indexes=(1, 2),
            evidence_kind="dataflow",
            confidence="high",
        ),
    ]
    analysis = _analysis(events, paths)

    legacy = decide([analysis])
    candidate = decide(
        [analysis],
        config=CascadeConfig(rule_aggregation="context-max-v1"),
    )

    assert legacy.rule_score == 100.0
    assert candidate.rule_score == 67.0
    assert candidate.verdict == "suspicious"
    assert len(candidate.evidence) == 8


def test_context_max_uses_maximum_context_instead_of_package_sum():
    analysis = _analysis(
        [
            _event("DYNAMIC_EXEC", 1, "first"),
            _event("DYNAMIC_EXEC", 2, "second"),
        ]
    )

    assert decide([analysis]).rule_score == 54.0
    assert (
        decide(
            [analysis],
            config=CascadeConfig(rule_aggregation="context-max-v1"),
        ).rule_score
        == 27.0
    )


def test_context_max_empty_analysis_scores_zero():
    result = decide(
        [_analysis([])],
        config=CascadeConfig(rule_aggregation="context-max-v1"),
    )
    assert result.rule_score == 0.0
    assert result.verdict == "low-signal"


def test_unknown_rule_aggregation_is_rejected():
    with pytest.raises(ValueError, match="unsupported rule aggregation"):
        decide(
            [_analysis([])],
            config=CascadeConfig(rule_aggregation="unknown"),  # type: ignore[arg-type]
        )
