import pytest

from malir.detector import CascadeConfig, decide
from malir.types import BehaviorPath, Event, FileAnalysis


def _event(
    op: str,
    line: int,
    function: str = "scan",
    path: str = "pkg.py",
) -> Event:
    return Event(
        op=op,
        category="sink",
        target="x",
        path=path,
        line=line,
        column=0,
        function=function,
        phase="runtime",
        detail=op.lower(),
    )


def _analysis(
    events: list[Event],
    paths: list[BehaviorPath] | None = None,
    path: str = "pkg.py",
) -> FileAnalysis:
    return FileAnalysis(
        path=path,
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


def test_context_cover_replaces_structural_events_instead_of_double_counting():
    analysis = _analysis(
        [_event("DYNAMIC_EXEC", 1), _event("FILE_DELETE", 2)],
        [
            BehaviorPath(
                motif="install_time_execution",
                score=30.0,
                reason="install execution",
                event_indexes=(0,),
                evidence_kind="structural",
                confidence="high",
            ),
            BehaviorPath(
                motif="destructive_file_action",
                score=18.0,
                reason="delete",
                event_indexes=(1,),
                evidence_kind="structural",
                confidence="high",
            ),
        ],
    )
    result = decide(
        [analysis], config=CascadeConfig(rule_aggregation="context-cover-v2")
    )
    assert result.rule_score == 48.0


def test_context_cover_exact_dataflow_summarizes_constituent_events():
    analysis = _analysis(
        [_event("ENV_READ", 1), _event("NETWORK_SEND", 2)],
        [
            BehaviorPath(
                motif="credential_or_file_exfil",
                score=36.0,
                reason="exact exfiltration",
                event_indexes=(0, 1),
                evidence_kind="dataflow",
                confidence="high",
            )
        ],
    )
    result = decide(
        [analysis], config=CascadeConfig(rule_aggregation="context-cover-v2")
    )
    assert result.rule_score == 36.0


def test_context_cover_proximity_does_not_suppress_event_evidence():
    analysis = _analysis(
        [_event("ENV_READ", 1), _event("NETWORK_SEND", 2)],
        [
            BehaviorPath(
                motif="credential_or_file_exfil",
                score=2.0,
                reason="nearby only",
                event_indexes=(0, 1),
                evidence_kind="proximity",
                confidence="low",
            )
        ],
    )
    result = decide(
        [analysis], config=CascadeConfig(rule_aggregation="context-cover-v2")
    )
    assert result.rule_score == 24.0


def test_context_cover_keeps_uncovered_occurrence_of_same_operation():
    analysis = _analysis(
        [_event("DYNAMIC_EXEC", 1), _event("DYNAMIC_EXEC", 2)],
        [
            BehaviorPath(
                motif="install_time_execution",
                score=30.0,
                reason="one covered exec",
                event_indexes=(0,),
                evidence_kind="structural",
                confidence="high",
            )
        ],
    )
    result = decide(
        [analysis], config=CascadeConfig(rule_aggregation="context-cover-v2")
    )
    assert result.rule_score == 57.0


def test_context_causal_v6_does_not_stack_unlinked_deserialization_and_exec():
    analysis = _analysis(
        [
            _event("PROCESS_EXEC", 1),
            _event("UNSAFE_DESERIALIZE", 2),
            _event("ENV_READ", 3),
            _event("FILE_WRITE", 4),
        ]
    )
    result = decide(
        [analysis], config=CascadeConfig(rule_aggregation="context-causal-v6")
    )
    assert result.rule_score == 35.0


def test_context_causal_v6_keeps_sensitive_and_remote_sources_additive():
    analysis = _analysis(
        [
            _event("PROCESS_EXEC", 1),
            _event("SENSITIVE_FILE_READ", 2),
            _event("NETWORK_RECEIVE", 3),
            _event("ENV_READ", 4),
        ]
    )
    result = decide(
        [analysis], config=CascadeConfig(rule_aggregation="context-causal-v6")
    )
    assert result.rule_score == 44.0


def test_context_causal_v6_preserves_deserialization_when_it_forms_a_path():
    analysis = _analysis(
        [_event("UNSAFE_DESERIALIZE", 1), _event("DYNAMIC_EXEC", 2)],
        [
            BehaviorPath(
                motif="encoded_execution",
                score=40.0,
                reason="exact flow",
                event_indexes=(0, 1),
                evidence_kind="dataflow",
                confidence="high",
            )
        ],
    )
    result = decide(
        [analysis], config=CascadeConfig(rule_aggregation="context-causal-v6")
    )
    assert result.rule_score == 40.0


def test_context_causal_v6_exact_motif_dominates_weak_same_motif_paths():
    analysis = _analysis(
        [
            _event("NETWORK_RECEIVE", 1),
            _event("PROCESS_EXEC", 2),
            _event("PROCESS_EXEC", 3),
        ],
        [
            BehaviorPath(
                motif="download_execute",
                score=42.0,
                reason="exact staged execution",
                event_indexes=(0, 1),
                evidence_kind="dataflow",
                confidence="high",
            ),
            BehaviorPath(
                motif="download_execute",
                score=4.0,
                reason="nearby process only",
                event_indexes=(0, 2),
                evidence_kind="proximity",
                confidence="low",
            ),
        ],
    )
    result = decide(
        [analysis], config=CascadeConfig(rule_aggregation="context-causal-v6")
    )
    assert result.rule_score == 42.0


def test_context_cover_summary_summarizes_constituent_events():
    analysis = _analysis(
        [_event("ENV_READ", 1), _event("NETWORK_SEND", 2)],
        [
            BehaviorPath(
                motif="credential_or_file_exfil",
                score=36.0,
                reason="bounded direct-call summary",
                event_indexes=(0, 1),
                evidence_kind="summary",
                confidence="medium",
            )
        ],
    )
    result = decide(
        [analysis], config=CascadeConfig(rule_aggregation="context-cover-v2")
    )
    assert result.rule_score == 36.0


def test_context_causal_v6_summary_suppresses_weak_same_motif_path():
    analysis = _analysis(
        [_event("ENV_READ", 1), _event("NETWORK_SEND", 2)],
        [
            BehaviorPath(
                motif="credential_or_file_exfil",
                score=36.0,
                reason="bounded direct-call summary",
                event_indexes=(0, 1),
                evidence_kind="summary",
                confidence="medium",
            ),
            BehaviorPath(
                motif="credential_or_file_exfil",
                score=2.0,
                reason="nearby only",
                event_indexes=(0, 1),
                evidence_kind="proximity",
                confidence="low",
            ),
        ],
    )
    result = decide(
        [analysis], config=CascadeConfig(rule_aggregation="context-causal-v6")
    )
    assert result.rule_score == 36.0


def test_legacy_summary_does_not_stack_its_constituent_events():
    analysis = _analysis(
        [_event("ENV_READ", 1), _event("NETWORK_SEND", 2)],
        [
            BehaviorPath(
                motif="credential_or_file_exfil",
                score=36.0,
                reason="bounded direct-call summary",
                event_indexes=(0, 1),
                evidence_kind="summary",
                confidence="medium",
            )
        ],
    )

    assert decide([analysis]).rule_score == 36.0
