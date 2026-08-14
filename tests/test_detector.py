import pytest

from malir.detector import CascadeConfig, decide
from malir.types import BehaviorPath, Event, FileAnalysis


def _event(
    op: str,
    line: int,
    function: str = "scan",
    path: str = "pkg.py",
    target: str = "x",
) -> Event:
    return Event(
        op=op,
        category="sink",
        target=target,
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


class _RecordingModel:
    def __init__(self, probability: float = 0.9) -> None:
        self.probability = probability
        self.calls: list[list[str]] = []

    def predict_proba(self, tokens: list[str]) -> float:
        self.calls.append(tokens)
        return self.probability


def _repeated_exfil_analysis(repeats: int) -> FileAnalysis:
    events = [
        _event("ENV_READ", 1, target="CI_TOKEN"),
        _event("ENCODE", 2, target="base64.b64encode"),
        *[
            _event(
                "NETWORK_SEND",
                3 + index,
                target=f"https://collector{index}.invalid/upload",
            )
            for index in range(repeats)
        ],
    ]
    paths = [
        BehaviorPath(
            motif="credential_or_file_exfil",
            score=2.0,
            reason="nearby only",
            event_indexes=(0, 2 + index),
            evidence_kind="proximity",
            confidence="low",
        )
        for index in range(repeats)
    ]
    return _analysis(events, paths)


def test_semantic_default_is_invariant_to_repeated_sink_spam():
    single = decide([_repeated_exfil_analysis(1)])
    spammed = decide([_repeated_exfil_analysis(20)])

    assert single.rule_score == 28.0
    assert spammed.rule_score == single.rule_score
    assert len(spammed.evidence) == 4
    assert (
        next(item for item in spammed.evidence if item.op == "NETWORK_SEND").occurrences
        == 20
    )
    assert (
        next(
            item
            for item in spammed.evidence
            if item.motif == "credential_or_file_exfil"
        ).occurrences
        == 20
    )


def test_model_input_is_semantically_compacted_before_inference():
    single_model = _RecordingModel()
    spam_model = _RecordingModel()
    single = decide([_repeated_exfil_analysis(1)], single_model)
    spammed = decide([_repeated_exfil_analysis(20)], spam_model)

    assert single_model.calls == spam_model.calls
    assert spammed.risk_score == pytest.approx(single.risk_score)
    assert spammed.model_consulted is True
    assert spammed.model_used is True


def test_model_is_consulted_but_advisory_outside_decision_gate():
    model = _RecordingModel(probability=0.99)
    result = decide([_analysis([])], model)

    assert model.calls == [[]]
    assert result.model_probability == 0.99
    assert result.model_consulted is True
    assert result.model_used is False
    assert result.risk_score == 0.0


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

    legacy = decide(
        [analysis],
        config=CascadeConfig(rule_aggregation="legacy-top8"),
    )
    candidate = decide(
        [analysis],
        config=CascadeConfig(rule_aggregation="context-max-v1"),
    )

    assert legacy.rule_score == 100.0
    assert candidate.rule_score == 67.0
    assert candidate.verdict == "suspicious"
    assert len(candidate.evidence) == 6
    assert (
        next(
            item for item in candidate.evidence if item.op == "SENSITIVE_FILE_READ"
        ).occurrences
        == 2
    )


def test_context_max_uses_maximum_context_instead_of_package_sum():
    analysis = _analysis(
        [
            _event("DYNAMIC_EXEC", 1, "first"),
            _event("DYNAMIC_EXEC", 2, "second"),
        ]
    )

    assert (
        decide(
            [analysis],
            config=CascadeConfig(rule_aggregation="legacy-top8"),
        ).rule_score
        == 54.0
    )
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

    assert (
        decide(
            [analysis],
            config=CascadeConfig(rule_aggregation="legacy-top8"),
        ).rule_score
        == 36.0
    )
