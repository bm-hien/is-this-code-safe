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


def test_file_write_content_is_not_treated_as_destination_path():
    source = (
        "def render(handle):\n    handle.write('.. toctree::\\n   :maxdepth: 1\\n')\n"
    )
    result = PythonExtractor().analyze_source(source)
    writes = [event for event in result.events if event.op == "FILE_WRITE"]
    assert len(writes) == 1
    assert writes[0].target.endswith(".write")
    assert "PERSISTENCE_WRITE" not in [event.op for event in result.events]


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


def test_explicit_builtins_compile_remains_dynamic_execution():
    source = (
        "import builtins\n"
        "def run(value):\n"
        "    return builtins.compile(value, '<value>', 'exec')\n"
    )
    result = PythonExtractor().analyze_source(source)
    assert "DYNAMIC_EXEC" in [event.op for event in result.events]
