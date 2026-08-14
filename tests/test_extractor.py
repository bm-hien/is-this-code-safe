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
    assert "PURPOSE:local_code_transformer" in summary.tokens


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
