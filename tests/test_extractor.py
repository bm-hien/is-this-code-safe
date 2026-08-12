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
