import json

import pytest

from malir.data import load_examples
from malir.model_tokens import canonicalize_model_tokens


def test_dataset_path_cannot_escape_manifest_directory(tmp_path):
    dataset_dir = tmp_path / "dataset"
    dataset_dir.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("print('not executed')", encoding="utf-8")
    manifest = dataset_dir / "samples.jsonl"
    rows = [
        {"label": 1, "tokens": ["O:DYNAMIC_EXEC"]},
        {"label": 0, "path": "../outside.py"},
    ]
    manifest.write_text(
        "\n".join(json.dumps(row) for row in rows),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="escapes"):
        load_examples(manifest)


def test_inline_dataset_accepts_both_classes(tmp_path):
    manifest = tmp_path / "samples.jsonl"
    rows = [
        {"label": "malicious", "tokens": ["O:DYNAMIC_EXEC"]},
        {"label": "benign", "source": "value = 1"},
    ]
    manifest.write_text(
        "\n".join(json.dumps(row) for row in rows),
        encoding="utf-8",
    )
    examples = load_examples(manifest)
    assert [label for _, label in examples] == [1, 0]


def test_model_tokens_normalize_concrete_targets_and_filenames():
    first = canonicalize_model_tokens(
        [
            "FILE:one.py",
            "P:runtime|C:sink|O:NETWORK_SEND|T:https://one.invalid/upload",
        ]
    )
    second = canonicalize_model_tokens(
        [
            "FILE:renamed.py",
            "P:runtime|C:sink|O:NETWORK_SEND|T:https://two.invalid/post",
        ]
    )

    assert first == second
    assert first[0] == "FILE"
    assert "P:runtime|C:sink|O:NETWORK_SEND|T:network" in first
    assert "EFFECT:ENTRY:library_callable" in first
    assert "EFFECT:DESTINATION:network" in first

    tokenizer = canonicalize_model_tokens(
        [
            "P:runtime|C:source|O:FILE_READ|T:tokenizer.py",
            "P:import|C:context|O:IMPORT|T:tokenizer",
        ]
    )
    assert "P:runtime|C:source|O:FILE_READ|T:file" in tokenizer
    assert "P:import|C:context|O:IMPORT|T:generic" in tokenizer
    assert not any(token.endswith("T:sensitive") for token in tokenizer)
