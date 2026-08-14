import json

import pytest

from malir.data import load_examples, load_training_dataset
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


def test_v2_training_dataset_is_group_and_representation_disjoint():
    dataset = load_training_dataset("examples/micro_train_v2.jsonl")

    assert len(dataset.train) == 60
    assert len(dataset.validation) == 30
    assert len(load_examples("examples/micro_train_v2.jsonl")) == 60
    assert len({row.group_id for row in dataset.train}) == 20
    assert len({row.group_id for row in dataset.validation}) == 10
    assert {row.group_id for row in dataset.train}.isdisjoint(
        {row.group_id for row in dataset.validation}
    )
    assert {row.representation_hash for row in dataset.train}.isdisjoint(
        {row.representation_hash for row in dataset.validation}
    )
    assert len(dataset.dataset_sha256) == 64
    assert len(dataset.split_fingerprint) == 64


def test_training_dataset_rejects_group_leakage(tmp_path):
    manifest = tmp_path / "leaked.jsonl"
    rows = [
        {
            "sample_id": "train-negative",
            "group_id": "shared",
            "split": "train",
            "label": 0,
            "tokens": ["O:FILE_READ"],
        },
        {
            "sample_id": "train-positive",
            "group_id": "positive-train",
            "split": "train",
            "label": 1,
            "tokens": ["O:DYNAMIC_EXEC"],
        },
        {
            "sample_id": "validation-negative",
            "group_id": "shared",
            "split": "validation",
            "label": 0,
            "tokens": ["O:FILE_WRITE"],
        },
        {
            "sample_id": "validation-positive",
            "group_id": "positive-validation",
            "split": "validation",
            "label": 1,
            "tokens": ["O:NETWORK_SEND"],
        },
    ]
    manifest.write_text(
        "\n".join(json.dumps(row) for row in rows),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="group_id crosses"):
        load_training_dataset(manifest)
