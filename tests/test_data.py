import json

import pytest

from malir.data import load_examples, load_training_dataset
from malir.model_tokens import canonicalize_model_tokens
from malir.support import assess_model_support, build_support_profile


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


def test_v3_training_dataset_adds_paired_effect_roles():
    dataset = load_training_dataset("examples/micro_train_v3.jsonl")

    assert len(dataset.train) == 72
    assert len(dataset.validation) == 36
    assert len({row.group_id for row in dataset.train}) == 24
    assert len({row.group_id for row in dataset.validation}) == 12
    assert len({row.pair_id for row in dataset.train if row.pair_id}) == 7
    assert len({row.pair_id for row in dataset.validation if row.pair_id}) == 6
    assert sum(row.pair_id is not None for row in dataset.all_examples) == 78
    assert any(
        "PATH:file_to_network|K:dataflow|Q:high" in row.tokens
        for row in dataset.train
        if row.label == 0
    )

    profile = build_support_profile(
        (row.tokens for row in dataset.train),
        (row.group_id for row in dataset.train),
    )
    assert all(
        assess_model_support(row.tokens, profile).supported
        for row in dataset.validation
    )
    obfuscator_context = [
        "FILE",
        "P:runtime|C:context|O:IMPORT|T:generic",
        "P:import|C:source|O:ENV_READ|T:generic",
        "P:import|C:sink|O:DYNAMIC_EXEC|T:generic",
        "EFFECT:ENTRY:import_time_effects",
        "EFFECT:FLOW:local_file_to_local_artifact",
        "EFFECT:TRANSFORM:code_generation",
    ]
    assert assess_model_support(obfuscator_context, profile).supported

    with open("examples/micro_ood_v3.jsonl", encoding="utf-8") as handle:
        probes = [json.loads(line) for line in handle if line.strip()]
    assert all(
        assess_model_support(probe["tokens"], profile).abstained for probe in probes
    )


def test_2026_08_15_dataset_preserves_causal_evidence_strength():
    dataset = load_training_dataset("examples/micro_train_2026_08_15.jsonl")

    assert len(dataset.train) == 78
    assert len(dataset.validation) == 42
    assert len({row.group_id for row in dataset.train}) == 26
    assert len({row.group_id for row in dataset.validation}) == 14
    negative = next(
        row
        for row in dataset.train
        if row.group_id == "train-unlinked-secret-telemetry-2026-08-15"
        and row.sample_id.endswith("--base")
    )
    positive = next(
        row
        for row in dataset.train
        if row.group_id == "train-exact-secret-exfil-2026-08-15"
        and row.sample_id.endswith("--base")
    )
    assert "PATH:credential_or_file_exfil|K:proximity|Q:low" in negative.tokens
    assert "EFFECT:FLOW:sensitive_data_to_network" not in negative.tokens
    assert "PATH:credential_or_file_exfil|K:dataflow|Q:high" in positive.tokens
    assert "EFFECT:FLOW:sensitive_data_to_network" in positive.tokens
    assert negative.representation_hash != positive.representation_hash


def test_2026_08_15_r2_dataset_adds_delete_context_pairs():
    dataset = load_training_dataset("examples/micro_train_2026_08_15_r2.jsonl")

    assert len(dataset.train) == 84
    assert len(dataset.validation) == 48
    assert len({row.group_id for row in dataset.train}) == 28
    assert len({row.group_id for row in dataset.validation}) == 16
    cleanup = next(
        row
        for row in dataset.train
        if row.group_id == "train-temporary-cleanup-2026-08-15-r2"
        and row.sample_id.endswith("--base")
    )
    destructive = next(
        row
        for row in dataset.train
        if row.group_id == "train-destructive-delete-2026-08-15-r2"
        and row.sample_id.endswith("--base")
    )
    assert "P:runtime|C:sink|O:FILE_DELETE|T:delete_temporary" in cleanup.tokens
    assert not any(
        token.startswith("PATH:destructive_file_action") for token in cleanup.tokens
    )
    assert "P:runtime|C:sink|O:FILE_DELETE|T:delete_user_data" in destructive.tokens
    assert "PATH:destructive_file_action|K:structural|Q:high" in destructive.tokens
    assert cleanup.representation_hash != destructive.representation_hash


def test_source_path_controls_lifecycle_for_source_training_rows(tmp_path):
    manifest = tmp_path / "samples.jsonl"
    rows = [
        {
            "sample_id": "install-negative",
            "group_id": "install-negative",
            "split": "train",
            "role": "compiler",
            "label": 0,
            "source": "os.system('gcc --version')",
            "source_path": "setup.py",
        },
        {
            "sample_id": "install-positive",
            "group_id": "install-positive",
            "split": "train",
            "role": "shell",
            "label": 1,
            "source": "os.system('sh payload.sh')",
            "source_path": "setup.py",
        },
        {
            "sample_id": "validation-negative",
            "group_id": "validation-negative",
            "split": "validation",
            "role": "compiler",
            "label": 0,
            "source": "platform.platform(); subprocess.run(['/usr/bin/clang'])",
            "source_path": "setup.py",
        },
        {
            "sample_id": "validation-positive",
            "group_id": "validation-positive",
            "split": "validation",
            "role": "shell",
            "label": 1,
            "source": "platform.platform(); subprocess.run(['sh', 'payload.sh'])",
            "source_path": "setup.py",
        },
    ]
    manifest.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    dataset = load_training_dataset(manifest)
    assert (
        "P:install|C:sink|O:PROCESS_EXEC|T:process_compiler" in dataset.train[0].tokens
    )
    assert "P:install|C:sink|O:PROCESS_EXEC|T:process_shell" in dataset.train[1].tokens


def test_2026_08_15_r3_dataset_adds_install_process_pairs():
    dataset = load_training_dataset("examples/micro_train_2026_08_15_r3.jsonl")
    assert len(dataset.train) == 90
    assert len(dataset.validation) == 54
    assert len({row.group_id for row in dataset.train}) == 30
    assert len({row.group_id for row in dataset.validation}) == 18
    compiler = next(
        row
        for row in dataset.train
        if row.group_id == "train-install-compiler-2026-08-15-r3"
        and row.sample_id.endswith("--base")
    )
    shell = next(
        row
        for row in dataset.train
        if row.group_id == "train-install-shell-2026-08-15-r3"
        and row.sample_id.endswith("--base")
    )
    assert "P:install|C:sink|O:PROCESS_EXEC|T:process_compiler" in compiler.tokens
    assert "P:install|C:sink|O:PROCESS_EXEC|T:process_shell" in shell.tokens
    assert compiler.representation_hash != shell.representation_hash


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
