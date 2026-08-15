import pytest

torch = pytest.importorskip("torch")

from malir.microlm import HashedTokenizer, MicroConfig, MicroMalPredictor, train_micro
from malir.support import build_support_profile


def test_micro_model_trains_saves_and_loads(tmp_path):
    examples = [
        (["O:FILE_READ", "O:PARSE"], 0),
        (["O:IMPORT", "O:FILE_WRITE"], 0),
        (["O:ENV_READ", "O:NETWORK_SEND"], 1),
        (["O:DECODE", "O:DYNAMIC_EXEC"], 1),
    ]
    checkpoint = tmp_path / "micro.pt"
    result = train_micro(
        examples,
        checkpoint,
        config=MicroConfig(
            vocab_size=128,
            max_length=16,
            d_model=16,
            n_heads=2,
            n_layers=1,
            ffn_dim=32,
            dropout=0.0,
        ),
        epochs=1,
        batch_size=4,
        threads=1,
    )
    predictor = MicroMalPredictor.load(checkpoint, threads=1)
    probability = predictor.predict_proba(["O:ENV_READ", "O:NETWORK_SEND"])
    assert checkpoint.exists()
    assert result["parameters"] < 10_000
    assert 0.0 <= probability <= 1.0


def test_tokenizer_windows_cover_tokens_beyond_the_first_context():
    tokenizer = HashedTokenizer(
        MicroConfig(
            vocab_size=128,
            max_length=8,
            d_model=16,
            n_heads=2,
            n_layers=1,
            ffn_dim=32,
            dropout=0.0,
        )
    )
    tokens = [f"token-{index}" for index in range(15)]
    windows = tokenizer.encode_windows(tokens, overlap=2)

    tail_id = tokenizer.encode([tokens[-1]])[0][1]
    last_ids, last_mask = windows[-1]
    assert len(windows) == 4
    assert last_ids[sum(last_mask) - 2] == tail_id


def test_micro_checkpoint_schema_is_checked(tmp_path):
    checkpoint = tmp_path / "invalid.pt"
    torch.save({"schema": "unknown"}, checkpoint)
    with pytest.raises(ValueError, match="schema"):
        MicroMalPredictor.load(checkpoint, threads=1)


def test_micro_config_rejects_oversized_shapes():
    with pytest.raises(ValueError, match="vocab_size"):
        MicroConfig(vocab_size=1_000_000).validate()


def test_micro_training_uses_disjoint_validation_for_calibration(tmp_path):
    training = [
        (["O:FILE_READ", "O:FILE_WRITE"], 0),
        (["O:NETWORK_RECEIVE", "O:FILE_WRITE"], 0),
        (["O:ENV_READ", "O:NETWORK_SEND"], 1),
        (["O:NETWORK_RECEIVE", "O:DYNAMIC_EXEC"], 1),
    ]
    validation = [
        (["O:FILE_READ", "O:ENCODE", "O:FILE_WRITE"], 0),
        (["O:SYSTEM_DISCOVERY", "O:FILE_WRITE"], 0),
        (["O:SENSITIVE_FILE_READ", "O:NETWORK_SEND"], 1),
        (["O:DECODE", "O:PROCESS_EXEC"], 1),
    ]
    checkpoint = tmp_path / "calibrated.pt"
    result = train_micro(
        training,
        checkpoint,
        config=MicroConfig(
            vocab_size=128,
            max_length=16,
            d_model=16,
            n_heads=2,
            n_layers=1,
            ffn_dim=32,
            dropout=0.0,
        ),
        validation_examples=validation,
        epochs=3,
        minimum_epochs=1,
        patience=1,
        batch_size=4,
        mlm_weight=0.0,
        threads=1,
    )

    stored = torch.load(checkpoint, map_location="cpu", weights_only=True)
    predictor = MicroMalPredictor.load(checkpoint, threads=1)
    assert result["validation_examples"] == 4
    assert result["validation_metrics"] is not None
    assert result["temperature"] >= 1.0
    assert stored["metadata"]["calibration"] == "temperature-scaled-validation"
    assert predictor.temperature == result["temperature"]


def test_micro_training_records_paired_semantic_metrics_and_support(tmp_path):
    training = [
        (["FILE", "O:FILE_READ"], 0),
        (["FILE", "O:FILE_READ", "EFFECT:ENTRY:explicit_cli"], 0),
        (["FILE", "O:NETWORK_SEND"], 1),
        (["FILE", "O:NETWORK_SEND", "EFFECT:ENTRY:explicit_cli"], 1),
    ]
    profile = build_support_profile(
        (tokens for tokens, _label in training),
        ["negative", "negative", "positive", "positive"],
    )
    checkpoint = tmp_path / "structured.pt"
    result = train_micro(
        training,
        checkpoint,
        config=MicroConfig(
            vocab_size=128,
            max_length=16,
            d_model=16,
            n_heads=2,
            n_layers=1,
            ffn_dim=32,
            dropout=0.0,
        ),
        validation_examples=training,
        pair_constraints=[(0, 2), (1, 3)],
        validation_pair_constraints=[(0, 2), (1, 3)],
        consistency_groups=[[0, 1], [2, 3]],
        validation_consistency_groups=[[0, 1], [2, 3]],
        checkpoint_metadata={
            "feature_schema": "malir.effect-context.v3",
            "support_profile": profile,
        },
        epochs=2,
        batch_size=4,
        mlm_weight=0.0,
        threads=1,
    )

    predictor = MicroMalPredictor.load(checkpoint, threads=1)
    known = predictor.predict_details(["FILE", "O:FILE_READ"])
    unknown = predictor.predict_details(["FILE", "O:CAMERA_READ"])
    assert result["pair_constraints"] == 2
    assert "pair_ordering_accuracy" in result["validation_metrics"]
    assert "semantic_variant_drift_max" in result["validation_metrics"]
    assert known["supported"] is True
    assert unknown["abstained"] is True


def test_micro_training_records_optional_positive_class_weight(tmp_path):
    examples = [
        (["FILE", "O:FILE_READ"], 0),
        (["FILE", "O:FILE_WRITE"], 0),
        (["FILE", "O:NETWORK_SEND"], 1),
    ]
    checkpoint = tmp_path / "weighted.pt"
    train_micro(
        examples,
        checkpoint,
        config=MicroConfig(
            vocab_size=128,
            max_length=16,
            d_model=16,
            n_heads=2,
            n_layers=1,
            ffn_dim=32,
            dropout=0.0,
        ),
        positive_class_weight=2.0,
        epochs=1,
        batch_size=3,
        mlm_weight=0.0,
        threads=1,
    )
    stored = torch.load(checkpoint, map_location="cpu", weights_only=True)
    assert stored["metadata"]["positive_class_weight"] == 2.0

    with pytest.raises(ValueError, match="positive_class_weight"):
        train_micro(examples, tmp_path / "invalid-weight.pt", positive_class_weight=0)
