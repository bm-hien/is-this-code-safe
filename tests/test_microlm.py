import pytest

torch = pytest.importorskip("torch")

from malir.microlm import HashedTokenizer, MicroConfig, MicroMalPredictor, train_micro


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
