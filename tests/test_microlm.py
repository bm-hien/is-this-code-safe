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
