from malir.model import OnlineLogisticModel

NEGATIVE = [
    ["O:IMPORT", "O:FILE_READ", "MOTIF:configuration_read"],
    ["O:IMPORT", "O:ENCODE", "O:FILE_WRITE"],
]
POSITIVE = [
    ["O:ENV_READ", "O:ENCODE", "O:NETWORK_SEND"],
    ["O:NETWORK_RECEIVE", "O:DECODE", "O:DYNAMIC_EXEC"],
]


def test_online_model_learns_and_round_trips(tmp_path):
    examples = [(tokens, 0) for tokens in NEGATIVE]
    examples += [(tokens, 1) for tokens in POSITIVE]
    model = OnlineLogisticModel(dimensions=4096, learning_rate=0.4)
    losses = model.partial_fit(examples, epochs=80, seed=7)
    assert losses[-1] < losses[0]
    assert min(model.predict_proba(item) for item in POSITIVE) > max(
        model.predict_proba(item) for item in NEGATIVE
    )

    checkpoint = tmp_path / "sparse.model.json"
    model.save(checkpoint)
    loaded = OnlineLogisticModel.load(checkpoint)
    assert loaded.predict_proba(POSITIVE[0]) == model.predict_proba(POSITIVE[0])
