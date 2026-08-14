import pytest

from malir.support import assess_model_support, build_support_profile


def _profile():
    return build_support_profile(
        [
            ["FILE", "O:FILE_READ", "EFFECT:ORIGIN:local_file"],
            ["FILE", "O:NETWORK_SEND", "EFFECT:DESTINATION:network"],
        ],
        ["local", "network"],
        min_nearest_jaccard=0.2,
    )


def test_support_profile_accepts_known_nearby_behavior():
    result = assess_model_support(
        ["FILE", "O:FILE_READ", "EFFECT:ORIGIN:local_file"],
        _profile(),
    )

    assert result.supported is True
    assert result.abstained is False
    assert result.token_coverage == 1.0
    assert result.nearest_similarity == 1.0


def test_support_profile_rejects_unknown_semantics():
    result = assess_model_support(
        ["FILE", "O:CAMERA_READ", "EFFECT:ORIGIN:camera"],
        _profile(),
    )

    assert result.supported is False
    assert result.abstained is True
    assert result.token_coverage == pytest.approx(1 / 3)
    assert result.unknown_tokens == (
        "EFFECT:ORIGIN:camera",
        "O:CAMERA_READ",
    )


def test_support_profile_rejects_unseen_composition_of_known_tokens():
    profile = build_support_profile(
        [["A", "B"], ["C", "D"]],
        ["first", "second"],
        min_nearest_jaccard=0.5,
    )
    result = assess_model_support(["A", "C"], profile)

    assert result.token_coverage == 1.0
    assert result.nearest_similarity == pytest.approx(1 / 3)
    assert result.supported is False
