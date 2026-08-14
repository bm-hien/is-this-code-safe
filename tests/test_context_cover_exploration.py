from pathlib import Path

import pytest

from scripts.explore_context_cover import _operating_points, _score_omc, _score_pypi


def test_exploration_refuses_pypi_holdout_before_file_access():
    with pytest.raises(ValueError, match="non-development"):
        _score_pypi({"split": "holdout"}, Path("/does/not/matter"))


def test_exploration_refuses_omcbench_test_before_file_access():
    with pytest.raises(ValueError, match="non-validation"):
        _score_omc({"split": "test"}, Path("/does/not/matter"))


def test_operating_points_use_group_maxima_and_separate_system_thresholds():
    pypi = [
        {
            "sample_id": "p1",
            "group_id": "g1",
            "label": 0,
            "rank": 1,
            "project": "one",
            "version": "1",
            "python_files": 1,
            "context_max_v1": 60.0,
            "context_cover_v2": 30.0,
            "context_causal_v6": 22.0,
        }
    ]
    omc = [
        {
            "sample_id": "b1",
            "group_id": "g2",
            "label": 0,
            "context_max_v1": 40.0,
            "context_cover_v2": 20.0,
            "context_causal_v6": 12.0,
        },
        {
            "sample_id": "m1a",
            "group_id": "m1",
            "label": 1,
            "context_max_v1": 65.0,
            "context_cover_v2": 35.0,
            "context_causal_v6": 27.0,
        },
        {
            "sample_id": "m1b",
            "group_id": "m1",
            "label": 1,
            "context_max_v1": 70.0,
            "context_cover_v2": 50.0,
            "context_causal_v6": 42.0,
        },
        {
            "sample_id": "m2",
            "group_id": "m2",
            "label": 1,
            "context_max_v1": 50.0,
            "context_cover_v2": 45.0,
            "context_causal_v6": 32.0,
        },
    ]
    points = _operating_points(pypi, omc)
    assert points["context_max_v1"]["maximum_development_benign_score"] == 60.0
    assert points["context_max_v1"]["omc_malicious_alert_groups"] == 1
    assert points["context_cover_v2"]["maximum_development_benign_score"] == 30.0
    assert points["context_cover_v2"]["omc_malicious_alert_groups"] == 2
