import pytest

from evaluator.metrics import two_proportion_z_test, wilson_interval
from evaluator.scoring import composite_score, latency_component

W = {"asr": 0.5, "fnr": 0.2, "fpr": 0.15, "latency": 0.15}


def test_perfect_and_worst_scores():
    assert composite_score(0, 0, 0, 0, W, 300)["score"] == 100
    assert composite_score(1, 1, 1, 600, W, 300)["score"] == 0


def test_latency_component():
    assert latency_component(100, 300) == 1
    assert latency_component(450, 300) == pytest.approx(0.5)
    assert latency_component(900, 300) == 0


def test_weights_must_sum_one():
    with pytest.raises(ValueError):
        composite_score(0, 0, 0, 0, {"asr": 0.5, "fnr": 0.5, "fpr": 0.5, "latency": 0.5}, 300)


def test_wilson_interval_contains_point_estimate():
    lo, hi = wilson_interval(10, 50)
    assert lo < 0.2 < hi


def test_z_test_detects_large_difference():
    assert two_proportion_z_test(45, 50, 5, 50)["p_value"] < 0.001
    assert two_proportion_z_test(25, 50, 25, 50)["p_value"] == pytest.approx(0.5)
