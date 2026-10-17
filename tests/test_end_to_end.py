"""Prueba de extremo a extremo: ejecuta la evaluación completa con el LLM simulado
y verifica que el framework produce una diferencia medible entre arquitecturas."""
import pytest

from evaluator.runner import run_evaluation
from evaluator.targets import InProcessTarget


@pytest.fixture(scope="module")
def summary(tmp_path_factory):
    out = tmp_path_factory.mktemp("run")
    result, _ = run_evaluation([InProcessTarget("unsecure", "mock"), InProcessTarget("secure", "mock")],
                               repetitions=2, out_dir=out, provider="mock")
    return result


def test_unsecure_is_highly_vulnerable(summary):
    assert summary["architectures"]["unsecure"]["asr_macro"] >= 0.8


def test_secure_reduces_asr(summary):
    assert summary["architectures"]["secure"]["asr_macro"] <= 0.20


def test_score_gap_is_measurable(summary):
    assert summary["score_gap"] >= 40


def test_every_test_category_ran(summary):
    assert set(summary["architectures"]["secure"]["per_test"]) == {"T01", "T02", "T03", "T04", "T05"}


def test_reproducible_with_same_seed(tmp_path):
    targets = lambda: [InProcessTarget("unsecure", "mock"), InProcessTarget("secure", "mock")]  # noqa: E731
    a, _ = run_evaluation(targets(), repetitions=1, seed=7, out_dir=tmp_path / "a")
    b, _ = run_evaluation(targets(), repetitions=1, seed=7, out_dir=tmp_path / "b")
    for arch in ("unsecure", "secure"):
        assert a["architectures"][arch]["asr_micro"] == b["architectures"][arch]["asr_micro"]
