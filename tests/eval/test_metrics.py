import pytest

from scripts.eval import metrics


def test_wilson_known_values() -> None:
    lo, hi = metrics.wilson(8, 10)
    assert lo == pytest.approx(0.4902, abs=1e-4)
    assert hi == pytest.approx(0.9433, abs=1e-4)
    assert metrics.wilson(0, 0) == (0.0, 1.0)
    lo, hi = metrics.wilson(0, 20)
    assert lo == 0.0
    assert hi == pytest.approx(0.1611, abs=1e-4)


def test_rate_and_recall_precision() -> None:
    labels = [1, 1, 1, 0, 0]
    flagged = [True, True, False, True, False]
    r = metrics.recall(labels, flagged)
    assert (r["k"], r["n"], r["value"]) == (2, 3, pytest.approx(2 / 3))
    p = metrics.precision(labels, flagged)
    assert (p["k"], p["n"]) == (2, 3)
    assert metrics.precision([0], [False])["value"] is None


def test_per_band_fpr() -> None:
    labels = [0, 0, 0, 0, 1]
    flagged = [True, False, False, False, True]
    bands = ["a", "a", "b", "b", "n/a"]
    fpr = metrics.per_band_fpr(labels, flagged, bands)
    assert fpr["a"]["value"] == 0.5
    assert fpr["b"]["value"] == 0.0
    assert "n/a" not in fpr  # malicious samples have no band FPR


def test_select_threshold_worst_band_governs() -> None:
    # band a benign scores 0.1..0.9 (9 values), band b all low; one malicious at 0.95.
    scores = [i / 10 for i in range(1, 10)] + [0.05] * 5 + [0.95]
    labels = [0] * 14 + [1]
    bands = ["a"] * 9 + ["b"] * 5 + ["n/a"]
    # FPR <= 0.2 in band a needs <= 1 of 9 flagged -> threshold just above 0.8 -> 0.9.
    assert metrics.select_threshold(scores, labels, bands, 0.2) == 0.9
    rec, t = metrics.recall_at_fpr(scores, labels, bands, 0.0)
    assert t == 0.95 and rec["value"] == 1.0


def test_select_threshold_separable_gives_full_recall() -> None:
    scores = [0.1, 0.2, 0.3, 0.7, 0.8]
    labels = [0, 0, 0, 1, 1]
    bands = ["x", "x", "x", "n/a", "n/a"]
    assert metrics.select_threshold(scores, labels, bands, 0.05) == 0.7


def test_pr_auc_known_values() -> None:
    assert metrics.pr_auc([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]) == pytest.approx(1.0)
    # ranking: 1 (0.9), 0 (0.8), 1 (0.7) -> AP = (1/1 + 2/3) / 2
    assert metrics.pr_auc([1, 0, 1], [0.9, 0.8, 0.7]) == pytest.approx(5 / 6)
    assert metrics.pr_auc([1, 1], [0.1, 0.2]) is None


def test_calibration_table() -> None:
    table = metrics.calibration_table([0, 1, 1, 1], [0.05, 0.15, 0.95, 1.0], bins=10)
    assert [r["bin"] for r in table] == ["0.0-0.1", "0.1-0.2", "0.9-1.0"]
    assert table[-1]["n"] == 2 and table[-1]["observed_malicious"] == 1.0
    assert table[0]["mean_predicted"] == pytest.approx(0.05)
