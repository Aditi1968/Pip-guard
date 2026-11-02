import copy
import functools
from pathlib import Path

import pytest

from scripts.eval import report
from scripts.eval.metrics import rate
from scripts.eval.train import run_ladder
from tests.eval.test_train import _samples

EVAL_MD = Path(__file__).resolve().parents[2] / "docs" / "EVAL.md"


@functools.cache
def _base_ladder() -> dict:
    return run_ladder(_samples(), None, n_estimators=5)[0]


def _ladder() -> dict:
    res = copy.deepcopy(_base_ladder())
    res |= {
        "counts": {
            "by_label": {"malicious": 100, "benign": 200},
            "by_source": {"datadog": 90, "openssf": 10, "top-pypi": 200},
            "by_band": {"top-100": 50, "random": 150},
            "by_split": {"train:benign": 160},
            "excluded": 7,
            "analysis_status": {"ok": 299, "error": 1},
            "openssf_fetchable": 10,
            "openssf_total": 40,
        },
        "training_manifest_sha256": "a" * 64,
        "typosquat_snapshot_date": "2026-11-01",
        "model_version": "lr-20261102-aaaaaaaa",
    }
    return res


def test_template_has_required_sections() -> None:
    md = EVAL_MD.read_text(encoding="utf-8")
    for needle in (
        report.START,
        report.END,
        "## Track A",
        "## Track B",
        "## Track C",
        "not yet run",
        "Behavioural features are not evaluated on Track A",
        "weak label",
        "Wilson",
        "Datadog dataset terms",
    ):
        assert needle in md, needle


def test_render_replaces_only_track_a() -> None:
    md = EVAL_MD.read_text(encoding="utf-8")
    out = report.update_eval(md, _ladder())
    for needle in (
        "### Counts",
        "| datadog | 90 |",
        "Fetchable OpenSSF artifacts: 10 of 40",
        "| error | 1 |",
        "Recall at per-band FPR",
        "95% CI",
        "PR-AUC",
        "### Calibration",
        "### Rules alone",
        "Not evaluated: pipguard.rules not importable",
        "### Ablations",
        "LightGBM alone",
        "Adopted rung:",
        "lr-20261102-aaaaaaaa",
        "never executed",
    ):
        assert needle in out, needle
    before, after = md.split(report.START)[0], md.split(report.END)[1]
    assert out.startswith(before) and out.endswith(after)
    assert report.update_eval(out, _ladder()) == out


def test_render_with_rules_section() -> None:
    res = _ladder()
    res["rules"] = {
        k: {"precision": rate(9, 10), "recall": rate(9, 50)} for k in ("blocking", "warning")
    }
    res["rules_all_samples"] = {"B_X": {"class": "blocking", "precision": rate(19, 20)}}
    res["rules_plus_logreg"] = {"recall_block": rate(40, 50)}
    text = report.render_track_a(res)
    assert "| B_X | blocking | 0.950 (19/20" in text
    assert "Rules + LR" in text and "Rules only (blocking)" in text


def test_missing_markers_rejected() -> None:
    with pytest.raises(ValueError, match="markers"):
        report.update_eval("# no markers", _ladder())
