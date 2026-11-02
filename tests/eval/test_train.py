import csv
import json
import random
from pathlib import Path

import numpy as np
import pytest

from pipguard.features import STATIC_FEATURE_NAMES
from pipguard.models import ModelArtifact, Thresholds
from scripts.eval import train
from scripts.eval.manifest import ManifestRow, write_manifest

BANDS = ["top-100", "101-1000", "1001-5000", "random"]


def _samples(n: int = 300, seed: int = 0, sep: float = 2.0) -> list[train.Sample]:
    rng = random.Random(seed)
    out = []
    for i in range(n):
        label = int(i % 3 == 0)
        x = [rng.gauss(0, 1) for _ in STATIC_FEATURE_NAMES]
        x[0] += sep * label
        x[1] += sep * label
        x[5] = 0.0  # a constant column, as blank metadata is in Track A
        h = rng.random()
        split, fold = ("holdout", None) if h < 0.2 else ("train", i % 5)
        out.append(
            train.Sample(
                sha256=f"{i:064x}",
                label=label,
                band="n/a" if label else BANDS[i % 4],
                split=split,
                fold=fold,
                x=x,
            )
        )
    return out


def test_lr_export_matches_sklearn() -> None:
    s = _samples()
    fit = [x for x in s if x.split == "train"]
    pipe = train.fit_lr(fit, 1.0)
    x_all = np.array([x.x for x in s])
    plain = train.export_lr(pipe, None, Thresholds(), model_version="t")
    sk = pipe.predict_proba(x_all)[:, 1]
    assert max(abs(train.predict_pure(plain, r) - p) for r, p in zip(x_all, sk)) < 1e-9

    a, b = train.fit_platt(pipe.decision_function(x_all), np.array([x.label for x in s]))
    assert a < 0  # increasing map in the 1 / (1 + exp(a z + b)) convention
    cal = train.export_lr(pipe, (a, b), Thresholds(), model_version="t")
    ref = train.platt_proba(pipe.decision_function(x_all), a, b)
    assert max(abs(train.predict_pure(cal, r) - p) for r, p in zip(x_all, ref)) < 1e-9
    # Round-trips through the contract unchanged.
    assert ModelArtifact.model_validate_json(cal.model_dump_json()) == cal


def test_constant_feature_gets_zero_weight() -> None:
    pipe = train.fit_lr([x for x in _samples() if x.split == "train"], 1.0)
    art = train.export_lr(pipe, None, Thresholds(), model_version="t")
    assert art.coefficients[5] == 0.0 and art.feature_scales[5] == 1.0


def test_select_c_returns_grid_value() -> None:
    c, cv = train.select_c([x for x in _samples() if x.split == "train"], grid=(0.1, 1.0))
    assert c in (0.1, 1.0) and set(cv) == {"0.1", "1.0"}
    assert all(0.5 < v <= 1.0 for v in cv.values())


def test_choose_thresholds_on_separable_validation() -> None:
    val = [
        train.Sample("a" * 64, 0, "top-100", "train", 0, []),
        train.Sample("b" * 64, 0, "random", "train", 0, []),
        train.Sample("c" * 64, 1, "n/a", "train", 0, []),
    ]
    th = train.choose_thresholds([0.1, 0.3, 0.9], val)
    assert th == Thresholds(warn=0.9, block=0.9)


@pytest.mark.parametrize(
    ("lr", "gbm", "adopted"),
    [(0.70, 0.73, True), (0.70, 0.729, False), (0.70, 0.80, True), (0.70, 0.60, False)],
)
def test_lightgbm_adoption_rule(lr: float, gbm: float, adopted: bool) -> None:
    assert train.adopt_lightgbm(lr, gbm) is adopted


def test_run_ladder_without_rules() -> None:
    res, art, gbm = train.run_ladder(_samples(), None, n_estimators=5)
    assert res["rules"] is None and "not importable" in res["rules_skipped"]
    assert art is not None and art.kind == "logreg" and art.platt_a is not None
    assert art.thresholds.warn <= art.thresholds.block
    assert res["logreg"]["recall_block"]["value"] > 0.5
    assert res["adopted"] in ("logreg", "lightgbm") and res["adoption_reason"]
    assert (gbm is not None) == (res["adopted"] == "lightgbm")
    json.dumps(res, default=str)


def test_run_ladder_with_rules() -> None:
    from datetime import date

    from pipguard.models import PackageSpec, StaticFeatures, TyposquatResult

    sf = StaticFeatures(
        spec=PackageSpec(name="x", version="1"),
        artifacts=[],
        typosquat=TyposquatResult(snapshot_date=date(2026, 1, 1)),
        metadata={},  # type: ignore[arg-type]
    ).model_dump_json()
    samples = [
        train.Sample(s.sha256, s.label, s.band, s.split, s.fold, s.x, sf) for s in _samples()
    ]
    # A blocking rule that never fires and a warning rule that always fires.
    res, art, _ = train.run_ladder(samples, lambda _sf: [("W_X", "warning")], n_estimators=5)
    assert res["rules"]["blocking"]["recall"]["value"] == 0.0
    assert res["rules"]["warning"]["recall"]["value"] == 1.0
    assert res["rules"]["warning"]["precision"]["value"] < 0.5
    assert res["rules_all_samples"]["W_X"]["class"] == "warning"
    assert res["rules_plus_logreg"]["recall_block"]["value"] > 0
    assert res["adopted"] != "rules" and art is not None


def test_run_ladder_needs_both_labels() -> None:
    s = [x for x in _samples() if x.label == 0]
    with pytest.raises(ValueError, match="both labels"):
        train.run_ladder(s, None, n_estimators=5)


def test_main_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(train, "rules_outcome", lambda: None)
    samples = _samples(seed=2)
    rows, recs = [], []
    for s in samples:
        rows.append(
            ManifestRow(
                name=f"p{s.sha256[-6:]}",
                sha256=s.sha256,
                label="malicious" if s.label else "benign",
                source="datadog" if s.label else "top-pypi",
                popularity_band=s.band,  # type: ignore[arg-type]
                split=s.split,  # type: ignore[arg-type]
                fold=s.fold,
            )
        )
        recs.append({"sha256": s.sha256, "status": "ok"} | dict(zip(STATIC_FEATURE_NAMES, s.x)))
    recs.append({"sha256": "f" * 64, "status": "error"})
    rows.append(
        ManifestRow(
            name="broken", sha256="f" * 64, label="malicious", source="datadog", split="holdout"
        )
    )
    manifest, results = tmp_path / "m.csv", tmp_path / "r.csv"
    write_manifest(rows, manifest)
    with results.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["sha256", "status", *STATIC_FEATURE_NAMES], restval="")
        w.writeheader()
        w.writerows(recs)
    top = tmp_path / "top.json"
    top.write_text(json.dumps({"snapshot_date": "2026-11-01", "names": []}), encoding="utf-8")
    out, ladder = tmp_path / "model.json", tmp_path / "ladder.json"
    argv = ["--manifest", str(manifest), "--results", str(results), "--out", str(out)]
    argv += ["--ladder", str(ladder), "--top-pypi", str(top), "--n-estimators", "5"]
    assert train.main(argv) == 0
    art = ModelArtifact.model_validate_json(out.read_text(encoding="utf-8"))
    assert art.model_version.startswith("lr-") and art.training_manifest_sha256
    assert str(art.typosquat_snapshot_date) == "2026-11-01"
    res = json.loads(ladder.read_text(encoding="utf-8"))
    assert res["counts"]["analysis_status"] == {"ok": len(samples), "error": 1}
