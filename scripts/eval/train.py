"""Model ladder on Track A static features (FR-5.2) with thresholds chosen on validation (FR-5.8).

    python -m scripts.eval.train --out src/pipguard/model/model.json

Protocol (all splits come from the manifest, grouped by package name and campaign):
- ``C`` for the logistic regression is picked by 5-fold grouped CV on ``split=train``
  (manifest folds 0-4), scored by mean PR-AUC.
- The validation fold is fold 0. Final models fit on folds 1-4; Platt scaling and the
  warn/block thresholds are fitted on fold 0; the frozen holdout is touched only to report.
- Thresholds: block = lowest score with FPR <= 0.05 in every benign popularity band;
  warn = the same at a looser 0.15 (a warn asks a human to look, it does not fail the build).
- Ladder: rules alone -> +LR (adopted if rules+LR recall beats rules alone) -> LightGBM
  (adopted only if its holdout recall at the block threshold beats LR by >= 3 points).
Behavioural features are never used here: Track A samples are never executed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler

from pipguard.features import STATIC_FEATURE_NAMES
from pipguard.models import ModelArtifact, StaticFeatures, Thresholds
from scripts.eval import metrics
from scripts.eval.batch_static import RESULTS_CSV
from scripts.eval.manifest import DATA, MANIFEST_CSV, ManifestRow, read_manifest

BLOCK_FPR = 0.05
WARN_FPR = 0.15
LGBM_MARGIN = 0.03
C_GRID = (0.01, 0.1, 1.0, 10.0)
VAL_FOLD = 0
LADDER_JSON = DATA / "results" / "ladder.json"

RuleFn = Callable[[StaticFeatures], list[tuple[str, str]]]  # -> [(rule_id, klass)]


@dataclass(frozen=True)
class Sample:
    sha256: str
    label: int  # 1 malicious, 0 benign
    band: str
    split: str
    fold: int | None
    x: list[float]
    static_json: str = ""


# ------------------------------------------------------------------ data


def load_samples(rows: list[ManifestRow], results: Path) -> tuple[list[Sample], Counter]:
    """Join manifest and results by SHA-256; also count results by status (errors kept)."""
    csv.field_size_limit(2**31 - 1)
    with results.open(newline="", encoding="utf-8") as f:
        recs = {r["sha256"]: r for r in csv.DictReader(f)}
    samples, status = [], Counter()
    for row in rows:
        rec = recs.get(row.sha256)
        if row.split == "excluded" or rec is None:
            continue
        status[rec["status"]] += 1
        if rec["status"] != "ok":
            continue  # counted and reported as errors, never treated as benign
        samples.append(
            Sample(
                sha256=row.sha256,
                label=int(row.label == "malicious"),
                band=row.popularity_band,
                split=row.split,
                fold=row.fold,
                x=[float(rec[n]) for n in STATIC_FEATURE_NAMES],
                static_json=rec.get("static_features_json", ""),
            )
        )
    return samples, status


def _xy(samples: Sequence[Sample]) -> tuple[np.ndarray, np.ndarray]:
    return np.array([s.x for s in samples], dtype=float), np.array([s.label for s in samples])


# ------------------------------------------------------------------ logistic regression


def fit_lr(samples: Sequence[Sample], c: float) -> Pipeline:
    x, y = _xy(samples)
    lr = LogisticRegression(C=c, class_weight="balanced", max_iter=5000)
    return make_pipeline(StandardScaler(), lr).fit(x, y)


def select_c(train: Sequence[Sample], grid: Sequence[float] = C_GRID) -> tuple[float, dict]:
    """Grouped CV over the manifest folds; best mean PR-AUC wins (ties -> smaller C)."""
    cv: dict[str, float] = {}
    for c in grid:
        aps = []
        for k in sorted({s.fold for s in train if s.fold is not None}):
            fit = [s for s in train if s.fold != k]
            val = [s for s in train if s.fold == k]
            if len({s.label for s in fit}) < 2:
                continue
            ap = metrics.pr_auc([s.label for s in val], logit(fit_lr(fit, c), val).tolist())
            if ap is not None:
                aps.append(ap)
        cv[str(c)] = float(np.mean(aps)) if aps else float("nan")
    best = max(grid, key=lambda c: (np.nan_to_num(cv[str(c)], nan=-1.0), -c))
    return best, cv


def logit(pipe: Pipeline, samples: Sequence[Sample]) -> np.ndarray:
    return pipe.decision_function(_xy(samples)[0])


def fit_platt(z: np.ndarray, y: np.ndarray) -> tuple[float, float]:
    """Platt scaling in scoring.py's convention: ``p = 1 / (1 + exp(a * z + b))``."""
    m = LogisticRegression(C=1e6, max_iter=5000).fit(z.reshape(-1, 1), y)
    return -float(m.coef_[0][0]), -float(m.intercept_[0])


def platt_proba(z: np.ndarray, a: float, b: float) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(a * z + b))


def export_lr(
    pipe: Pipeline, platt: tuple[float, float] | None, thresholds: Thresholds, **extra
) -> ModelArtifact:
    """Plain-number export so inference needs no scikit-learn."""
    scaler = pipe.named_steps["standardscaler"]
    lr = pipe.named_steps["logisticregression"]
    return ModelArtifact(
        kind="logreg",
        feature_names=list(STATIC_FEATURE_NAMES),
        feature_means=[float(v) for v in scaler.mean_],
        feature_scales=[float(v) for v in scaler.scale_],
        coefficients=[float(v) for v in lr.coef_[0]],
        intercept=float(lr.intercept_[0]),
        platt_a=platt[0] if platt else None,
        platt_b=platt[1] if platt else None,
        thresholds=thresholds,
        **extra,
    )


def predict_pure(art: ModelArtifact, x: Sequence[float]) -> float:
    """Reference pure-Python inference, same formula as scoring.py."""
    z = art.intercept + sum(
        c * (v - m) / s
        for c, v, m, s in zip(
            art.coefficients, x, art.feature_means, art.feature_scales, strict=True
        )
    )
    if art.platt_a is not None and art.platt_b is not None:
        return 1.0 / (1.0 + math.exp(art.platt_a * z + art.platt_b))
    return 1.0 / (1.0 + math.exp(-z))


# ------------------------------------------------------------------ LightGBM


def fit_lgbm(samples: Sequence[Sample], n_estimators: int = 200, seed: int = 0):
    from lightgbm import LGBMClassifier

    x, y = _xy(samples)
    model = LGBMClassifier(
        n_estimators=n_estimators,
        learning_rate=0.05,
        num_leaves=15,
        min_child_samples=5,
        class_weight="balanced",
        random_state=seed,
        verbose=-1,
    )
    return model.fit(x, y)


def adopt_lightgbm(lr_recall: float, lgbm_recall: float, margin: float = LGBM_MARGIN) -> bool:
    """FR-5.2: LightGBM replaces LR only if recall at the FPR target improves by >= margin."""
    return lgbm_recall - lr_recall >= margin - 1e-12


# ------------------------------------------------------------------ evaluation


def choose_thresholds(scores: Sequence[float], val: Sequence[Sample]) -> Thresholds:
    labels, bands = [s.label for s in val], [s.band for s in val]
    block = metrics.select_threshold(scores, labels, bands, BLOCK_FPR)
    warn = metrics.select_threshold(scores, labels, bands, WARN_FPR)
    return Thresholds(warn=min(warn, block), block=block)


def evaluate_scores(scores: Sequence[float], hold: Sequence[Sample], th: Thresholds) -> dict:
    labels, bands = [s.label for s in hold], [s.band for s in hold]
    block = [p >= th.block for p in scores]
    warn = [p >= th.warn for p in scores]
    return {
        "thresholds": th.model_dump(),
        "recall_block": metrics.recall(labels, block),
        "fpr_block": metrics.per_band_fpr(labels, block, bands),
        "recall_warn": metrics.recall(labels, warn),
        "fpr_warn": metrics.per_band_fpr(labels, warn, bands),
        "pr_auc": metrics.pr_auc(labels, list(scores)),
    }


def rules_outcome() -> RuleFn | None:
    """Adapter for Workstream D's rules engine; None (rung skipped) if it is not importable."""
    try:
        from pipguard.rules import (  # pyright: ignore[reportMissingImports]
            build_inputs,
            evaluate,
            load_rules,
        )
    except ImportError:
        return None
    rs = load_rules()

    def outcome(sf: StaticFeatures) -> list[tuple[str, str]]:
        feats, ev = build_inputs(sf, None)
        return [(h.rule_id, h.klass) for h in evaluate(rs, feats, ev)]

    return outcome


def evaluate_rules(rule_fn: RuleFn, samples: Sequence[Sample]) -> dict:
    """Blocking and warning classes separately, plus per-rule precision."""
    hits = [rule_fn(StaticFeatures.model_validate_json(s.static_json)) for s in samples]
    labels, bands = [s.label for s in samples], [s.band for s in samples]
    out: dict = {}
    for klass in ("blocking", "warning"):
        flagged = [any(k == klass for _, k in h) for h in hits]
        out[klass] = {
            "precision": metrics.precision(labels, flagged),
            "recall": metrics.recall(labels, flagged),
            "fpr": metrics.per_band_fpr(labels, flagged, bands),
        }
    ids = sorted({(rid, k) for h in hits for rid, k in h})
    out["per_rule"] = {
        rid: {"class": k, "precision": metrics.precision(labels, [(rid, k) in h for h in hits])}
        for rid, k in ids
    }
    out["block_flags"] = [any(k == "blocking" for _, k in h) for h in hits]
    return out


def run_ladder(
    samples: list[Sample], rule_fn: RuleFn | None, n_estimators: int = 200, seed: int = 0
) -> tuple[dict, ModelArtifact | None, object | None]:
    """Everything except file IO: returns (ladder results, LR artifact, LightGBM model)."""
    train = [s for s in samples if s.split == "train"]
    hold = [s for s in samples if s.split == "holdout"]
    val = [s for s in train if s.fold == VAL_FOLD]
    fit = [s for s in train if s.fold != VAL_FOLD]
    for name, part in (("fit folds", fit), ("validation fold", val), ("holdout", hold)):
        if len({s.label for s in part}) < 2:
            raise ValueError(f"{name} needs both labels; got {len(part)} samples")
    y_val, y_hold = np.array([s.label for s in val]), [s.label for s in hold]
    res: dict = {"protocol": __doc__, "block_fpr_target": BLOCK_FPR, "warn_fpr_target": WARN_FPR}

    # Rung 1: rules alone
    rules = evaluate_rules(rule_fn, hold) if rule_fn else None
    res["rules"] = {k: v for k, v in rules.items() if k != "block_flags"} if rules else None
    if rules is None:
        res["rules_skipped"] = "pipguard.rules not importable; rules rung not evaluated"
    if rule_fn:
        res["rules_all_samples"] = evaluate_rules(rule_fn, samples)["per_rule"]

    # Rung 2: logistic regression, Platt-calibrated on the validation fold
    c, cv = select_c(train)
    lr = fit_lr(fit, c)
    platt = fit_platt(logit(lr, val), y_val)
    p_val = platt_proba(logit(lr, val), *platt)
    th_lr = choose_thresholds(p_val.tolist(), val)
    p_hold = platt_proba(logit(lr, hold), *platt).tolist()
    res["logreg"] = evaluate_scores(p_hold, hold, th_lr) | {"C": c, "cv_pr_auc": cv}
    res["logreg"]["calibration"] = metrics.calibration_table(y_hold, p_hold)
    if rules:
        combined = [
            b or p >= th_lr.block for b, p in zip(rules["block_flags"], p_hold, strict=True)
        ]
        res["rules_plus_logreg"] = {
            "recall_block": metrics.recall(y_hold, combined),
            "fpr_block": metrics.per_band_fpr(y_hold, combined, [s.band for s in hold]),
        }

    # Rung 3: LightGBM, raw score (no calibration), same protocol
    gbm = fit_lgbm(fit, n_estimators, seed)
    s_val = np.asarray(gbm.predict_proba(_xy(val)[0]))[:, 1].tolist()
    th_gbm = choose_thresholds(s_val, val)
    s_hold = np.asarray(gbm.predict_proba(_xy(hold)[0]))[:, 1].tolist()
    res["lightgbm"] = evaluate_scores(s_hold, hold, th_gbm)

    lr_recall = res["logreg"]["recall_block"]["value"]
    rules_recall = rules["blocking"]["recall"]["value"] if rules else None
    lr_adopted = rules is None or res["rules_plus_logreg"]["recall_block"]["value"] > rules_recall
    gbm_adopted = lr_adopted and adopt_lightgbm(lr_recall, res["lightgbm"]["recall_block"]["value"])
    res["adopted"] = "lightgbm" if gbm_adopted else "logreg" if lr_adopted else "rules"
    res["adoption_reason"] = _reason(rules_recall, res, lr_adopted, gbm_adopted)
    artifact = export_lr(lr, platt, th_lr, model_version="unversioned") if lr_adopted else None
    return res, artifact, gbm if gbm_adopted else None


def _reason(rules_recall: float | None, res: dict, lr_ok: bool, gbm_ok: bool) -> str:
    lr = res["logreg"]["recall_block"]["value"]
    gbm = res["lightgbm"]["recall_block"]["value"]
    parts = [
        "rules rung unavailable -> LR adopted by default"
        if rules_recall is None
        else f"rules blocking recall {rules_recall:.3f} vs rules+LR "
        f"{res['rules_plus_logreg']['recall_block']['value']:.3f}"
        + (" -> LR adopted" if lr_ok else " -> LR not adopted"),
        f"LightGBM recall {gbm:.3f} vs LR {lr:.3f} (needs +{LGBM_MARGIN:.2f})"
        + (" -> LightGBM adopted" if gbm_ok else " -> LightGBM not adopted"),
    ]
    return "; ".join(parts)


# ------------------------------------------------------------------ CLI


def track_a_counts(rows: list[ManifestRow], status: Counter) -> dict:
    live = [r for r in rows if r.split != "excluded"]
    return {
        "by_label": dict(Counter(r.label for r in live)),
        "by_source": dict(Counter(r.source for r in live)),
        "by_band": dict(Counter(r.popularity_band for r in live if r.label == "benign")),
        "by_split": dict(Counter(f"{r.split}:{r.label}" for r in live)),
        "excluded": sum(r.split == "excluded" for r in rows),
        "analysis_status": dict(status),
        "openssf_fetchable": sum(r.source == "openssf" and bool(r.sha256) for r in rows),
        "openssf_total": sum(r.source == "openssf" for r in rows),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--manifest", type=Path, default=MANIFEST_CSV)
    p.add_argument("--results", type=Path, default=RESULTS_CSV)
    p.add_argument("--out", type=Path, required=True, help="ModelArtifact JSON path")
    p.add_argument("--ladder", type=Path, default=LADDER_JSON)
    p.add_argument("--top-pypi", type=Path, default=DATA / "top-pypi-5000.json")
    p.add_argument("--n-estimators", type=int, default=200)
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args(argv)

    rows = read_manifest(args.manifest)
    samples, status = load_samples(rows, args.results)
    rule_fn = rules_outcome()
    if rule_fn is None:
        print("pipguard.rules is not importable: skipping the rules rung")
    res, artifact, gbm = run_ladder(samples, rule_fn, args.n_estimators, args.seed)

    manifest_sha = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    snapshot = json.loads(args.top_pypi.read_text(encoding="utf-8"))["snapshot_date"]
    now = datetime.now(UTC)
    res["counts"] = track_a_counts(rows, status)
    res["training_manifest_sha256"] = manifest_sha
    res["typosquat_snapshot_date"] = snapshot
    stamp = {
        "training_manifest_sha256": manifest_sha,
        "typosquat_snapshot_date": date.fromisoformat(snapshot),
        "trained_at": now,
    }
    if artifact is not None:
        artifact = artifact.model_copy(
            update={"model_version": f"lr-{now:%Y%m%d}-{manifest_sha[:8]}", **stamp}
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
        res["model_version"] = artifact.model_version
        print(f"wrote {args.out} ({artifact.model_version})")
    else:
        print("LR did not beat rules alone: no model written, scoring stays rules-only")
    if gbm is not None:
        # scoring.py has no LightGBM inference yet; ship the decision, not a broken artifact.
        gbm_art = ModelArtifact(
            kind="lightgbm",
            model_version=f"lgbm-{now:%Y%m%d}-{manifest_sha[:8]}",
            feature_names=list(STATIC_FEATURE_NAMES),
            lightgbm_model=gbm.booster_.model_to_string(),  # type: ignore[attr-defined]
            thresholds=Thresholds(**res["lightgbm"]["thresholds"]),
            **stamp,
        )
        gbm_path = args.out.with_name(args.out.stem + "-lightgbm.json")
        gbm_path.write_text(gbm_art.model_dump_json(indent=2), encoding="utf-8")
        print(f"LightGBM adopted; wrote {gbm_path}. scoring.py needs LightGBM support to use it")
    args.ladder.parent.mkdir(parents=True, exist_ok=True)
    args.ladder.write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print(f"wrote {args.ladder}; adopted rung: {res['adopted']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
