"""Evaluation metrics for Track A. Labels are 1 = malicious, 0 = benign.

A sample is flagged when ``score >= threshold`` (the same rule ``scoring.py`` applies).
"""

from __future__ import annotations

import math
from collections.abc import Sequence

Z95 = 1.959963984540054


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    """95% Wilson score interval for k successes in n trials; (0, 1) when n == 0."""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def rate(k: int, n: int) -> dict:
    """``{k, n, value, ci_low, ci_high}``; value is None when n == 0."""
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "value": k / n if n else None, "ci_low": lo, "ci_high": hi}


def recall(labels: Sequence[int], flagged: Sequence[bool]) -> dict:
    return rate(sum(f for y, f in zip(labels, flagged, strict=True) if y == 1), sum(labels))


def per_band_fpr(labels: Sequence[int], flagged: Sequence[bool], bands: Sequence[str]) -> dict:
    """False-positive rate on benign samples, per popularity band."""
    out: dict[str, list[int]] = {}
    for y, f, b in zip(labels, flagged, bands, strict=True):
        if y == 0:
            fp_n = out.setdefault(b, [0, 0])
            fp_n[0] += int(f)
            fp_n[1] += 1
    return {b: rate(fp, n) for b, (fp, n) in sorted(out.items())}


def select_threshold(
    scores: Sequence[float], labels: Sequence[int], bands: Sequence[str], max_fpr: float
) -> float:
    """Lowest threshold whose FPR is <= max_fpr in *every* benign band (worst band governs).

    The lowest such threshold gives the highest recall. 1.0 if nothing qualifies below it.
    """
    for t in sorted({*scores, 1.0}):
        flagged = [s >= t for s in scores]
        fprs = per_band_fpr(labels, flagged, bands).values()
        if all(r["value"] is None or r["value"] <= max_fpr for r in fprs):
            return t
    return 1.0


def recall_at_fpr(
    scores: Sequence[float], labels: Sequence[int], bands: Sequence[str], max_fpr: float
) -> tuple[dict, float]:
    """Recall at the per-band FPR target, threshold chosen on these same samples."""
    t = select_threshold(scores, labels, bands, max_fpr)
    return recall(labels, [s >= t for s in scores]), t


def pr_auc(labels: Sequence[int], scores: Sequence[float]) -> float | None:
    """Average precision (scikit-learn); None when only one class is present."""
    from sklearn.metrics import average_precision_score

    if len(set(labels)) < 2:
        return None
    return float(average_precision_score(labels, scores))


def calibration_table(labels: Sequence[int], probs: Sequence[float], bins: int = 10) -> list[dict]:
    """Reliability table: per equal-width bin, count, mean prediction and observed rate."""
    rows = []
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i, p in enumerate(probs) if lo <= p < hi or (b == bins - 1 and p == 1.0)]
        if idx:
            rows.append(
                {
                    "bin": f"{lo:.1f}-{hi:.1f}",
                    "n": len(idx),
                    "mean_predicted": sum(probs[i] for i in idx) / len(idx),
                    "observed_malicious": sum(labels[i] for i in idx) / len(idx),
                }
            )
    return rows


def precision(labels: Sequence[int], flagged: Sequence[bool]) -> dict:
    """Precision of a binary rule: true positives over everything it flagged."""
    hits = [y for y, f in zip(labels, flagged, strict=True) if f]
    return rate(sum(hits), len(hits))
