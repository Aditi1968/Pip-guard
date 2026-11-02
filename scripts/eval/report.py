"""Render the Track A section of ``docs/EVAL.md`` from ``data/results/ladder.json``.

    python -m scripts.eval.report

Only the text between the ``track-a`` markers is replaced; Tracks B and C are left alone.
Only aggregate numbers are rendered, never per-sample results (Datadog terms caveat).
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Sequence
from pathlib import Path

from scripts.eval.train import LADDER_JSON

EVAL_MD = Path(__file__).resolve().parents[2] / "docs" / "EVAL.md"
START, END = "<!-- track-a:start -->", "<!-- track-a:end -->"


def _pct(r: dict) -> str:
    if r["value"] is None:
        return f"n/a (0/{r['n']})"
    return f"{r['value']:.3f} ({r['k']}/{r['n']}; 95% CI {r['ci_low']:.3f}-{r['ci_high']:.3f})"


def _table(header: list[str], rows: Sequence[Sequence[object]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + " --- |" * len(header)]
    return out + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]


def _counts(name: str, d: dict) -> list[str]:
    return [f"**{name}**", "", *_table(["", "n"], [[k, v] for k, v in sorted(d.items())]), ""]


def render_track_a(res: dict) -> str:
    c = res["counts"]
    lines = [
        START,
        "## Track A: static classification (real-world corpus)",
        "",
        f"Model version `{res.get('model_version', 'none written')}`; training manifest "
        f"SHA-256 `{res['training_manifest_sha256']}`; typosquat snapshot "
        f"{res['typosquat_snapshot_date']}. Static features only.",
        "",
        "### Counts",
        "",
        *_counts("By label", c["by_label"]),
        *_counts("By source", c["by_source"]),
        *_counts("Benign by popularity band", c["by_band"]),
        *_counts("By split", c["by_split"]),
        *_counts(
            "Static analysis status (errors are reported, never dropped)", c["analysis_status"]
        ),
        f"Excluded rows (duplicates, unfetchable, benign names in a malicious set): "
        f"{c['excluded']}. Fetchable OpenSSF artifacts: {c['openssf_fetchable']} of "
        f"{c['openssf_total']} reports with explicit versions.",
        "",
        "### Recall at per-band FPR (holdout)",
        "",
        f"Thresholds were chosen on the validation fold (block: FPR <= "
        f"{res['block_fpr_target']} in every band, worst band governs; warn: <= "
        f"{res['warn_fpr_target']}) and applied unchanged to the holdout.",
        "",
    ]
    rungs = [("Logistic regression", "logreg"), ("LightGBM", "lightgbm")]
    rows = []
    for label, key in rungs:
        r = res[key]
        rows.append(
            [
                label,
                f"{r['thresholds']['block']:.4f}",
                _pct(r["recall_block"]),
                "None" if r["pr_auc"] is None else f"{r['pr_auc']:.3f}",
            ]
        )
    lines += _table(["Model", "Block threshold", "Recall at block", "PR-AUC"], rows)
    lines += ["", "Per-band false-positive rate at the block threshold:", ""]
    bands = sorted({b for _, k in rungs for b in res[k]["fpr_block"]})
    lines += _table(
        ["Model", *bands],
        [[lbl, *(_pct(res[k]["fpr_block"][b]) for b in bands)] for lbl, k in rungs],
    )
    lines += ["", "### Calibration (logistic regression, Platt-scaled, holdout)", ""]
    lines += _table(
        ["Bin", "n", "Mean predicted", "Observed malicious"],
        [
            [r["bin"], r["n"], f"{r['mean_predicted']:.3f}", f"{r['observed_malicious']:.3f}"]
            for r in res["logreg"]["calibration"]
        ],
    )
    lines += ["", "### Rules alone", ""]
    if res.get("rules"):
        rules = res["rules"]
        lines += _table(
            ["Class", "Precision", "Recall"],
            [
                [k, _pct(rules[k]["precision"]), _pct(rules[k]["recall"])]
                for k in ("blocking", "warning")
            ],
        )
        lines += [
            "",
            "Per-rule precision on all analysed samples (rules have no fitted parameters):",
            "",
        ]
        lines += _table(
            ["Rule", "Class", "Precision"],
            [
                [rid, v["class"], _pct(v["precision"])]
                for rid, v in res["rules_all_samples"].items()
            ],
        )
    else:
        lines.append(f"Not evaluated: {res.get('rules_skipped', 'rules unavailable')}.")
    lines += ["", "### Ablations (holdout, block threshold)", ""]
    abl = (
        [["Rules only (blocking)", _pct(res["rules"]["blocking"]["recall"])]]
        if res.get("rules")
        else []
    )
    if res.get("rules_plus_logreg"):
        abl.append(["Rules + LR", _pct(res["rules_plus_logreg"]["recall_block"])])
    abl += [["LR alone", _pct(res["logreg"]["recall_block"])]]
    abl += [["LightGBM alone", _pct(res["lightgbm"]["recall_block"])]]
    lines += _table(["Configuration", "Recall"], abl)
    lines += [
        "",
        f"**Adopted rung: {res['adopted']}.** {res['adoption_reason']}.",
        "",
        "Behavioural features are not evaluated on Track A: these samples are never executed.",
        END,
    ]
    return "\n".join(lines)


def update_eval(md: str, res: dict) -> str:
    if START not in md or END not in md:
        raise ValueError("EVAL.md lacks the track-a markers")
    pattern = re.compile(re.escape(START) + ".*?" + re.escape(END), re.S)
    return pattern.sub(lambda _: render_track_a(res), md)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--ladder", type=Path, default=LADDER_JSON)
    p.add_argument("--eval-md", type=Path, default=EVAL_MD)
    args = p.parse_args(argv)
    res = json.loads(args.ladder.read_text(encoding="utf-8"))
    args.eval_md.write_text(update_eval(args.eval_md.read_text(encoding="utf-8"), res), "utf-8")
    print(f"updated Track A in {args.eval_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
