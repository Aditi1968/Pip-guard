# Costs

pip guard is built and operated for **₹0 / $0**. The project's hard rule (PRD, "Zero-cost constraint") is: no paid plan, no API key with a billing account, no cloud resource that can accrue charges, and no free tier that needs a card to activate.

## Ledger

| Phase | Spend | Free tiers and tools touched | Notes |
| --- | --- | --- | --- |
| 0. Foundation and spike | ₹0 | GitHub (public repo), GitHub Actions (public repo: unlimited minutes), Docker Desktop (free for personal use), PyPI JSON API, Docker Hub (pulling `python:3.12-slim-bookworm`), raw.githubusercontent.com (moby's default seccomp profile) | The spike ran locally. CI re-runs it on `ubuntu-latest`. |
| 1. Fetch, extraction, static | ₹0 | PyPI JSON API; `hugovk.github.io/top-pypi-packages` (a single download of the frozen snapshot) | `rapidfuzz`, `pyyaml` and `pytest-cov` were added with the author's approval; all are permissively licensed. |
| 2. Sandbox | ₹0 | Local Docker; GitHub Actions `ubuntu-latest` for the `docker` CI job | No network layer and no cloud runtime. |
| 3. Rules, model, evaluation | ₹0 | Local CPU only (scikit-learn, LightGBM) | The corpus is downloaded and analysed on the author's machine, never in CI (PRD cost trap). Raw samples are never committed. |
| 4. CLI and Action | ₹0 | GitHub Actions, the Actions cache and artifacts (500 MB of free storage) | Reports are gzip-compressed. Traces are uploaded only for non-`allow` verdicts and capped at 5 MB per package (FR-6.3). |
| 5. Docs and demo | ₹0 | A public demo repo on GitHub; `vhs` or `asciinema` + `agg` for the GIF | The planted package lives in the demo repo as a wheel and is never published to PyPI. |

## Development assistant

Claude Code is used through the author's existing Claude subscription. That is paid for other reasons, so it is not a project cost (PRD, zero-cost table).

## Traps avoided

These are the PRD's list, and each is enforced by a concrete choice:

- **Private repository:** Actions minutes become metered. The repo stays public.
- **Card-gated free tiers** (Snyk, Socket, Semgrep Cloud, Oracle Cloud, cloud GPUs): none are used.
- **Commercial LLM or security APIs:** the classifier is a local logistic regression stored as plain JSON coefficients.
- **Uploading raw strace dumps on every run:** these are compressed, capped and uploaded only for non-`allow` verdicts.
- **Datasets in Git LFS:** only `data/manifest.csv` and the 5,000-name snapshot are committed.
- **Evaluation in CI:** the `scripts/eval/` steps run locally (`scripts/eval/README.md`).
