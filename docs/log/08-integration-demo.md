# Build log 08: integration and the demo (Track C)

How the six workstreams were merged into one working scanner, the bugs that only appeared once they ran together, and the demo repository that will show pip guard failing a real check. Commits: merges `fdc608a`, `98a45da`, `163b00c`, `97f080d`, `b18430d`, `b068e90`; fixes `45b3871`, `385d7c2`, `61f88bb`, `4591a2a`, `cfaae00`, `d58ded3`; demo `4591a2a`.

## How the work was merged

The foundation commit (`bf5d51f`, plus `056b9ef` for the feature vector and model artifact) fixed the contract first: `models.py`, `features.py`, `errors.py`, `config.py`. Each workstream (A fetch/extract, B static, C sandbox, D rules/scoring, E diff/cache/report/action, F evaluation) was then built in its own git worktree against that contract and merged back with a merge commit.

Because the contract came first, most merges were mechanical. Two habits made parallel work possible:

- **Lazy imports across workstreams.** Workstream F was written before A, B and D had merged, so it reaches them through small adapters that import lazily: `batch_static._static_features_for` imports `pipguard.static` inside the function, `build_manifest.extract_sample` imports `safe_extract` inside the function, and `train.rules_outcome` returns `None` (rung skipped, and the report says so) if `pipguard.rules` is not importable (`scripts/eval/train.py:218-234`). After the merge they all resolve.
- **Test doubles at every boundary.** `PyPIClient` takes an `opener`, `sandbox.run` takes a `docker`, `ScanOptions` takes `fetcher`, `sandbox_run` and `image_digest` (`pipeline.py:49-62`). So each workstream's tests ran without the others, and `pipeline.py` could be tested end to end with fakes before Docker worked.

The integration layer itself (`pipeline.py` and `cli.py`, commit `61f88bb`) was written last, and its one rule is that every failure ends in a verdict, enforced in one place (`pipeline.py:245-256`) rather than in each caller.

## Bugs and fixes found during integration

### Line-ending normalisation (`45b3871`)

The project is developed on Windows. Without a rule, Git may check text files out with CRLF line endings, and scripts that run under bash on Linux (`sandbox/spike.sh`, `action/map_exit.sh`, `demo/make_prs.sh`) then fail in confusing ways, for example bash reporting `$'\r': command not found`. Files copied into the image or committed as data should also be byte-identical across platforms. `.gitattributes` now sets `* text=auto eol=lf`, forces LF for JSON, and marks `*.whl` and `*.gz` as binary so their bytes and hashes are never touched.

The same commit removed `musllinux_1` from the sandbox platform prefixes in `models.py`, because the image is glibc and a musl wheel cannot install there. (The live selection logic is in `fetch.py:156-172`; the `models.py` constants are no longer used anywhere.)

### Double escaping (`385d7c2`)

Workstream D escaped untrusted values for Markdown when rendering a rule's reason; Workstream E escaped every table cell in the job summary. Each was correct alone. Together, the summary showed entity codes instead of characters, and the JSON report carried escaped text. The decision: escape exactly once, at the boundary where text becomes Markdown. `rules.safe_text` now only removes control and format characters and caps length (`rules.py:49-62`); `report._cell` does all Markdown escaping (`report.py:50-58`). Details in log 05.

### Static-analysis tuning against real packages (`61f88bb`, `d58ded3`)

Running real packages through the full pipeline showed three false-positive sources, each fixed in `static.py` and explained in log 03: install-hook indicators only from the root `setup.py`; raw IPs only when globally routable (or documentation ranges); and popular packages exempt from typosquat, after the benign Track C bump `six==1.17.0` warned because `six` is two edits from `pip`.

### Sandbox image failures (`cfaae00`)

If Docker is not running or the image is missing, that is not the package misbehaving; it is the scanner unable to do its job. `image_digest` raises `SandboxError` (`sandbox.py:147-160`), and the pipeline checks the digest before the cache lookup and turns the failure into an `error` verdict with coverage `sandbox: failed` (`pipeline.py:139-153`). It is checked first because the digest is part of the cache key.

### `--local-index` precedence (`4591a2a`)

The demo repository ships its planted wheels in `vendor/wheels` and passes `local-index: vendor/wheels` to the action. The first version of `--local-index` *replaced* PyPI: every spec had to be in the directory. That broke two demo cases: the benign bump `six==1.17.0` and the forced download failure `six==99.0.0` both need real PyPI. Now the index takes precedence and anything not in it is fetched from PyPI as usual (`pipeline.py:77-94`, `203-208`). The local-index resolver is deliberately minimal: it refuses wheels that declare dependencies (`pipeline.py:91-92`), marked with a `ponytail:` comment, because the planted wheels have none.

### Policy for PR-proposed local wheels (`cfaae00`)

`--local-index` wheels arrive through `from_local_artifact`, so their origin is `local_artifact`, which the FR-4.10 policy guard originally never executed. But a wheel that a PR adds to its own repository is exactly a "package a PR actually proposes", which the PRD allows to run. The rule became: `local_artifact` runs only when the caller marks it a PR candidate (`sandbox.py:191-192`). Only `pipguard ci` sets that flag. `pipguard scan --artifact` and the evaluation batch runner never set it, so arbitrary local files and the archived malware corpus remain static-only. `docs/DESIGN.md`'s policy paragraph still says `local_artifact` "never runs" and needs updating.

## The demo (Track C)

Everything is under `demo/`:

- `planted/requets/`: a typosquat of `requests` that on import reads `~/.aws/credentials` (keeping only its length), runs `sh -c "curl --version"`, and attempts `connect()` to `203.0.113.50:443`. Harmless by design: it sends nothing, and 203.0.113.0/24 is TEST-NET-3 (RFC 5737), which routes nowhere. It is never published to PyPI and runs only in the network-less sandbox.
- `planted/sleepy/`: `time.sleep(600)` at import, to force a timeout.
- `build_wheels.py`: builds both with `scripts/make_wheel.py`, which zips files and runs no package code.
- `template/`: the demo repo's starting point: `requirements.txt` (`six==1.16.0`), `pipguard.toml` (import timeout lowered to 30 s so the timeout case finishes quickly), and `.github/workflows/pipguard.yml` (on `pull_request`, `contents: read`, `pull-requests: write` only for the comment, checkout with `fetch-depth: 0`, the action pinned to a commit SHA, `local-index: vendor/wheels`).
- `make_prs.sh OWNER/DEMO OWNER/PIPGUARD SHA`: refuses a SHA that is not 40 hex characters, copies the template, builds the wheels into `vendor/wheels`, pins the action, creates a **public** repo with `gh` (Actions minutes are free only on public repos), and opens five PRs.

| PR | Change | Expected verdict | Check |
| --- | --- | --- | --- |
| add-planted | `requets==2.31.0` | `block` | fails |
| benign-bump | `six` 1.16.0 → 1.17.0 | `allow` | passes |
| unpinned-spec | `flask>=3` | `warn` (not an exact pin, not scanned) | passes with warning |
| forced-timeout | `sleepy==1.0.0` | `incomplete:timeout` | fails |
| download-failure | `six==99.0.0` | `error` | fails |

### What has been verified, and what has not

Verified locally:

- A local end-to-end `pipguard ci` run over the demo changes produced `block` for `requets` with reasons for the credential read plus subprocess/connect, the typosquat of `requests`, and the raw IP; `incomplete:timeout` for `sleepy`; `warn` for `flask>=3`; overall exit code 3 (an incomplete verdict outranks block).
- `pipguard scan six==1.17.0` with the sandbox: `allow` in 21 s.
- `pipguard scan six==99.0.0`: `error`, exit 3, in 3 s (404 is not retried).
- `tests/test_demo.py`: the demo config is valid, the planted wheel blocks on static evidence alone (typosquat), and the demo workflow is read-only and never uses `pull_request_target` or `continue-on-error`.

Not done:

- The demo repository has **not** been pushed and the five PRs do not exist on GitHub, so the Track C table in `docs/EVAL.md` is empty, there is no GIF, and no CI timings (p50/p95) exist.
- CI has not run on GitHub, so the action and the spike have not run on `ubuntu-latest`.

To run it: push pip guard to a public GitHub repo, note a commit SHA, `gh auth login`, then `bash demo/make_prs.sh <you>/pipguard-demo <you>/pip-guard <sha>`.

## Limitations and known gaps

- The planted package's behaviour is at import, not install; the PRD's use case 1 describes a connect "during pip install", which a wheel cannot do. The demo shows the realistic case (import-time payload).
- The local-index resolver does not resolve dependencies.
- The forced-download-failure case depends on PyPI not having `six==99.0.0`.
- Track C will measure the five cases once; it is a demonstration, not a statistical evaluation.
- `docs/PLAN.md` has not been ticked for most completed steps, and `docs/DESIGN.md` lags the code in a few places (listed in the hand-off report).

## Interview questions

**How did you build six workstreams in parallel without constant merge conflicts?**
The shared contract (pydantic models, the feature vector, errors and config) was written and committed first, and every workstream built against it in its own worktree. Each boundary took an injectable dependency (an HTTP opener, a Docker runner, a fetcher), so each workstream's tests ran alone. The evaluation scripts imported other workstreams lazily so they could be written before those workstreams merged.

**What bug only appeared when the workstreams were combined?**
Double escaping: the rules module escaped reasons for Markdown and the report module escaped table cells again, so the summary showed entity codes. Each module was right on its own; the fix was a single rule, escape once at the Markdown boundary. The same integration pass found false positives on real packages (private IPs in test code, vendored `setup.py` files, `six` versus `pip`), which unit fixtures had not exercised.

**Why does the demo ship its malicious package as a wheel in the repo instead of publishing it?**
Publishing a credential-stealer look-alike to PyPI, even a harmless one, would put a typosquat in front of real users and violate PyPI's policies. Shipping it in the demo repo and resolving it through `--local-index` keeps it contained. The wheel is still a PR-proposed package, so the policy guard allows it to run in the sandbox.

**Why does `--local-index` take precedence over PyPI instead of replacing it?**
The demo needs both: the planted wheels come from the repo, but the benign bump and the forced download failure must hit real PyPI to show realistic behaviour. Replacing PyPI made every non-planted spec fail. With precedence, only specs present in the directory come from it.

**Is it safe that local wheels can now run in the sandbox?**
Only local wheels the PR itself proposes, through the `ci` command, are marked as PR candidates. `scan --artifact` and the evaluation runner never set that flag, so arbitrary files and archived malware stay static-only, and a unit test checks the batch runner never imports the sandbox. The rule matches the PRD's wording: the sandbox runs fixtures and packages a PR actually proposes.

**Why is the demo payload harmless, and how do you know?**
It reads the credential file, keeps only its length and never sends anything, its subprocess is `curl --version`, which transmits nothing, and it connects to a TEST-NET-3 address reserved for documentation that routes nowhere. On top of that it runs only inside a container with no network. It demonstrates the observable shape of an attack without being one.

**Why did the local `ci` run exit 3 rather than 2 when it contained a block?**
The run included the forced-timeout package, whose verdict was `incomplete`, and `error`/`incomplete` outrank `block` in the exit code. Both fail the check; 3 says that something was not fully examined, which must never be hidden behind a "blocked" result. Each package's own verdict is still shown in the summary table.
