# Build log 05: rules and scoring (Workstream D)

`src/pipguard/rules.yaml`, `src/pipguard/rules.py`, `src/pipguard/scoring.py`. Commits `68ca4ff` (rules), `798cfb6` (scoring), `385d7c2` (escape once, moved to `report.py`).

## What was built

| FR | Requirement | Where |
| --- | --- | --- |
| FR-5.1 | Blocking rules force `block`; warning rules force at least `warn`; both in `rules.yaml` | `rules.yaml`, `scoring.py:204-210` |
| FR-5.2 | Model ladder at runtime: rules-only or logistic regression; LightGBM refused until adopted | `scoring.py:62-115` |
| FR-5.3 | `Verdict` with level, score, score label, reasons, coverage, overrides, model version, thresholds | `scoring.py:241-254`, `models.py:371-394` |
| FR-5.4 | Every `warn`/`block` has a reason; a blocking hit always blocks; a warning hit never allows | `models.py:389-394`, `scoring.py:204-239` |
| FR-5.5 (P1) | Coefficient contributions through a fixed template | `scoring.py:128-139` |
| FR-5.8 | Thresholds stored with the model; 0.5/0.85 placeholders | `models.py:321-330`, `scoring.py:123-125` |
| FR-7.2 | Allowlist caps at `warn`, reported, never hides observations | `scoring.py:225-228` |

There is no trained model yet (Track A not run), so every scan currently uses `RULES_ONLY` (`scoring.py:47`).

## How it works

### The rule language

A rule (`rules.py:101-105`) has an `id` (`^[A-Z][A-Z0-9_]{0,63}$`), a description, a reason template and a `when` condition. A condition is one of:

- a leaf `{feature, op, value}` with `op` in `>=`, `>`, `==`, `<=`, `<` (`rules.py:72-85`);
- `{all: [conditions]}` or `{any: [conditions]}`, nested to any depth (`rules.py:88-98`).

`load_rules` reads the file with `yaml.safe_load` and validates it with pydantic (`rules.py:155-165`). At load time, every feature name must be in `FEATURE_NAMES` (log 01) or the rule-only extra `connect_install_external_count`; rule ids must be unique; every `{placeholder}` in a reason must be a plain known name with no attribute access, indexing, conversion or format spec (`rules.py:112-146`). A missing, malformed or empty rules file is a `PipGuardError`, so the scan fails closed rather than allowing everything. At evaluation, a feature the caller did not supply raises instead of silently evaluating to false (`rules.py:171-174`, `198-201`).

`build_inputs(static, trace)` (`rules.py:227-260`) returns the feature dict from `vectorize()`, plus `connect_install_external_count` (install-step IP connects that are not loopback or unspecified, `rules.py:211-219`), plus raw evidence strings for templates: the first connect endpoint per step, the first credential path, the first subprocess argv and the first *suspicious* one, the first outside write, the first raw IP, the first shortener, and the typosquat target.

`render` fills a template with every value passed through `safe_text` (`rules.py:184-188`): control and format characters (newlines, bidi overrides, zero-width) become spaces and the text is capped at 120 characters. `safe_text` deliberately does **not** Markdown-escape (see "Escaping once" below).

### The rules (`rules.yaml`)

Blocking (each must reach ≥ 0.95 precision on the stratified benign sample; not yet measured):

| Id | Fires when | Line |
| --- | --- | --- |
| `B_CONNECT_INSTALL` | ≥ 1 `connect()` to a non-loopback IP during pip install | `rules.yaml:15` |
| `B_CREDENTIAL_EXFIL` | credential file read **and** a subprocess or `connect()` in the same trace | `rules.yaml:20` |
| `B_TYPOSQUAT_TOP100` | typosquat distance ≤ 1 to a top-100 name | `rules.yaml:26` |

Warning: `W_INSTALL_HOOK` (cmdclass or overridden install command), `W_PTH_IMPORT`, `W_IP_LITERAL`, `W_URL_SHORTENER`, `W_TYPOSQUAT` (the FR-3.6 indicator fired), `W_SUSPICIOUS_SUBPROCESS` (argv names curl/wget/a shell/powershell/nc), `W_CONNECT_IMPORT`, `W_CONNECT_INSTALL` (any install connect, including loopback and Unix sockets), `W_CREDENTIAL_READ`, `W_WRITE_OUTSIDE`, `W_OBFUSCATION` (a decoder *and* `exec`/`eval`) (`rules.yaml:36-100`).

For the demo's `requets`, the hits are `B_CREDENTIAL_EXFIL`, `B_TYPOSQUAT_TOP100`, and the warnings `W_IP_LITERAL`, `W_TYPOSQUAT`, `W_SUSPICIOUS_SUBPROCESS`, `W_CONNECT_IMPORT`, `W_CREDENTIAL_READ`.

### Level precedence (`scoring.score`, `scoring.py:182-254`)

In this order:

1. **Rules.** Any blocking hit → `block`; else any warning hit → `warn`; else `allow`.
2. **Model.** If a model is loaded, its score is compared with the effective thresholds. At or above `block` → model level `block`; at or above `warn` → `warn`. The model's reasons (score plus the top three positive contributions) are added, and the level is raised **only if the model's level is higher** (`scoring.py:213-223`). The model never lowers a rule result.
3. **Allowlist.** If the level is `block` and the PEP 503 name is in `config.allowlist`, cap it at `warn` and record the override "allowlisted in pipguard.toml: capped block → warn" (`scoring.py:225-228`). All reasons stay. A `warn` stays `warn`; the allowlist never produces `allow` from a rule hit.
4. **Incomplete evidence.** If the sandbox evidence is incomplete, add a reason naming the completeness state and its sanitised detail, and set the level to `incomplete` **unless it is already `block`** (`scoring.py:230-239`). An allowlisted package capped to `warn` with an incomplete trace therefore becomes `incomplete`, which fails the check.

"Incomplete" is decided by `_sandbox_state` (`scoring.py:145-155`):

| Trace | Sandbox requested | Coverage status | Complete? |
| --- | --- | --- | --- |
| none | yes | failed | no |
| none | no (`--no-sandbox`) | skipped | yes |
| `complete` | any | completed | yes |
| `skipped:policy` | yes | skipped | no |
| `skipped:policy` | no | skipped | yes |
| any other `incomplete:*` | any | failed | no |

A `skipped:policy` trace contains no behaviour, so it is not vectorised; otherwise `behaviour_available` would be 1 for a package that was never run (`scoring.py:196-202`).

### Coverage

Every verdict carries `Coverage` (`scoring.py:158-176`): status of fetch, static, sandbox and scoring; the sandbox completeness; each examined artifact by filename, kind and SHA-256; and `not_evaluated`, which always contains "environment-variable reads (not observable)" and "DNS names (not observable)", plus "sdist build-backend behaviour (not exercised)" when an sdist exists, plus a sandbox note when behaviour was skipped or stopped early.

`error_verdict` (`scoring.py:257-276`) and `unsupported_verdict` (`scoring.py:279-296`) build the other two verdict shapes: a failed scan (level `error`, the reason sanitised and capped at 300 chars) and a non-pin spec (level `warn`, "not scanned: …").

### Model inference

- `load_model` (`scoring.py:62-75`): no `model/model.json` in the package → `RULES_ONLY`. An explicit path that is missing, or any malformed file, raises: a broken model must never silently score everything as `allow`.
- `predict` (`scoring.py:101-115`): logistic regression as a pure-Python dot product of standardised features, `z = intercept + Σ coef × (x − mean) / scale`; with Platt parameters, `p = 1 / (1 + exp(a·z + b))`, else the plain sigmoid. The logit is clamped to ±500 before `exp`. A model feature the scanner does not compute, or a non-positive scale, raises. A LightGBM artifact raises until LightGBM inference is added.
- `score_label` is "calibrated probability" only when Platt parameters exist, else "score" (FR-5.3).
- `effective_thresholds` (`scoring.py:123-125`): the model artifact's thresholds, unless `pipguard.toml` sets thresholds that differ from the defaults.

## Key design decisions

| Decision | Reason | Rejected alternative |
| --- | --- | --- |
| A tiny interpreted condition language validated at load | Rules are data an author can review; nothing in YAML can execute | Python expressions with `eval`, or rules as Python functions |
| Unknown features and bad placeholders fail at load | A typo in a rule would otherwise silently never fire | Lazy errors at evaluation |
| Two classes: blocking and warning | `block` stops work, so only high-precision evidence may force it; everything else asks a human | One score threshold for everything |
| `B_CONNECT_INSTALL` counts only non-loopback IP connects; loopback and Unix sockets only warn | Local IPC during install is unusual but not exfiltration | Blocking on any install connect |
| `B_CREDENTIAL_EXFIL` is co-occurrence | The trace has no ordering; the PRD says "followed by", the YAML comment records the deviation | Adding timestamps to strace output (`-tt`) and ordering (more parsing, more attacker-controlled text) |
| Model can raise, never lower | A rule hit is direct evidence; a score is a statistical estimate | Model overrides rules |
| Allowlist caps `block` at `warn`, keeps reasons, never overrides `incomplete` | An escape hatch for known-noisy packages that still shows evidence and cannot pass an unexamined package | Skipping allowlisted packages; capping at `allow` |
| `incomplete` unless already `block` | Both fail the check, and `block` says more: something bad was seen in what was collected | `incomplete` always wins (would hide a blocking observation) |
| Per-package allowlist | Simplest form the PRD allows; per-(package, rule) is an open question | Per-rule allowlist (more config surface) |
| LR as plain coefficients, pure-Python inference | No scikit-learn at runtime, auditable JSON, no pickle | A pickled scikit-learn model (unpickling runs code) |
| Config thresholds win only if changed from defaults | A shipped model's tuned thresholds should not be overwritten by unchanged defaults in `pipguard.toml` | Config always wins |

### Escaping once: the decision that moved to `report.py`

Reasons contain untrusted text: file paths, argv and IPs chosen by the package. The first version of `safe_text` turned Markdown and HTML metacharacters into entities when the reason was built. `report.py` independently escapes every table cell. The result was **double-escaped** output: the second pass escaped the `&` and `#` of the first pass's entities, so the rendered job summary showed literal entity codes (such as `&#95;` where `_` was meant), and the JSON report carried escaped text instead of the plain reason.

The fix (`385d7c2`): `safe_text` only strips control/format characters and caps length, which keeps a reason one bounded line of plain text; `report.py._cell` is the single place that escapes for Markdown (`report.py:50-58`). The rule is "escape once, at the boundary where the text becomes Markdown". Tests assert both that hostile values are one line and that a hostile trace never breaks the summary table (`tests/test_rules.py`).

## Limitations and known gaps

- Blocking-rule precision (≥ 0.95) is required but **not measured yet**; it depends on Track A. Any blocking rule that misses it must move to `warning` (`rules.yaml` header).
- No trained model exists, so `score` is `None` and every verdict is rules-only.
- LightGBM inference is not implemented; `train.py` writes the artifact separately if LightGBM is adopted, and `scoring.py` refuses it (FR-5.2).
- `B_CREDENTIAL_EXFIL` cannot distinguish "read credentials, then exfiltrate" from "spawned a harmless subprocess, and separately read a credential file".
- `B_CONNECT_INSTALL` and `W_CONNECT_INSTALL` will rarely fire on wheels, because installing a wheel runs no code; they exist for completeness and for any future sdist path.
- The comment at `rules.yaml:12` still says values are "Markdown-escaped before it goes in"; that is no longer true (escaping moved to `report.py`). `docs/DESIGN.md` Workstream D notes say the same; both are stale.

## How it is tested

- `tests/test_rules.py`: a clean package fires nothing; behavioural, static and typosquat rules; reason rendering; IPv6 endpoints and missing evidence ("unknown"); hostile values stay one line; `safe_text` caps; a hostile trace never breaks the Markdown table; custom rule files load; bad rule files raise (unknown feature, unknown or formatted placeholder, unsupported operator, bad id, duplicate id, empty `all`, extra keys, no rules, malformed YAML, and a `!!python/object/apply` tag that `safe_load` refuses); missing file raises; a missing feature at evaluation raises; evidence keys and extra features cover the contract.
- `tests/test_scoring.py`: clean complete trace allows; blocking hit blocks; warning hit warns; allowlist caps block at warn and keeps reasons; allowlist never lowers warn to allow; incomplete trace is incomplete; incomplete with a blocking hit stays block; incomplete allowlisted block stays failing; sandbox requested but no trace is incomplete; `--no-sandbox` uses static evidence; LR prediction on known numbers; model errors; the model warns and blocks with contributions; the model cannot lower a rule level; threshold precedence; model loading; error and unsupported verdicts.

## Interview questions

**Why not let the model decide everything?**
The model's numbers are not measured yet, and even once they are, a score is a statistical estimate over a population. A rule hit such as "read `~/.aws/credentials` and spawned `sh -c curl`" is direct evidence about this artifact. So rules set a floor, the model may raise the level when it sees a risky combination, and it can never lower a rule result.

**What makes a rule "blocking"?**
It must reach at least 0.95 precision on the stratified benign sample, because a false block stops a team's work. The three blocking rules are the ones the PRD names: an external connect during install, a credential read together with a subprocess or connect, and a name within one edit of a top-100 package. Their precision still has to be confirmed by the evaluation, and any that misses moves to warning.

**How does the allowlist interact with failures?**
It only ever caps `block` at `warn`, keeps all the reasons, and is named in the summary. It is applied before the incomplete check, so an allowlisted package whose sandbox run timed out becomes `incomplete` and still fails. That means an allowlisted package that is later hijacked still shows its evidence, and an unexamined one never passes.

**Why is the rule condition language so small?**
Rules are configuration that a reviewer should be able to read and that must never become code. Comparisons and `all`/`any` cover every rule in the PRD, and everything is validated at load: unknown features, malformed placeholders and duplicate ids are errors. Anything more expressive would invite `eval`, which would turn a YAML file into an execution path.

**Why is "credential read plus subprocess" called co-occurrence and not "followed by"?**
The trace records observations per step but not their order, because strace was run without timestamps to keep traces small and parsing simple. So the rule says both happened in the same run, which the YAML comment records as a deviation from the PRD's wording. In practice, reading credentials and also spawning a shell or connecting during install or import is already a strong signal.

**What was the double-escaping bug?**
Reasons were escaped for Markdown when they were built, and the report escaped every table cell again, so the job summary showed entity codes instead of characters and the JSON report had escaped text in it. The fix was to escape exactly once, at the boundary where text becomes Markdown. `safe_text` now only removes control characters and caps length.

**Why store the logistic regression as plain numbers?**
Inference is a dot product and a sigmoid, which is a few lines of Python, so scikit-learn is not needed at runtime. Plain JSON coefficients can be reviewed and diffed, and loading them runs no code, unlike a pickled model. The training script writes means, scales, coefficients, intercept, Platt parameters and thresholds, and a test checks the pure-Python prediction against known numbers.
