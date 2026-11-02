# Build log 06: diff, cache, report, action, pipeline and CLI (Workstream E)

`src/pipguard/diff.py`, `cache.py`, `report.py`, `action/action.yml`, `action/map_exit.sh`, and the integration layer `pipeline.py` and `cli.py`. Commits `7248150` (diff, cache, report, action), `61f88bb` (pipeline and CLI), `7da8fd4` and `5d97506` (action hardening and its tests).

## What was built

| FR | Requirement | Where |
| --- | --- | --- |
| FR-1.1 | Added or changed exact pins between base and head in `requirements.txt` and PEP 621 `[project] dependencies` | `diff.py:146-175` |
| FR-1.2 | Every non-pin is `unsupported` with a reason and a `warn` verdict; no resolution | `diff.py:41-79`, `scoring.py:279-296` |
| FR-1.3 | SQLite cache keyed by artifact SHA-256, scanner, model, config (+ image digest); no writes on forks; best-effort | `cache.py` |
| FR-6.1 | Job summary: package, artifact, verdict, coverage, top reasons; `allow` rows collapsed | `report.py:111-144` |
| FR-6.2 | `block`/`error`/`incomplete` fail; `warn`/`allow` pass; README warns about `continue-on-error` | `report.py:38-47`, `README.md` |
| FR-6.3 | gzip JSON report always; traces only for non-`allow`, capped at 5 MB per package | `report.py:164-201` |
| FR-6.4 (P1) | One PR comment on same-repo PRs, updated in place; skipped on forks with a note | `action/action.yml:121-139`, `report.py:147-152` |
| FR-6.6 | Composite action maps exit codes explicitly, with a test per mapping | `action/map_exit.sh`, `tests/test_action.py` |
| FR-7.1 | `scan <name==version>` JSON, `--pretty`, `--no-sandbox`, `--artifact` | `cli.py:62-97` |
| FR-7.3 (P1) | `explain <spec>`: trace, features, rule evaluations | `cli.py:160-189` |
| FR-7.4 | Exit codes 0 / 1 (`--fail-on-warn`) / 2 / 3 | `report.py:38-47`, `cli.py:198-213` |

## How it works

### Diff (`diff.py`)

`read_files_at(ref, paths)` (`diff.py:178-198`) checks the ref with `git rev-parse --verify --quiet <ref>^{commit}` and refuses refs that start with `-` (so a ref cannot be read as a git option). An unknown ref raises: a base that cannot be read must not look like "no dependencies". A file missing at a ref reads as empty.

Parsing is conservative and has no `packaging` dependency:

- `parse_requirement` (`diff.py:41-79`) accepts only `name==version` with a valid version. Everything else becomes an `unsupported_reason`: `name @ url`, URLs and local paths, extras (FR-1.4 is P2), environment markers, no specifier, `===`, ranges (`>=`, `~=`, …), multiple specifiers, wildcards.
- `parse_requirements` (`diff.py:100-119`) joins backslash continuations, strips comments the way pip does (`#` at line start or after whitespace, so `url#egg=` survives, `diff.py:25`), reports `-r`/`-c` includes and `-e` editables as unsupported, ignores other option lines, and drops per-requirement options such as `--hash=...`.
- `parse_pyproject` (`diff.py:122-132`) reads only `[project] dependencies`; malformed TOML or a non-list is an error.
- `diff_dependencies` (`diff.py:146-175`) compares per file. A requirement is unchanged if the base file has the same name with the same identity: `==version` for pins, the whitespace-stripped lowercased line otherwise (`diff.py:139-143`). Otherwise it is `ADDED` (name not in base) or `CHANGED` (name present, version or pin-ness differs). Removed and unchanged requirements produce nothing. A move between files is rescanned.

### Cache (`cache.py`)

One table, primary key (artifact SHA-256, scanner version, model version, config hash, image digest) (`cache.py:32-42`). The image digest is `''` for static-only verdicts, so a static-only result never satisfies a sandboxed lookup.

The restored file comes from the GitHub Actions cache and is treated as hostile (`cache.py:46-63`):

- `PRAGMA trusted_schema = OFF` (no schema-defined functions or views run with elevated trust), `cell_size_check = ON`, and `quick_check` must return `ok`.
- A different `user_version` drops the table and starts over.
- Reads filter rows over 6 MB in SQL, validate the JSON with the `Verdict`/`BehaviorTrace` models, and then check that the row's **own** content agrees with its key: same schema version, cacheable level, same scanner and model version, and the artifact hash appears in the verdict's coverage (`cache.py:194-202`); for traces, same artifact and image digest.
- Every failure is a miss plus a warning, never a crash and never a trusted verdict.

Writes (`cache.py:141-191`) are skipped when `read_only` (fork PRs), for `error`/`incomplete`, for a verdict that does not cover the artifact it is filed under, for a trace of a different artifact or image, and for rows over 6 MB.

### Report (`report.py`)

- `exit_code` (`report.py:38-47`): 3 if any `error`/`incomplete`, else 2 if any `block`, else 1 if `--fail-on-warn` and any `warn`, else 0. Both fail the job; `error`/`incomplete` wins so that a run in which some package was not fully examined is always reported as such, even if another package was blocked.
- `_cell` (`report.py:50-58`) makes untrusted text inert in a Markdown table: whitespace collapsed to one line, length capped, a zero-width space inserted into `@`, `://` and `www.` (no mentions, no autolinks), then the characters ``& < > | ` * _ [ ] ( ) ! # ~ \ $ :`` turned into numeric entities.
- `render_summary` (`report.py:111-144`): a headline (`PASS`, `PASS with warnings`, `FAIL: blocked`, `FAIL: error or incomplete scan (failing closed)`, …), counts per level, a table of non-`allow` rows, `allow` rows inside a collapsed `<details>`, overrides, notes, a fork note, a "never observed" footer, and the scanner version and correlation ID.
- `render_comment` (`report.py:147-152`) prefixes `<!-- pipguard-report -->` so the action can find and update its own comment, capped at 60,000 characters (GitHub's limit is 65,536).
- `write_report_artifact` (`report.py:178-201`) writes the whole `ScanReport` as gzip JSON. A trace is dropped only when its spec's verdict is `allow`; each kept trace goes through `cap_trace`, which halves every list until the JSON fits in 5 MB and marks it truncated (`report.py:164-175`).

### Pipeline (`pipeline.py`)

`scan_spec` → fetch (or local index) → `scan_fetched` → extract → image digest → cache → static → sandbox → score → cache write (`pipeline.py:119-223`). The module docstring states the rule: every failure path ends in a `Verdict`, never an exception and never `allow`.

- `FetchError` → `error` with coverage `fetch: failed` (`pipeline.py:209-219`).
- `ExtractionError` → `error`, "unsafe archive" (`pipeline.py:128-136`).
- Sandbox image unavailable → `error` before any cache lookup (`pipeline.py:139-153`). So a cached verdict is not served when the sandbox cannot be checked, because the cache key needs the image digest.
- Anything else, including unexpected exceptions, is caught by `_guarded` and becomes `error` with "internal scanner error (<Type>); failing closed" (`pipeline.py:245-256`).
- `scan_changes` turns unsupported changes into `warn` verdicts and scans the rest into one `ScanReport` with per-stage timings (`pipeline.py:259-286`).

### CLI (`cli.py`)

- `pipguard scan SPEC | --artifact PATH` (`cli.py:62-97`): exactly one of the two. A spec the developer names is treated as a PR candidate (PRD use case 4); an `--artifact` file is not (log 04). Prints JSON or a `--pretty` table and exits with `exit_code`.
- `pipguard ci --base REF [--head REF] …` (`cli.py:100-157`): diffs the watched files, scans changes with `pr_candidate=True`, appends the summary to `$GITHUB_STEP_SUMMARY`, writes the report and the comment body, and exits with `exit_code`. A diff failure exits 3.
- `pipguard explain SPEC` (`cli.py:160-189`): verdict, full feature dict, every rule hit with its reason, static features, and the trace as JSON.
- `main` (`cli.py:198-213`) runs typer with `standalone_mode=False`. Click's usage errors exit with code 2 by default, which would read as `block`; here they are recognised by their `show()` method, shown, and mapped to 3. Any other uncaught exception prints "pipguard crashed …: failing closed" and exits 3.

### The composite action (`action/action.yml`)

1. `setup-uv`, pinned to a commit SHA.
2. **Detect fork PR** (`action.yml:50-55`): the head repo differs from the base repo.
3. **Install from the action's own checkout** (`action.yml:60-64`): `uv sync --locked --no-default-groups --project "$GITHUB_ACTION_PATH/.."`. `--locked` installs exactly the hash-pinned `uv.lock`; `--no-default-groups` skips dev and eval dependencies. Not `uv tool install`, because the typosquat snapshot, `rules.yaml` and the seccomp profile live in the repo next to the code (`sandbox.py:43-46`).
4. **Restore the cache** with `actions/cache/restore` (untrusted, see above).
5. **Build the sandbox image** from the action's checkout.
6. **Scan** (`action.yml:78-101`): inputs reach the script only through `env:`, never `${{ }}` inside `run:`, so a crafted input cannot inject shell. `--read-only-cache` is added unless `IS_FORK` is exactly `false`. The step runs with `bash -e`, so the CLI call is written `… || code=$?`; the code is written to `$GITHUB_OUTPUT` and the step exits with it.
7. **Save the cache** only when not a fork.
8. **Upload the report** (`if: always()`), 14-day retention.
9. **Post or update the PR comment** only on same-repo `pull_request` events (`action.yml:121-139`). It looks for a comment by `github-actions[bot]` that starts with the marker and edits only that one; otherwise posts a new one. Failure only warns.
10. **Map exit code** (`if: always()`, `action.yml:142-147`): `map_exit.sh` exits 0 for 0, and 1, 2, 3 with a `::error::` annotation for the others; any other value, including empty (the scan step never ran), exits 3. The unexpected value is echoed only if it is 0-16 alphanumerics, so it cannot inject a workflow command.

## Key design decisions

| Decision | Reason | Rejected alternative |
| --- | --- | --- |
| Only exact pins are scanned; everything else is `warn` with a reason | Exact pin = exact artifact; anything else would need resolution, which is out of scope | Resolving ranges with pip (runs on the host, may build sdists) |
| Unknown git ref raises | An unreadable base would otherwise look like "everything added" or "nothing changed" | Treating a missing ref as empty |
| Image digest in the cache key | PRD: a behavioural result is reused only for the identical artifact and runtime image | Key without the image (stale behaviour after a sandbox change) |
| Never cache `error`/`incomplete` | They describe a failed run, not the artifact; caching would either block forever or hide an unexamined package | Caching every verdict |
| Restored cache treated as hostile | It crosses a trust boundary (Actions cache can be written by other workflows on the repo) | Trusting the file |
| `error`/`incomplete` outrank `block` in the exit code | Fail closed, and a scanner failure must not be read as a security finding | `block` wins |
| Escape once, in `_cell` | One place to audit; reasons stay readable in JSON | Escaping at rule render time (double escaping, log 05) |
| Click usage errors mapped to 3 | Click's default 2 collides with `block` | Leaving typer's standalone mode on |
| Action runs from its own locked checkout | Supply chain: exactly the reviewed code and lock; data files available | `uv tool install pipguard` from PyPI |
| Inputs via `env:` only | Prevents expression injection into shell | `${{ inputs.x }}` inside `run:` |
| `|| code=$?` then exit, then a separate always-run map step | A failing scan step would otherwise skip the steps that record and upload results | `continue-on-error: true` (defeats enforcement) |
| Edit only the bot's own marked comment | Another user's comment containing the marker must not be overwritten | Matching on the marker alone |
| Comment skipped on forks, summary says so | Fork PRs get a read-only token; `pull_request_target` would give write access to untrusted code | `pull_request_target` |

## Limitations and known gaps

- No lockfiles, Poetry tables, `requirements*.txt` globs, extras or markers (FR-1.4, FR-1.5 are P2).
- Transitive dependencies are not scanned.
- `scan --artifact` with the sandbox requested is always `incomplete` unless a static blocking rule fires (policy: arbitrary local files never run). `README.md`'s "Run it locally" section shows `scan --artifact` without `--no-sandbox`, which will exit 3 for an ordinary wheel.
- The image is rebuilt on every action run; the PRD's "publish to GHCR with its digest" is not done.
- Scan-time targets (p50 ≤ 3 min uncached, ≤ 10 s cached on `ubuntu-latest`) are unmeasured until the demo runs on GitHub. Locally, `six==1.17.0` took 21 s with the sandbox.
- The action has not run on GitHub yet; its tests check the parsed YAML, not a live run.

## How it is tested

- `tests/test_diff.py`: exact pins; every unsupported form; requirements file handling (comments, continuations, options, includes, editables); trailing continuation; PEP 621 only; malformed pyproject raises; added/changed/removed/unchanged; whitespace-only change is unchanged; new files; a parser that never crashes; `read_files_at` against a temporary git repo, and a bad ref raises.
- `tests/test_cache.py`: round trip sets `cache_hit`; any key difference misses; fork read-only skips writes; failed runs never cached; a verdict not covering its artifact is not cached; trace round trip with image digest; corrupt file, foreign schema, old schema, hostile rows, hostile trace rows, oversized row, unopenable path and SQLite read errors are all misses.
- `tests/test_report.py`: exhaustive exit-code table; summary layout and headline; empty and fork summaries; unsupported rows use the raw spec; `_cell` neutralises markup; hostile strings cannot change the table shape; comment marker and cap; the report artifact keeps only non-`allow` traces and applies the 5 MB cap.
- `tests/test_action.py`: `map_exit.sh` run for every code including garbage and no argument; the parsed action has no `continue-on-error` and no `pull_request_target`; every `uses:` pinned to a 40-hex SHA; upload and map steps always run; the scan step records and propagates its code; cache save and comment skip forks; the action installs locked from its own path and edits only its own comment.
- `tests/test_pipeline.py`, `tests/test_cli.py`: benign static-only is `allow`; fetch failure, corrupt archive, missing image and unexpected crash are `error`; incomplete sandbox fails closed; sandbox credential exfiltration blocks; cache hit and fork read-only; unsupported plus scanned changes; local index and its dependency refusal; `ci` blocks a typosquat and writes summary, report and comment; no changes passes; bad ref exits 3; usage errors and crashes exit 3.

## Interview questions

**What counts as a "changed" dependency?**
Per file, a requirement whose name is new is added, and one whose name exists in the base but with a different pinned version, or that switched between pinned and unpinned, is changed. Whitespace-only edits are unchanged, and removals produce nothing. Only exact `==` pins are scanned; anything else gets a `warn` verdict that says exactly why it was not scanned.

**Why is the cache key so long?**
The verdict depends on the exact bytes (artifact hash), the scanner's code (scanner version), the model, the user's config (thresholds and allowlist), and for behaviour, the sandbox image. If any of those changes, an old verdict might be wrong, so it must miss. Static-only verdicts store an empty image digest so they never satisfy a sandboxed lookup.

**Why treat your own cache file as untrusted?**
It is restored from the GitHub Actions cache, which crosses a trust boundary, so a poisoned file could otherwise inject an `allow`. The cache turns off trusted schema, checks database integrity, validates every row with pydantic, and checks that the row's own versions and artifact match the key it is stored under. Any problem is a miss, which just means the package is scanned again.

**How does the action make sure a failure fails the job?**
The scan step records the CLI's exit code even when it is non-zero, the report upload and comment run regardless, and a final always-run step maps the code: 0 passes, 1, 2 and 3 fail with an annotation, and anything else, including an empty code, fails as 3. There is no `continue-on-error`, and a test checks that. The CLI itself maps crashes and usage errors to 3.

**Why did you remap click's usage errors?**
Click exits with code 2 on a usage error, such as a missing option. In pip guard, 2 means `block`, so a broken invocation would have been reported as "a dependency looks malicious". Running typer with `standalone_mode=False` lets the CLI catch those errors and exit 3, which correctly says the scan did not happen.

**How do you prevent a malicious package from breaking the Markdown summary?**
Every untrusted value goes through `_cell`, which collapses it to one line, caps its length, breaks mentions and autolinks with a zero-width space, and converts every Markdown or HTML-active character to a numeric entity. So a package name or path containing `|`, backticks, `<script>` or `@someone` renders as text and cannot add a table column, a link or a notification. A test feeds hostile strings and checks the table shape is unchanged.

**Why does the action not use `pull_request_target`?**
`pull_request_target` runs with a write token and secrets in the context of the base repository, and checking out and running a fork's code there is a well-known way to give an attacker write access. pip guard runs on `pull_request` with a read-only token, so fork PRs simply skip the comment and cache writes and say so in the summary. The job summary and check status are the product; the comment is a convenience.
