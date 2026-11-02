# Build log 02: fetch and safe extraction (Workstream A)

`src/pipguard/fetch.py` and `src/pipguard/extract.py`. Commit `729f076`, with `45b3871` (musllinux removed from sandbox tags).

## What was built

| FR | Requirement | Where |
| --- | --- | --- |
| FR-2.1 | Resolve `name==version` via the PyPI JSON API; pick the wheel for the sandbox and the sdist; record filename, kind, SHA-256, tags | `fetch.py:566-599`, `fetch.py:198-243` |
| FR-2.2 | Verify every download against PyPI's SHA-256; mismatch is an error | `fetch.py:118-143` |
| FR-2.3 | Safe extraction: path containment, no links, 100 MB / 500 MB / 20,000-entry limits | `extract.py` |
| FR-2.4 | Metadata: release date, version count, maintainer count (missing), days since release / first release, project URLs | `fetch.py:264-297` |
| FR-2.5 | Declared dependencies from wheel METADATA; download their wheels for the untraced preinstall | `fetch.py:303-321`, `fetch.py:520-560` |
| FR-7.1 | `--artifact <path>` wraps a local wheel or sdist | `fetch.py:602-641` |

Nothing in either module runs package code. Every PyPI response and every downloaded byte is treated as untrusted.

## How it works

### Network access (`PyPIClient`)

`PyPIClient` is the only class that touches the network, and tests inject a fake `opener` (`fetch.py:70-77`).

- **https only.** `urllib.request.urlopen` also speaks `file://` and `ftp://`; `_retry` refuses any URL that does not start with `https://` (`fetch.py:80-81`), because download URLs come from PyPI's JSON.
- **Retry with backoff, then fail closed.** Three tries with 1 s and 2 s sleeps, then `FetchError` (`fetch.py:79-94`). A 404 is raised immediately as `_NotFound`: retrying a missing version only wastes time. This is why `six==99.0.0` fails in about 3 s.
- **Byte caps while streaming.** JSON is capped at 64 MB (large projects' release JSON is tens of MB), downloads at 100 MB (`fetch.py:42-43`, `fetch.py:96-105`). A declared `size` over the cap is refused before downloading (`fetch.py:229-230`).
- **Hash while streaming.** The file is written to `<name>.part` while SHA-256 is computed; on mismatch `HashMismatchError` is raised and the `.part` file deleted; only a verified file is renamed into place (`fetch.py:118-143`).
- **Filenames are validated** against `^[A-Za-z0-9][A-Za-z0-9._+!-]*$` with no `..` before being used as a path (`fetch.py:55`, `fetch.py:225-226`), so a hostile JSON response cannot write outside the download directory.

### Choosing the wheel for the sandbox, not the host

The sandbox is CPython 3.12 on linux x86_64 with glibc 2.36 (`python:3.12-slim-bookworm`). The developer's machine may be Windows or macOS, so host tags are irrelevant. `_wheel_rank` (`fetch.py:175-195`) scores each wheel:

- Platform (`_platform_rank`, `fetch.py:156-172`): `any` first, then manylinux x86_64 with the highest glibc that is still ≤ 2.36 (legacy names `manylinux1/2010/2014` mapped to their glibc), then `linux_x86_64`. Anything else, including musllinux (the image is glibc, not musl), is incompatible.
- ABI: `cp312` beats `abi3` (for `cp3x` with x ≤ 12) beats `none` with `py3`/`py312`/`cp312`.
- Ties break on filename, so the choice is deterministic.

No compatible wheel means only the sdist is fetched; the sandbox later reports `incomplete:no_wheel`. No wheel and no sdist is a `FetchError` (`fetch.py:581-582`).

### Metadata (FR-2.4)

From the version JSON and the project JSON (`fetch.py:264-297`): release date is the earliest upload time of this version's files; first release date is the earliest across all releases that still have files; version count counts only releases with files. `maintainer_count` is always `None`, because the PyPI JSON API does not expose maintainers, and `None` means missing, never zero (`models.py:96-106`). Project URLs are capped at 30 entries of 100/500 characters.

### Declared dependencies (FR-2.5)

The sandbox needs the target's dependencies to import it, but they must be installed **untraced** so their behaviour is not blamed on the target.

1. `read_requires_dist` opens the wheel as a zip and reads exactly one `*.dist-info/METADATA` (≤ 1 MB) with the stdlib email header parser; no extraction (`fetch.py:303-321`).
2. Each requirement is parsed (`fetch.py:481-496`) and its environment marker evaluated against the **sandbox's** marker environment (`SANDBOX_MARKERS`, `fetch.py:384-395`) by a small recursive-descent evaluator (`fetch.py:403-478`). `extra == "…"` is false because extras are never installed.
3. The version is resolved to the newest stable, non-yanked release that satisfies the specifiers and has a sandbox wheel (`fetch.py:499-517`). An exact pin is honoured even for a pre-release.
4. The closure is walked breadth first, first requirement per name wins, capped at 50 wheels and depth 10 (`fetch.py:520-560`).

Anything it cannot decide (a URL dependency, an unknown marker variable, a pre-release range, an sdist-only dependency) is skipped with a log line. It is not an error at fetch time, but the traced import will then fail, which is `incomplete:import_failed`, so the check still fails closed.

### Local artifacts (`--artifact`)

`from_local_artifact` parses the name and version from the filename, copies the file into the work directory, hashes the copy, and returns a `FetchedPackage` with `origin="local_artifact"` and empty metadata (`fetch.py:602-641`). The origin matters: the sandbox policy guard will not execute a local artifact unless the caller marks it as PR-proposed (log 04).

### Safe extraction (`extract.py`)

`safe_extract(archive, dest)` (`extract.py:107-133`):

1. Picks the extractor by suffix (`.whl`/`.zip` or `.tar.gz`/`.tgz`/`.tar.bz2`/`.tar`); anything else is refused.
2. Refuses archives over 100 MB on disk and a non-empty destination.
3. **Checks every entry before writing anything.** `_safe_member_path` (`extract.py:30-44`) rejects empty names, absolute paths, `..` components, backslashes, `:` (drive letters and NTFS alternate data streams), and NUL, then confirms the resolved path is inside `dest`.
4. Zip (`extract.py:57-85`): the Unix file type is read from the high 16 bits of `external_attr`; symlinks and any type other than regular file or directory are refused (a type of 0 is common and treated as a regular file). Declared sizes are summed against the 500 MB cap, and then **the bytes actually decompressed are counted while streaming**, because a zip's declared size can lie (a zip bomb).
5. Tar (`extract.py:88-104`): members are iterated, not loaded with `getmembers()`, so the 20,000-entry cap stops a header flood early. Symlinks, hardlinks and special files are refused; sizes are summed. Then `extractall(..., filter="data")` is used as a second, independent defence.
6. On any failure, `dest` is deleted (`extract.py:125-132`), so a half-extracted tree is never analysed as if it were complete. Corrupt archives (`BadZipFile`, `TarError`, `zlib.error`, `EOFError`) become `ExtractionError`.

`extract_package` extracts the target's wheel and sdist only; dependency wheels are never extracted on the host, because they are not scanned (`extract.py:136-144`).

## Key design decisions

| Decision | Reason | Rejected alternative |
| --- | --- | --- |
| Pick tags for the sandbox (cp312, linux x86_64, glibc ≤ 2.36), not the host | The wheel must install in the container; dev hosts may be Windows | `packaging.tags.sys_tags()` on the host (wrong platform) |
| No musllinux | The image is glibc; a musl wheel would fail to install, which is a false `incomplete` | Accepting any manylinux/musllinux prefix (an early version did; removed in `45b3871`) |
| Minimal PEP 440 / PEP 508 subset in-house | CLAUDE.md asks to prefer the stdlib and to ask before adding dependencies; the subset covers common specifiers and says "cannot decide" otherwise | Adding `packaging` (marked with a `ponytail:` comment as the upgrade path if a wrong version is ever picked) |
| Skip unresolvable dependencies instead of failing fetch | The import then fails and reports exactly which module failed; a fetch error would say less | Failing the whole scan at fetch time |
| 404 is not retried | A missing version will not appear in 3 seconds | Uniform retry |
| Hash while streaming into `.part`, rename after verification | An unverified file never exists under its real name | Download, then hash, then delete on mismatch |
| Pre-check every archive entry, then extract | Nothing is written if any entry is unsafe | Extract and check afterwards |
| Count streamed bytes for zips | Declared sizes in a zip header are attacker-controlled | Trusting `ZipInfo.file_size` |
| Own checks plus `filter="data"` for tar | Two independent defences; `filter="data"` also normalises permissions | `filter="data"` alone (behaviour has changed across Python versions) |
| Delete `dest` on failure | A partial tree could look clean to static analysis | Leaving partial output |

## Limitations and known gaps

- The PEP 440 subset does not handle epochs, pre/dev releases in ranges, `===`, or the rule that `>V` excludes post-releases of V (`fetch.py:324-328`). Such dependencies are skipped and the import fails closed.
- `python_full_version` is fixed at `3.12.0` in the marker environment; a marker that depends on a later patch version could be misjudged.
- Maintainer count is always missing (API limitation).
- The PRD says "download the wheel matching the runner's Python and platform"; the code deliberately matches the sandbox, which is what actually installs it. This is a refinement, documented in `docs/DESIGN.md`.
- `from_local_artifact` reads the name and version from the filename only. A local file named to look like another package is scanned under that name.
- Dependency wheels are downloaded and hash-checked but not scanned (PRD non-goal: transitive dependencies).

## How it is tested

All unit tests use a fake opener; no network.

- `tests/test_fetch.py`: wheel compatibility and ranking (`test_wheel_ranking`, `test_fetch_picks_cp312_manylinux_x86_64`), sdist-only, no artifacts, 404 without retry, hash mismatch, download cap and declared-size cap, retry then fail and retry then succeed, refusing non-https URLs and unsafe filenames, transitive dependencies with markers, the 50-wheel and depth caps, marker evaluation including "unsure" cases, specifier evaluation, and local wheels/sdists.
- `tests/test_extract.py`: zip and tar traversal, zip symlink and FIFO, tar links and devices, too many entries, zip bomb with honest and **lying** declared sizes (`test_zip_bomb_lying_declared_size`), streamed byte counting, tar bomb, compressed-size cap, corrupt archives, non-empty destination, and a property-style test that entry names never escape (`test_entry_names_never_escape`).

## Interview questions

**Why choose the wheel for the sandbox's platform rather than the machine running pip guard?**
The wheel is installed inside the container, which is CPython 3.12 on glibc 2.36 x86_64, regardless of where pip guard runs. Choosing by host tags would pick a Windows or macOS wheel on a laptop, which would then fail to install and produce a false `incomplete`. So the ranking prefers pure-Python wheels, then manylinux up to glibc 2.36, and never musllinux.

**How do you defend against a zip bomb?**
Three checks: the compressed file must be under 100 MB, the sum of declared sizes must be under 500 MB, and the bytes actually produced by decompression are counted while streaming and stopped at 500 MB. The third check matters because the declared size in a zip header is written by the attacker. There is also a 20,000-entry cap, and the destination is deleted if any limit is hit.

**What does path containment mean, and why check backslashes and colons?**
Every entry name is mapped to a path and must resolve inside the extraction directory, so `../../etc/passwd` or `/etc/passwd` is refused. Backslashes are refused because on Windows they are path separators, and colons because they introduce drive letters and NTFS alternate data streams. The check runs for every entry before anything is written.

**Why not just use `tarfile`'s `filter="data"`?**
It is used, but as a second line of defence. pip guard's own pre-checks reject links and special files and enforce size and count caps, which `filter="data"` does not do. Having two independent checks means a gap in one is not a gap in the system.

**How do you resolve declared dependencies without running pip on the host?**
The METADATA file is read straight out of the wheel zip, markers are evaluated against the sandbox's environment, and versions are chosen from the PyPI JSON with a small PEP 440 subset. The resulting wheels are downloaded and hash-checked and later installed inside the container with `--no-deps`. Running pip's resolver on the host was avoided because it can build sdists, which runs package code.

**What happens if a dependency cannot be resolved?**
It is skipped with a log line rather than failing the fetch. The traced import inside the sandbox will then fail with a named exception, which produces `incomplete:import_failed` and fails the check. That keeps the fail-closed property while giving a more specific reason.

**Why is a 404 not retried?**
Retries exist for transient failures such as timeouts and resets. A 404 from PyPI means the release does not exist, and it will not appear on a retry. Failing immediately is why a typo'd version fails the check in about 3 seconds.
