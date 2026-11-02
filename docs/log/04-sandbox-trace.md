# Build log 04: sandbox, runner and trace parser (Workstream C)

`src/pipguard/sandbox.py` (host side), `sandbox/runner.py` (in the container), `src/pipguard/trace.py` (parser). Commits `008fe1e` (parser), `702a54b` (runner, orchestration, fixtures), `63b6e3f` (Docker fixture suite, design notes), `cfaae00` (integration: `SandboxError`, PR-proposed local wheels).

## What was built

| FR | Requirement | Where |
| --- | --- | --- |
| FR-4.1 | Dependencies preinstalled untraced; target installed `--no-deps` and imported, both traced; modules found on disk in the install dir (not from the wheel's own metadata), each import verified to come from there; no module or failed import is `incomplete` | `runner.py:164-210`, `runner.py:141-161` |
| FR-4.2 | Offline installs from local wheels (`--no-index`) | `runner.py:177-190` |
| FR-4.3 | Fake credential files observed via `openat` | `trace.py:246-247`, `sandbox/manifest.json` |
| FR-4.5 | `BehaviorTrace`: outside writes, credential reads, subprocess argv, `connect()` family/address/port, exit codes, step times, completeness | `trace.py`, `sandbox.py:356-373` |
| FR-4.6 | 90 s install / 60 s import timeouts; kill the process tree; `incomplete:timeout` | `runner.py:116-128`, `sandbox.py:309-318` |
| FR-4.7 | Hardened `docker run` | `sandbox.py:59-78` |
| FR-4.10 | Execute only fixtures and PR-proposed packages | `sandbox.py:170-193` |
| FR-4.11 | strace output is attacker-influenced: caps, defensive parsing, fuzz tests | `trace.py` |

## How it works

### Host side: `sandbox.run` (`sandbox.py:274-373`)

1. **Policy guard first** (`sandbox.py:170-193`). A refused package returns `skipped:policy` without starting a container. A package without a wheel returns `incomplete:no_wheel`, also without a container.
2. **Image digest.** `docker image inspect --format {{.Id}}` must return `sha256:<64 hex>` (`sandbox.py:147-160`). The digest goes into the trace and the cache key. A missing image or Docker CLI is `incomplete:sandbox_error` here; the pipeline checks the digest earlier and turns that into an `error` verdict.
3. **Transport in.** The target wheel and dependency wheels are packed into a tar in memory (`target/<wheel>`, `deps/*.whl`, `sandbox.py:231-238`) and written to the container's stdin. No bind mounts.
4. **Run.** `docker_run_argv` builds the fixed command (`sandbox.py:59-78`); a unique name `pipguard-<uuid>` lets the host kill and remove exactly this container. `DockerRunner` runs it with list arguments (no shell), pumps stdout and stderr on threads, caps stdout at 12 MB and stderr at 64 KB, and sets `MSYS_NO_PATHCONV=1` so Git Bash on Windows does not rewrite `/tmp`-style arguments (`sandbox.py:104-136`).
5. **Backstop timeout** of `2 × install + import + 30 s` (preinstall, traced install, import, slack; `sandbox.py:311`). On expiry: `docker kill`, result `incomplete:timeout`. `docker rm -f <name>` runs in a `finally` after every run (`sandbox.py:323-324`).
6. **Transport out.** The runner prints exactly one envelope: `PIPGUARD-ENVELOPE-V1 <len>\n<json>`. The host matches the marker at the start of stdout, reads exactly `<len>` bytes, and validates them with a strict pydantic model: extra fields forbidden, at most 2 steps, at most 50 modules whose names must be Python identifiers, short strings (`sandbox.py:199-228`). Anything else is `incomplete:sandbox_error`. Stdout over the cap is `incomplete:trace_truncated`.
7. **Parse.** Each step's base64 trace is decoded (`validate=True`), the two steps share a 5 MB budget, and each goes through `parse_strace` with the credential paths from `sandbox/manifest.json` (`sandbox.py:338-354`).
8. **State** (`_verdict_state`, `sandbox.py:248-271`), first match wins: runner error → `sandbox_error`; any step timed out → `timeout`; trace over budget → `trace_truncated`; install missing or non-zero → `sandbox_error`; no modules → `no_importable_module`; import step non-zero or any module not `ok` → `import_failed` (with up to five `module (ExceptionName)` pairs, the name checked against an identifier regex); otherwise `complete`. Observations are kept in every state.

### In the container: `sandbox/runner.py`

The container's command is `python -I /opt/pipguard/runner.py <install_s> <import_s>`, so the runner is PID 1. It uses only the stdlib and is our code, never package code.

1. **Non-dumpable.** First, `prctl(PR_SET_DUMPABLE, 0)` via `ctypes` (`runner.py:87-89`). A non-dumpable process's `/proc/<pid>/fd` cannot be opened by another process of the same uid, so the package cannot open `/proc/1/fd/1` and write a forged envelope.
2. **Untar** stdin into `/tmp/in` with `filter="data"`; exactly one target wheel is required.
3. **Untraced dependency preinstall** (`runner.py:177-188`): `python -I -B -m pip install --no-deps --no-index --find-links /tmp/in/deps --target /sandbox/deps <dep wheels>`. `--no-deps` because `fetch.py` already resolved the closure. Failure → envelope error "dependency preinstall failed" → `incomplete:sandbox_error`.
4. **Traced install** (`runner.py:189-191`): `strace -f -qq -s 256 -e trace=network,process,file -o /dev/stderr python -I -B -c <PIP_PROGRAM> install --no-deps --no-index --target /sandbox/site-packages <wheel>`.
5. **Module list** (`runner.modules`): read from the filesystem under `/sandbox/site-packages`. It includes top-level `*.py` files and directories that contain any `.py`, and excludes `*.dist-info`, `*.data`, `*.egg-info`, `__pycache__` and `bin`. Identifiers only, at most 50. The import program then checks that each module's `__file__`/`__path__` resolves inside `/sandbox/site-packages`; if not, the result is `NotFromTarget`, which gives `incomplete:import_failed`. The first version trusted `top_level.txt`. The review showed that a wheel listing `json` there would import the stdlib, and an unexecuted package would come back `complete`.
6. **Traced import** (`runner.py:73-84`, `197-198`): one interpreter appends `/sandbox/deps` to `sys.path`, calls `site.addsitedir('/sandbox/site-packages')`, then imports each module and writes `{module: "ok" | ExceptionName}` to `/tmp/import_results.json`.
7. **Envelope** in a `finally`, so the host always gets one, even after an unexpected exception (reported as `runner error: <type>`).

`traced()` (`runner.py:100-138`) starts the step with `start_new_session=True` (its own process group), drains strace's output from the stderr pipe on a thread with a byte budget, and on timeout sends SIGTERM to the whole group (so strace can flush what it has), then SIGKILL after 2 s. The partial trace is still returned with `timed_out: true`.

### Parser: `trace.py`

`parse_strace(text, step, credential_paths=...)` never raises on any input (`trace.py:329-378`).

- **Caps before looking:** whole input 5 MB, each line 64 KB; extracted fields: path 512, argv 32 items × 256 chars, address 64; at most 100 distinct observations per category per step (`trace.py:27-33`). Control and NUL characters are stripped. Field and list caps set `truncated` but keep the observation; only input over 5 MB sets `input_truncated`, which becomes `incomplete:trace_truncated`.
- **No backtracking:** every regex is anchored or bounded with no nested quantifiers. Arguments are split by a hand-written linear scanner that jumps between special characters, tracks bracket depth and skips quoted strings (`trace.py:153-185`). A hypothesis test feeds 1 MB lines of adversarial characters and asserts it stays fast.
- **strace syntax handled:** `PID syscall(...) = ret` and `[pid N]` prefixes, `<unfinished ...>` / `<... resumed>` stitched by pid, a call still unfinished at the end is still counted, `+++ exited +++`, `--- SIG… ---`, `"…"...` truncation, and `\x`, octal, `\n`, `\"` escapes (rebuilt as bytes, decoded as UTF-8). Unrecognised lines are counted as garbage, never fatal.
- **Writes** (`trace.py:226-245`): `open`/`openat`/`openat2`/`creat` with any of `O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND` outside the allowed prefixes (`/tmp`, `/sandbox/site-packages`, `/sandbox/deps`, `/home/sandbox/.cache`, `/dev/null`, `/dev/tty`, `/dev/pts`, `/dev/shm`, `/proc/self`; `trace.py:37-47`). Failed attempts count: on a read-only root a write fails with EROFS, and the attempt is the signal. Paths are normalised; relative `AT_FDCWD` paths resolve against the WORKDIR `/home/sandbox/project`; paths relative to another directory fd are kept as written and never treated as allowed.
- **Credential reads:** any open of a path listed in the manifest, whatever the flags (`trace.py:246-247`). `stat`/`access` do not count.
- **Subprocesses** (`trace.py:250-275`): `execve`/`execveat` argv, excluding the command the runner launched itself (the root pid's first exec and its PATH-search ENOENT attempts with the same argv). A later exec by the root pid (`os.execv`) is reported. PATH search in a child is reported once per (pid, argv).
- **Connects** (`trace.py:278-305`): family, address and port for AF_INET/AF_INET6, socket path for AF_UNIX, anything else as `other`. AF_UNIX connects to glibc's nscd sockets are dropped (`trace.py:52`, `294-295`).

## Decisions, with the reason and the rejected alternative

**Transport: tar on stdin, one length-prefixed envelope on stdout.** FR-4.7 forbids bind mounts, and the container's output is untrusted. A single envelope with a length and a strict schema lets the host reject anything malformed. Rejected: a bind-mounted results directory (forbidden, and exposes host paths); parsing free-form stdout (ambiguous, easy to spoof).

**Runner inside the container, not `docker exec` from the host.** The runner enforces per-step timeouts itself and still reports the partial trace, so a timeout is `incomplete:timeout` with evidence rather than a bare kill. The host keeps only a backstop. Rejected: one `docker exec` per step (more Docker calls, and a host-side kill loses the trace).

**Attribution: deps untraced, target `--no-deps`, `sys.path.append` for deps.** Dependencies are installed before strace starts. In the traced import, `/sandbox/deps` is *appended* to `sys.path` rather than added with `site.addsitedir`, so dependency `.pth` files never run there, while `site.addsitedir('/sandbox/site-packages')` makes the target's `.pth` files run as in a real environment. Appending (rather than `PYTHONPATH`, which `-I` ignores anyway) also stops a dependency from shadowing a stdlib module such as `site`. Module code of a dependency that the target imports *does* run and is attributed to the target, which chose to import it. Rejected: tracing one full `pip install` (every dependency's behaviour would land on the target).

**strace writes to a pipe (`-o /dev/stderr`), not a file.** The package runs as the same uid as the runner and strace. A trace file in `/tmp` could be rewritten or truncated by the package. A pipe the runner is already reading cannot be rewound. Rejected: `-o /tmp/trace` (what the spike did; fine for the spike, tamperable in production).

**Package output kept off the trace pipe.** Both traced programs begin by moving their own fds 1 and 2 to log files in `/tmp` before any package code runs (`runner.py:56-60`), and the step's stdout is `/dev/null`. So whatever the package prints cannot enter the trace stream or the runner's stdout.

**Non-dumpable PID 1.** Without it, a same-uid package could open `/proc/1/fd/1` and write its own envelope before the runner's. Rejected: a second uid for the runner (needs `CAP_SETUID`, which `--cap-drop ALL` removes).

**Switch off pip's `distro` probe.** pip builds a User-Agent even with `--no-index`, and its vendored `distro` module spawns `lsb_release -a` and `uname -rs` to do so. That would put two subprocesses into every install trace. `PIP_PROGRAM` replaces the module's global `LinuxDistribution` with one constructed with `include_lsb=False, include_uname=False` before running pip (`runner.py:61-72`). Rejected: filtering `lsb_release`/`uname` in the parser (a package could then hide behind those names).

**Interpreters run with `-I -B`.** `-I` (isolated) ignores `PYTHON*` environment variables and does not put the current directory on `sys.path`, so nothing in the working directory can shadow a module. `-B` is needed because `-I` also ignores `PYTHONDONTWRITEBYTECODE`; without it, Python tries to write `.pyc` files next to stdlib modules on the read-only root, and every such attempt would appear as a write outside the allowed directories.

**Drop the nscd sockets.** glibc's name-service code tries `/var/run/nscd/socket` before reading `/etc/passwd` or resolving a name, for example in `getpwuid` and `getaddrinfo`. That is libc plumbing, not the package talking to anyone, and it made `W_CONNECT_INSTALL` fire on ordinary code. Only those two exact paths are dropped.

**`noexec` tmpfs kept.** Docker's tmpfs default is `noexec`, so compiled extensions in `/sandbox/site-packages` cannot be mapped and such packages fail import → `incomplete:import_failed`, which fails closed. Allowing exec would widen what package code can do in the container; it is recorded as an open decision for the author, not taken.

**Policy guard with three origins** (`sandbox.py:170-193`). `pypi` runs only when the caller marks it a PR candidate. `fixture` runs only when every artifact file (target, sdist, dependency wheels) resolves inside `fixtures_root`, which ties "fixture" to files we control rather than a label. `local_artifact` runs only when marked a PR candidate, which only the `ci` path does for wheels shipped in the PR (log 08); `scan --artifact` and the evaluation runner never set it.

**Exit codes from the runner, not from the trace.** `-qq` hides strace's exit lines, and trace text is forgeable, so step exit codes come from the process results the runner records.

## Tamper resistance: what is and is not covered

Covered: rewriting the trace (it is a pipe), mixing package output into the trace or envelope (fds moved first), forging the envelope via `/proc/1/fd/1` (non-dumpable).

Not covered, accepted for v1 and documented in `docs/DESIGN.md`:

- The package can open strace's own pipe through `/proc/<strace pid>/fd` and inject text. It cannot remove lines strace already wrote, but an injected partial line can corrupt the next real line, which the parser then counts as garbage.
- It can kill strace; the step then exits non-zero, which is `incomplete`.
- Code running in the import interpreter can forge the per-module import results file.

All three need a tracer outside the container (eBPF, P2) or a second uid, which the dropped capabilities rule out.

## Hardening added after the PRD review (2026-11-03)

- **Path aliases:** `//home/...` and `/proc/self/root/home/...` reach the same file but did not match the credential list. `trace._canon` collapses both, with a bounded loop for nested `/proc/<pid>/root` prefixes.
- **dirfd-relative opens:** `openat(fd, ".netrc")` cannot be resolved from a trace, so a seeded credential file's *name* counts as a read.
- **Links:** `symlink`/`link`/`rename` with a credential file as the source counts as a credential read. Symlinks cannot be resolved from a trace, so creating the alias is the signal.
- **UDP:** `sendto`/`sendmsg`/`sendmmsg` with an explicit destination are recorded as connect attempts. On a network-less container both mean "tried to reach this address", and a UDP send never calls `connect()`.

## Limitations and known gaps

- Docker shares the host kernel; not escape-proof.
- Only install and import are exercised. Behaviour triggered by a call, input, timer or environment check is not seen.
- Environment-variable reads and DNS names are not observable. A hostname-based connection fails at resolution, before `connect()`, so it is not seen at all.
- `chdir` is not tracked; relative paths always resolve against the WORKDIR (`trace.py:55`).
- `B_CREDENTIAL_EXFIL` is co-occurrence, not order, because observations are not timestamped.
- Packages with compiled extensions always end `incomplete:import_failed` (noexec).
- A package that detects the sandbox can behave benignly.
- `scan --artifact` never runs the sandbox, so with the sandbox requested the result is `incomplete` (exit 3) unless a static blocking rule fires. Use `--no-sandbox` for a static-only scan of a local file.

## How it is tested

- `tests/test_trace.py` (unit, no Docker): sample observations; root PATH search excluded but a later root exec reported; `[pid N]` prefix and `execveat`; open variants and allowed prefixes; Unix and other connects; escapes and control characters; `"..."...` truncation; field caps; observation cap and dedup; unfinished-at-end counted and orphan `resumed` counted as garbage; line and input caps; and three hypothesis tests: arbitrary text never raises, structured garbage never raises, adversarial 1 MB lines are fast.
- `tests/test_sandbox.py` (unit, Docker faked): the argv contains every hardening flag and nothing forbidden (no `-v`, no `--privileged`, no socket); policy for all origins including dependency paths; policy denial and no-wheel start no container; complete run merges steps and records the digest; fresh container name per run; every incomplete state; import failure keeps observations and sanitises the exception name; trace over the package cap; timeout kills and removes; missing Docker CLI, missing image, garbled envelope, oversize output; `docker rm` runs even on unexpected exceptions; `DockerRunner` caps stdout and feeds stdin; runner programs compile; module discovery from installed files, ignoring a lying `top_level.txt`; the import program's origin check.
- `tests/test_behaviour_fixtures.py` (15 Docker tests, Track B, pass locally): five suspicious/benign pairs (`connect_import`, `credential_exfil`, `pth_import`, `obfuscated_exec`, `write_outside`), each suspicious one observed with no install-step observations and each benign one quiet; a real `pip install` trace is clean; the `noisy_dependency` attribution test; import timeout; import failure; no container left behind.

## Interview questions

**Why does behaviour show up at import rather than install?**
Installing a wheel only unzips files and writes `RECORD`; pip runs no package code. So install-time attacks in wheels are rare, and the interesting behaviour happens when the package's modules execute at import, or when a `.pth` file runs at interpreter start. The fixture suite is built around that, and a Docker test checks that a real wheel install produces no observations, so install-step rules do not fire on every package.

**How do you attribute behaviour to the target and not to its dependencies?**
Dependency wheels are installed into their own directory before tracing starts. The target is installed alone with `--no-deps`, and in the traced import the dependency directory is appended to `sys.path` so its `.pth` hooks do not run, while the target's site directory is processed normally. If the target imports a dependency, that dependency's module code runs and is attributed to the target, because the target chose to run it.

**The package runs as the same user as strace. How can you trust the trace?**
Partially, and the limits are written down. The trace goes to a pipe rather than a file, the package's own stdout and stderr are redirected before it runs, and the runner is non-dumpable so its stdout cannot be hijacked through `/proc`. A package could still inject text into strace's pipe, kill strace, or forge its import results; killing strace makes the run incomplete, and the rest needs a tracer outside the container, which is deferred.

**Why did pip itself show up as spawning subprocesses, and how did you fix it?**
pip's vendored `distro` module runs `lsb_release -a` and `uname -rs` to build a User-Agent string, even with `--no-index`. Every install trace would have shown two subprocesses. The runner wraps pip in a small program that replaces `distro`'s probe object with one that skips both commands, rather than filtering those names in the parser, which a package could exploit.

**Why `-I -B` on every interpreter?**
`-I` isolates the interpreter from `PYTHON*` environment variables and the current directory, so nothing can be injected into the import path. But it also ignores `PYTHONDONTWRITEBYTECODE`, so Python would try to write `.pyc` files on the read-only root and each attempt would look like a suspicious write. `-B` turns that off explicitly.

**How are timeouts enforced, and what does the verdict say?**
The runner gives each traced step its own process group and, on timeout, sends SIGTERM to the group so strace can flush, then SIGKILL two seconds later, and still reports the partial trace. The host keeps a backstop timeout that kills the container if the runner itself hangs. Either way the trace is `incomplete:timeout`, which fails the check, and any observations made before the timeout are kept.

**How do you stop a hostile trace from hanging or crashing the parser?**
Input and line sizes are capped before parsing, every regex is anchored or bounded with no nested quantifiers, and arguments are split by a linear scanner instead of a regex. Every field and list is capped, control characters are stripped, nothing is evaluated, and unknown lines are counted rather than raising. Hypothesis tests feed random and adversarial text, including 1 MB lines, and assert it never raises and stays fast.

**Why not allow exec on the site-packages tmpfs so compiled packages work?**
Docker's tmpfs is `noexec` by default, and allowing exec would let package code map and run arbitrary native code from a writable location. Keeping it means packages with compiled extensions fail import and the check fails closed, which is noisy but safe. It is recorded as an open decision for the author rather than changed silently.
