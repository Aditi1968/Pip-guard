# Build log 09: final decisions on the open items

The review left four design questions that only the author could settle. This log records what was decided on 2026-11-04, the alternative that was rejected and why, and the interview question each one answers. Code: `src/pipguard/sandbox.py` (`compiled_extensions`, `_compiled_state`, `policy_allows`), `src/pipguard/models.py` (`FetchedPackage.origin`), `src/pipguard/rules.py` (`evaluate_all`), `src/pipguard/cli.py` (`explain`), `sandbox/sandbox.Dockerfile`.

## 1. Compiled extensions: keep `noexec`, report `incomplete`

**Decision.** The sandbox's writable tmpfs mounts stay `noexec` (Docker's default). A wheel that contains native code (`.so`, `.so.N`, `.pyd`, `.dylib`) can never have that code observed, because the dynamic loader cannot map it executable. So such a trace is never `complete`:

- `sandbox.compiled_extensions(wheel)` lists native files from the wheel's zip index. Only the names are read; nothing is extracted or run.
- `_compiled_state` turns a `complete` or `import_failed` result into `incomplete:import_failed`, with a reason such as `compiled extension _speedups.cpython-312-x86_64-linux-gnu.so cannot load in the noexec sandbox; native code was not observed (known limitation)`.
- Scoring maps that to the `incomplete` verdict, so the check exits 3 and fails.
- Other states (timeout, truncation, sandbox error) are left alone, because they are already failures with a more specific reason.

This also covers a case the import result alone would miss: a package that does `try: import _speedups except ImportError: pass` imports "successfully" without its native code ever running. The decision is based on what the wheel contains, not on whether the import succeeded, so that case is caught too.

**Rejected alternative:** mounting `/sandbox/site-packages` with `exec`. It would make numpy-style packages scan to completion. But it lets package-written files run as native code in the container, which widens the attack surface on the one component that runs untrusted code. CLAUDE.md says never to weaken isolation to make tracing work. An honest `incomplete` that a human reviews is cheaper than a sandbox you have to defend.

**Cost, stated openly:** any PR that bumps a package with compiled extensions fails the gate until a human reviews it or allowlists the package. This is listed in the README's known limitations.

**Interview question:** *"Your sandbox can't run C extensions. Isn't that most of the scientific Python ecosystem? Why not just allow exec?"* Answer: isolation is the product, so trading it for coverage would be the wrong way round. The gate fails closed and says exactly why, the allowlist exists for reviewed packages, and gVisor (v2) is the path to running native code safely.

## 2. Pin `strace`; publish to GHCR later

**Decision.** `sandbox/sandbox.Dockerfile` installs `strace=6.1-0.1`, the Debian bookworm version (checked on packages.debian.org on 2026-11-04). The base image is already pinned by digest, so the tracer the verdicts depend on is now pinned too. If bookworm ever replaces 6.1-0.1, the build fails loudly instead of silently changing what we observe; when that happens, bump the pin on purpose. The Dockerfile is part of the cache fingerprint, so bumping the pin also invalidates old cached verdicts.

Publishing the image to GHCR waits until the repo is public; there is a TODO in PLAN.md. Until then the Action builds the image, which is slower but has no registry trust to manage.

**Rejected alternatives:**
- *Leave strace unpinned:* every rebuild could pick up a different tracer, and a change in strace's output format could break the parser between two identical runs.
- *Build strace from source or vendor a binary:* more supply chain to maintain than a pinned distro package.
- *Publish to GHCR now:* it needs the public repo and an Actions write permission, and pre-release it buys little.

**Interview question:** *"How do you know two scans of the same package used the same tracer?"* Answer: the base image is pinned by digest and strace by exact version, the image digest is part of the cache key, and the Dockerfile is hashed into the scanner fingerprint.

## 3. `pipguard explain` shows every rule

**Decision.** `explain` now prints `rules`, one entry per rule in `rules.yaml`, blocking first:

- `fired`: true or false.
- `description`.
- `features`: the values of exactly the features the rule's condition read.
- `reason`: the rendered reason, only when the rule fired.

`rules.evaluate_all` uses the same `_holds` as the verdict path (`evaluate`), so explain cannot disagree with the verdict. A test asserts that the fired rules equal `evaluate`'s hits.

**Rejected alternative:** keep printing only the hits (the old `rule_hits`). That answers "why was it blocked?" but not "why was it *not* blocked?", and FR-7.3 asks for rule evaluations, not hits. A separate code path that re-explains the rules was also rejected: two evaluators would drift apart.

**Interview question:** *"A reviewer thinks a package should have been blocked. How do they find out why it wasn't?"* Answer: `pipguard explain` shows each rule's condition inputs next to `fired: false`, for example `connect_install_external_count: 0`, so they can see whether the evidence was missing or the threshold too high.

## 4. `FetchedPackage.origin` is required, and `"unknown"` is refused

**Decision.** `origin` has no default. Its values are `pypi`, `local_artifact`, `fixture` and the new `unknown`. `policy_allows` handles each known origin explicitly and refuses everything else, `unknown` included, even when the package is marked as a PR candidate. Tests check that building a `FetchedPackage` without `origin` fails validation, and that `origin="unknown"` gets `skipped:policy` without starting a container.

**Rejected alternative:** keep the default `"pypi"`. It was the most permissive value the policy knew, because a PR candidate from PyPI runs in the sandbox. A new code path that forgot to set `origin`, for example a future corpus loader, would silently get "run me". With the field required, forgetting it is a validation error. With `unknown`, a caller that genuinely cannot say has a value that fails closed.

**Interview question:** *"How do you make sure archived malware never gets executed by accident?"* Answer: by more than convention. The corpus is static-only by policy, `origin` must be stated explicitly, local artifacts run only when a PR ships them, `unknown` never runs, and the default-deny branch at the end of `policy_allows` catches anything not handled above it.
