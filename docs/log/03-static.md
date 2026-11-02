# Build log 03: static analysis (Workstream B)

`src/pipguard/static.py` and the frozen snapshot `data/top-pypi-5000.json`. Commit `304e975`; integration tuning in `61f88bb` (root `setup.py` only, routable IPs only) and `d58ded3` (popular packages exempt from typosquat).

## What was built

| FR | Requirement | Where |
| --- | --- | --- |
| FR-3.1 | Parse every `.py` with `ast`; syntax errors are a feature, not a failure | `static.py:463-475`, `static.py:621-631` |
| FR-3.2 | Install-time indicators as presence flags: `cmdclass`, overridden `install`/`develop`/`egg_info`, `.pth` import lines, PEP 517 backend (sdist only) | `static.py:373-386`, `435-438`, `564-580` |
| FR-3.3 | Suspicious-indicator counts: `exec`, `eval`, `compile`, non-literal `__import__`/`importlib.import_module`, `b64decode`, `zlib.decompress`, `marshal.loads`, `pickle.loads`, `ctypes` | `static.py:65-81`, `416-439` |
| FR-3.4 | High-entropy strings: ≥ 4.5 bits/char over ≥ 40 chars | `static.py:53-54`, `443-454` |
| FR-3.5 | URLs, IPv4/IPv6 literals, domain-like strings; raw IPs and URL shorteners flagged | `static.py:138-168`, `487-558` |
| FR-3.6 | Typosquat: PEP 503 names, Damerau-Levenshtein via `rapidfuzz` against a frozen, dated top-5,000 snapshot | `static.py:172-251` |
| FR-3.7 | Network, subprocess, filesystem and environment imports at module top level or in install-hook code | `static.py:97-130`, `350-357` |

Everything here parses; nothing imports, compiles-and-runs or executes package code (`static.py:1-9`).

## How it works

`analyze(pkg)` runs `analyze_dir` on each extracted artifact and computes one typosquat result for the package (`static.py:669-684`). `analyze_dir` walks the tree (`static.py:586-666`):

- Every file counts toward `file_count` and `total_size`; `.so`/`.pyd`/`.dylib` set `has_compiled_extensions`.
- Symlinks are never followed (extraction already refuses them; this is belt and braces).
- `.py` files are read with a 5 MB cap and parsed. A file that is too large, undecodable, a syntax error, or so deeply nested that the parser or visitor hits `RecursionError`, increments `syntax_error_count` and analysis continues (`static.py:463-484`). Only a missing or unreadable directory raises `PipGuardError`, which becomes an `error` verdict.
- `.pth`, `.toml` and `.cfg` text is scanned for URLs/IPs/domains; `.pth` lines starting with `import ` or `import\t` (exactly the lines `site.py` executes) set `pth_import_lines` and are themselves parsed as hook code (`static.py:564-569`).
- In an sdist, the project's own `pyproject.toml` (root or the sdist's top folder) sets `pep517_build_backend` if `[build-system] build-backend` is present; malformed TOML counts as a syntax error (`static.py:572-580`, `638-644`).

### The AST visitor

One `_Visitor` pass per module (`static.py:297-454`):

- **Alias resolution.** Before visiting, it collects every `import x as y` and `from m import n as k` in the module (`static.py:305-322`), so `import base64 as b; b.b64decode(...)` and `from base64 import b64decode as d; d(...)` both resolve to `base64.b64decode`. `builtins.` and `__builtins__.` prefixes are stripped. Plain assignment aliases (`d = base64.b64decode`) are not followed.
- **Literal indirection.** `getattr(builtins, "exec")` and `getattr(base64, "b64decode")` count as the named call (`static.py:418-426`).
- **Dynamic imports.** `__import__(x)` or `importlib.import_module(x)` counts as `dynamic_import` only when the argument is not a string literal; a literal is treated as an ordinary import of that module (`static.py:429-434`), so `__import__("ctypes")` counts as a ctypes import.
- **Install hooks.** In a root `setup.py`, a `setup(...)` call with a non-empty `cmdclass=` sets `setup_py_cmdclass` (`static.py:435-438`). A class whose base resolves to `setuptools.command.{install,develop,egg_info}` or the `distutils` equivalent sets `overridden_install_command`, and its body is visited as hook code (`static.py:373-386`).
- **Risky imports (FR-3.7).** A name is "counted" when it is reached at module top level (including module-level `if`/`try` and class bodies) or anywhere in hook code (`static.py:350-352`). Function bodies at depth > 0 outside hooks do not count, so a library that imports `socket` inside a function does not fire. Categories and their names are in `RISKY_NAMES` (`static.py:97-130`); `ssl`, `pathlib`, `os.path` and `tempfile` are deliberately left out because almost every package uses them. `os.system`, `os.exec*` and similar are matched as uses, since `import os` alone says nothing.
- **Literals.** Every string or bytes constant updates the entropy maximum and the high-entropy count (≥ 40 chars and ≥ 4.5 bits/char), and is kept for the network-literal scan (`static.py:443-454`).

### Network literals (FR-3.5)

`_scan_network_literals` runs bounded regexes over string literals and the raw text of non-Python files (`static.py:487-520`). The IPv4/IPv6/domain regexes use lookbehinds so matches start at token boundaries and the scan stays linear on hostile input (`static.py:164-168`).

- **URLs:** scheme `http(s)`, `ftp`, `ws(s)`. The host of every URL counts as a domain; a host in `URL_SHORTENERS` (bit.ly, tinyurl.com and ten others) records the URL as a shortener.
- **Scheme-less domains** count only with a TLD from a short list (`DOMAIN_TLDS`, `static.py:158-161`) that omits file-extension TLDs such as `.py`, `.sh`, `.cc`. Otherwise every `module.attr` string would be a domain.
- **Raw IPs** (`_is_raw_ip`, `static.py:543-558`): a valid IP literal that is globally routable, or in one of the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) so fixtures and the demo can use safe addresses. IPv6 must also be in 2000::/3. LAN, loopback, link-local, CGNAT and other reserved values are not raw-IP indicators. A version string that happens to be a public IPv4 (`1.2.3.4`) still counts; it is indistinguishable.
- All lists are deduplicated and capped at 50 entries of 200 characters each (`static.py:50-51`), so a hostile file cannot bloat the report.

### Typosquat (FR-3.6)

`typosquat(name, top)` (`static.py:211-251`):

1. PEP 503-normalise the name.
2. **If the name itself is in the snapshot, return "no result"** (`static.py:218-223`). See "Integration tuning" below.
3. Otherwise ask `rapidfuzz.process.extract` for every snapshot name within Damerau-Levenshtein distance 2 (transposition counts as one edit, so `requets` → `requests` is 1).
4. A candidate **fires** at distance ≤ 1 to a top-500 name or ≤ 2 to a top-100 name (`static.py:173-177`, `236-238`). A firing candidate is preferred over a closer one that does not fire; then distance, then rank.

The result records distance, target, the target's 1-based rank, the snapshot date, and whether it fired. The snapshot is `data/top-pypi-5000.json` from hugovk/top-pypi-packages dated 2026-11-01 (`requests` is rank 8, `six` rank 16). It is loaded once per process (`functools.cache`, `static.py:206-208`); a bad file raises `PipGuardError`.

## Integration tuning, and why

These came out of running the real pipeline against real packages, not from the PRD text.

**1. Install-hook indicators only from the root `setup.py`** (`61f88bb`). Originally any file named `setup.py` was treated as hook code, and any class overriding `install` set `overridden_install_command`. Large sdists vendor sub-projects and test data with their own `setup.py` files, which never run when the outer project is installed. Now a `setup.py` counts only at the archive root or in the sdist's single top folder (`len(relative parts) <= 2`, `static.py:625`), and `overridden_install_command` is reset to false when the artifact has no root `setup.py` (`static.py:655-659`), because an install-command class in, say, a meson project's test folder is never executed.

**2. Raw IPs only when routable** (`61f88bb`). The first version kept private ranges (DESIGN.md still says so). The `requests` sdist alone has 17 literals such as `10.0.0.1` and `192.168.0.0/16` in tests and proxy code, so `W_IP_LITERAL` fired on most networking libraries. An exfiltration endpoint has to be reachable from a victim's machine, so routable addresses are the signal; documentation ranges stay in so fixtures work.

**3. Popular packages are exempt from typosquat** (`d58ded3`). The benign Track C bump `six==1.17.0` warned: `six` is 2 edits from `pip`, and `pip` is top-100, so the indicator fired. The PRD only excludes "the package itself". A package that is itself in the popularity snapshot is not a typosquat of another popular package; attackers' typosquats are by construction not popular. The exemption returns no distance at all, so neither a rule nor a model feature can fire.

## Key design decisions

| Decision | Reason | Rejected alternative |
| --- | --- | --- |
| `ast` instead of regex for code | Resolves aliases and `getattr` indirection; a regex misses `b = base64; b.b64decode` | Regex/grep scanners (PRD: "regex-only scanners miss obfuscation") |
| Per-file failures are features | Malware often ships deliberately unparsable files; failing the scan would be an easy DoS of the gate | Raising on the first `SyntaxError` |
| Indicators are "suspicious", reported as present, never executed | Legitimate code uses all of them; the verdict must not claim more than was observed | Calling them "dangerous calls" (renamed in the PRD) |
| Top-level or hook context only for FR-3.7 | What runs without the user calling anything is what matters for install/import-time attacks | Counting every import anywhere (fires on almost everything) |
| Alias collection is module-wide and scope-insensitive | Simple and an attacker gains nothing by shadowing, since every alias is still resolved | Full scope analysis (much more code, no extra signal for indicators) |
| Frozen, dated snapshot committed in the repo | Results are reproducible and the date is recorded in every `TyposquatResult` | Fetching the live top list per scan (non-deterministic, needs network) |
| Firing candidate beats a closer non-firing one | `reqeusts` should report `requests` (fires) rather than some closer obscure name | Pure nearest neighbour |
| Popular-package exemption | Removes false positives like `six`/`pip` without losing recall on unpopular typosquats | Excluding only the package's own name |

## Limitations and known gaps

- Assignment aliases (`d = base64.b64decode; d(x)`) and computed attribute names are not followed.
- Strings built at runtime (`"ex" + "ec"`, `bytes([...])`) are not reconstructed; entropy and URL scans see only literals.
- Version strings that are valid public IPv4 addresses count as raw IPs.
- The popular-package exemption means a **hijacked release of a package that is itself in the top 5,000** gets no typosquat signal (correctly: it is not a typosquat). Other indicators and behaviour still apply. It also means typosquat features are constant for the three snapshot benign bands in Track A, so typosquat's false-positive rate there is zero by construction; the random band beyond the top 5,000 is the honest test (log 07).
- `DESIGN.md` has not yet been updated for the three integration changes above (raw-IP rule, root `setup.py`, exemption).
- Typosquat thresholds are the PRD defaults and still have to be re-tuned on validation data (FR-3.6).
- Static analysis cannot see behaviour that is fetched at runtime (a second-stage payload) or hidden in compiled extensions.

## How it is tested

`tests/test_static.py`, no network, fixtures under `tests/fixtures/static/`:

- One suspicious/benign pair per indicator family: `cmdclass`, `pth`, `pep517` (sdist only), `exec_b64`, `dynamic_import`, `marshal_pickle`, `ctypes`, `entropy`, `network_literals`, `risky_imports`, plus a `requets` typosquat fixture.
- Robustness: syntax errors counted not fatal, oversize files, deep nesting does not crash, malformed `pyproject.toml` counted, missing directory fails closed, unextracted artifact refused, `analyze_dir` never raises on hostile trees.
- Resolution: alias resolution, `getattr` indirection, ctypes variants and literal `__import__`, risky contexts (top level vs function vs hook), "everything in root `setup.py` is hook code", nested `setup.py` is not a hook.
- Literals: bytes and IPv6, list caps, Shannon entropy values, LAN and link-local IPs are not raw-IP indicators.
- Typosquat: distances, self-exclusion and rank, firing candidate preferred, the committed snapshot loads, bad snapshot raises, and a popular package is not a typosquat of another.

## Interview questions

**Why parse with `ast` instead of searching the text?**
`ast` gives the structure of the code, so the scanner can resolve `import base64 as b` and then recognise `b.b64decode(...)` as a base64 decode, or recognise `getattr(builtins, "exec")` as `exec`. A text search either misses these or fires on comments and strings. Parsing never executes the code, so it is safe on malware.

**What happens if a malicious package includes a file that cannot be parsed?**
It is counted in `syntax_error_count`, which is a feature, and the rest of the package is still analysed. The same applies to oversize files and pathologically nested code that would exhaust the recursion limit. Only an unreadable directory fails the scan, because then nothing was analysed.

**Why only count risky imports at module top level or in install hooks?**
Install- and import-time attacks run without anyone calling a function, so code at module level, in a class body, or in a `setup.py` hook is what executes. Counting imports inside functions would fire on most libraries, since many legitimately use `subprocess` or `socket` inside some function. Very common modules like `pathlib` and `ssl` are excluded because they carry no signal.

**Why did you stop treating private IP addresses as indicators?**
Running the scanner on real packages showed that test suites and proxy code are full of LAN and loopback literals; `requests` alone had 17. A credential stealer needs an address it can reach from a victim's machine, so globally routable addresses are the signal. Documentation ranges are kept so that safe fixtures and the demo still trigger the indicator.

**How does the typosquat check work, and why was the exemption needed?**
Names are normalised and compared with Damerau-Levenshtein distance (a transposition is one edit) against a frozen, dated list of the top 5,000 PyPI names. It fires at distance ≤ 1 to a top-500 name or ≤ 2 to a top-100 name. The exemption was added because `six` is 2 edits from `pip` and both are top-100 packages, so a benign bump warned; a package that is itself popular is not impersonating another popular package.

**What does the popular-package exemption cost you?**
A hijacked release of a popular package gets no typosquat signal, which is correct because it is not a typosquat, and the other indicators and the sandbox still apply. In evaluation, it makes the typosquat false-positive rate on the top-5,000 benign bands zero by construction, so the random band of less popular packages is where that feature is honestly measured. That is stated as a limitation rather than hidden.

**Why is the snapshot committed instead of fetched each time?**
A frozen file makes every scan reproducible and lets the verdict say exactly which list it was compared against; the snapshot date is recorded in each result and in the model artifact. Fetching it live would add a network dependency and make results change from day to day.
