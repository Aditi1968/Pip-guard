"""Static analysis of extracted artifacts (PRD FR-3.1 to FR-3.7).

Everything here *parses*; nothing imports, compiles-and-runs or executes package code.
File contents are untrusted: reads are capped, every parser failure is caught per file and
recorded as a feature (FR-3.1), and only a failure to analyse the artifact as a whole (a
missing or unreadable directory) raises ``PipGuardError`` so the verdict fails closed.

Indicators are *suspicious*, not proof: legitimate libraries use all of them.
"""

from __future__ import annotations

import ast
import ipaddress
import json
import logging
import math
import os
import re
import tomllib
import warnings
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from functools import cache
from pathlib import Path
from urllib.parse import urlsplit

from rapidfuzz import process
from rapidfuzz.distance import DamerauLevenshtein

from pipguard.errors import PipGuardError
from pipguard.models import (
    ArtifactKind,
    ArtifactStaticFeatures,
    FetchedPackage,
    ImportCategory,
    InstallIndicators,
    StaticFeatures,
    SuspiciousCounts,
    TyposquatResult,
    normalize_name,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------- limits

MAX_FILE_BYTES = 5 * 1024 * 1024  # larger files are not read; an oversize .py counts as unparsed
MAX_LIST = 50  # FR-3.5 / FR-3.7 lists are deduplicated and capped ...
MAX_ITEM_CHARS = 200  # ... and each entry truncated, so a hostile file cannot bloat the report

ENTROPY_MIN_LEN = 40  # FR-3.4
ENTROPY_THRESHOLD = 4.5  # bits per character

COMPILED_SUFFIXES = frozenset({".so", ".pyd", ".dylib"})
# Non-Python text files whose raw text is scanned for URLs/IPs/domains (FR-3.5).
TEXT_SCAN_SUFFIXES = frozenset({".cfg", ".pth", ".toml"})

# ---------------------------------------------------------------- FR-3.3 suspicious calls

# Qualified call target -> SuspiciousCounts field. Targets are resolved through import aliases,
# so ``import base64 as b; b.b64decode`` and ``from base64 import b64decode as d; d`` both hit.
# All base64 decoders (b16/b32/b64/b85/a85/urlsafe) share the ``b64decode`` counter.
SUSPICIOUS_CALLS: dict[str, str] = {
    "exec": "exec",
    "eval": "eval",
    "compile": "compile",
    "base64.b64decode": "b64decode",
    "base64.urlsafe_b64decode": "b64decode",
    "base64.standard_b64decode": "b64decode",
    "base64.b32decode": "b64decode",
    "base64.b16decode": "b64decode",
    "base64.b85decode": "b64decode",
    "base64.a85decode": "b64decode",
    "base64.decodebytes": "b64decode",
    "zlib.decompress": "zlib_decompress",
    "marshal.loads": "marshal_loads",
    "pickle.loads": "pickle_loads",
}
DYNAMIC_IMPORTERS = frozenset({"__import__", "importlib.import_module"})

# ---------------------------------------------------------------- FR-3.7 risky imports

# What a package can do *at import or install time* without a function call from the user.
# Only names reached at module top level (incl. module-level if/try) or in install-hook code
# count, so a library that imports socket inside a function does not fire.
#   network:     modules whose only job is talking to other hosts. ``ssl`` is left out: it is
#                imported for certificate handling by many offline libraries.
#   subprocess:  process creation; os.system/popen/exec*/spawn* are attributes of the very
#                common ``os`` module, so they are matched as uses, not as ``import os``.
#   filesystem:  destructive or broad file operations. pathlib/os.path/tempfile are left out:
#                nearly every package uses them, so they would carry no signal.
#   environment: reading environment variables / credentials of the user.
# A trailing ``*`` matches any name with that prefix (``os.exec*`` -> os.execv, os.execvp...);
# otherwise an entry matches itself and its dotted children (``urllib`` -> urllib.request).
RISKY_NAMES: dict[ImportCategory, tuple[str, ...]] = {
    ImportCategory.NETWORK: (
        "socket",
        "urllib",
        "urllib3",
        "http.client",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "smtplib",
        "telnetlib",
        "paramiko",
    ),
    ImportCategory.SUBPROCESS: (
        "subprocess",
        "pty",
        "commands",
        "os.system",
        "os.popen",
        "os.exec*",
        "os.spawn*",
    ),
    ImportCategory.FILESYSTEM: (
        "shutil",
        "glob",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.removedirs",
        "open",
    ),
    ImportCategory.ENVIRONMENT: ("os.environ", "os.getenv", "os.putenv", "getpass"),
}

# FR-3.2: command classes whose override runs code at install time.
INSTALL_COMMANDS = frozenset({"install", "develop", "egg_info"})
COMMAND_PACKAGES = ("setuptools.command.", "distutils.command.")

# ---------------------------------------------------------------- FR-3.5 network literals

URL_SHORTENERS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
        "buff.ly",
        "rebrand.ly",
        "tiny.cc",
    }
)
# Bare (scheme-less) domain-like strings only count with one of these TLDs; otherwise every
# ``module.attr`` or ``file.py`` string would be a "domain". Hosts inside URLs always count.
# File-extension TLDs (py, sh, md, cc, so...) are deliberately absent.
# fmt: off
DOMAIN_TLDS = frozenset({
    "com", "net", "org", "io", "info", "biz", "xyz", "top", "ru", "cn", "tk", "ml", "ga",
    "cf", "gq", "pw", "su", "ws", "me", "co", "us", "uk", "de", "icu", "online",
})
# fmt: on

_URL_RE = re.compile(r"(?:https?|ftp|wss?)://[^\s'\"<>`]+", re.IGNORECASE)
# Lookbehinds anchor matches at token starts so the scan stays linear on hostile input.
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_DOMAIN_RE = re.compile(r"(?<![\w.-])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")

# ---------------------------------------------------------------- FR-3.6 typosquat

TOP_PACKAGES_PATH = Path(__file__).resolve().parents[2] / "data" / "top-pypi-5000.json"
TYPOSQUAT_TOP_STRICT = 100  # distance <= 2 to a top-100 name fires
TYPOSQUAT_STRICT_DISTANCE = 2
TYPOSQUAT_TOP_LOOSE = 500  # distance <= 1 to a top-500 name fires
TYPOSQUAT_LOOSE_DISTANCE = 1
TYPOSQUAT_RADIUS = 2  # nearest name reported only within this distance


@dataclass(frozen=True)
class TopPackages:
    """A frozen, dated, ranked list of popular names (PEP 503-normalised)."""

    names: tuple[str, ...]
    snapshot_date: date
    rank: dict[str, int] = field(init=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "names", tuple(normalize_name(n) for n in self.names))
        rank: dict[str, int] = {}
        for i, n in enumerate(self.names, start=1):
            rank.setdefault(n, i)
        object.__setattr__(self, "rank", rank)


def load_top_packages(path: Path = TOP_PACKAGES_PATH) -> TopPackages:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return TopPackages(
            names=tuple(raw["names"]), snapshot_date=date.fromisoformat(raw["snapshot_date"])
        )
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise PipGuardError(f"cannot load typosquat snapshot {path}: {e}") from e


@cache
def default_top_packages() -> TopPackages:
    return load_top_packages()


def typosquat(name: str, top: TopPackages) -> TyposquatResult:
    """Nearest popular name within ``TYPOSQUAT_RADIUS`` (Damerau-Levenshtein), FR-3.6.

    The package's own name is excluded. Among candidates, one that fires wins over a merely
    closer one; ties break on distance, then rank.
    """
    me = normalize_name(name)
    if me in top.rank:
        # A package that is itself in the popularity snapshot is not a typosquat of another
        # popular package (six is 2 edits from pip; both are top-100 projects). Attackers'
        # packages are by construction not popular, so this costs no recall on the target
        # population. No distance is reported, so no rule or model feature can fire on it.
        return TyposquatResult(snapshot_date=top.snapshot_date)
    hits = process.extract(
        me,
        top.names,
        scorer=DamerauLevenshtein.distance,
        score_cutoff=TYPOSQUAT_RADIUS,
        limit=None,
    )
    best: tuple[bool, int, int, str] | None = None
    for cand, dist, idx in hits:
        if cand == me:
            continue
        rank = idx + 1
        fires = (dist <= TYPOSQUAT_LOOSE_DISTANCE and rank <= TYPOSQUAT_TOP_LOOSE) or (
            dist <= TYPOSQUAT_STRICT_DISTANCE and rank <= TYPOSQUAT_TOP_STRICT
        )
        key = (not fires, int(dist), rank, cand)
        if best is None or key < best:
            best = key
    if best is None:
        return TyposquatResult(snapshot_date=top.snapshot_date)
    not_fires, dist, rank, cand = best
    return TyposquatResult(
        distance=dist,
        target=cand,
        target_rank=rank,
        snapshot_date=top.snapshot_date,
        fired=not not_fires,
    )


# ---------------------------------------------------------------- helpers


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _risky_match(qualified: str) -> tuple[ImportCategory, str] | None:
    """Category and the matched name (trimmed to the entry's depth) for a dotted name."""
    for cat, entries in RISKY_NAMES.items():
        for entry in entries:
            if entry.endswith("*"):
                hit = qualified.startswith(entry[:-1])
            else:
                hit = qualified == entry or qualified.startswith(entry + ".")
            if hit:
                return cat, ".".join(qualified.split(".")[: entry.count(".") + 1])
    return None


def _capped(items: dict[str, None]) -> list[str]:
    return [s[:MAX_ITEM_CHARS] for s in list(items)[:MAX_LIST]]


@dataclass
class _Acc:
    """Mutable per-artifact accumulator, frozen into ``ArtifactStaticFeatures`` at the end."""

    syntax_errors: int = 0
    install: dict[str, bool] = field(
        default_factory=lambda: dict.fromkeys(InstallIndicators.model_fields, False)
    )
    counts: Counter[str] = field(default_factory=Counter)
    max_entropy: float = 0.0
    high_entropy: int = 0
    strings: list[str] = field(default_factory=list)  # literals + raw text to scan (FR-3.5)
    categories: set[ImportCategory] = field(default_factory=set)
    modules: dict[str, None] = field(default_factory=dict)  # ordered set


class _Visitor(ast.NodeVisitor):
    """One pass over a module's AST.

    Aliases are collected module-wide first (scope-insensitive: good enough for indicators,
    and an attacker gains nothing by shadowing since every alias is still resolved). Plain
    assignments like ``d = base64.b64decode`` are not followed.
    """

    def __init__(self, acc: _Acc, tree: ast.AST, *, hook: bool, setup_py: bool) -> None:
        self.acc = acc
        self.hook = hook  # inside install-hook code: setup.py, .pth line, install override
        self.setup_py = setup_py
        self.fn_depth = 0
        self.aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.aliases[a.asname] = a.name
                    else:
                        top = a.name.split(".")[0]
                        self.aliases[top] = top
            elif isinstance(node, ast.ImportFrom):
                mod = "." * node.level + (node.module or "")
                for a in node.names:
                    self.aliases[a.asname or a.name] = f"{mod}.{a.name}"

    # -- name resolution

    def qualify(self, node: ast.expr) -> str | None:
        """Dotted name of a Name/Attribute chain, resolved through import aliases."""
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        parts.append(self.aliases.get(node.id, node.id))
        q = ".".join(reversed(parts))
        for prefix in ("builtins.", "__builtins__."):
            if q.startswith(prefix):
                return q[len(prefix) :]
        return q

    def _imported(self, node: ast.expr) -> str | None:
        """Like ``qualify`` but only for names bound by an import (or the builtin ``open``)."""
        base = node
        while isinstance(base, ast.Attribute):
            base = base.value
        if isinstance(base, ast.Name) and (base.id in self.aliases or base.id == "open"):
            return self.qualify(node)
        return None

    @property
    def counted(self) -> bool:
        return self.hook or self.fn_depth == 0

    def _risky(self, qualified: str) -> None:
        if self.counted and (m := _risky_match(qualified)):
            self.acc.categories.add(m[0])
            self.acc.modules.setdefault(m[1])

    def _imported_module(self, module: str) -> None:
        if module == "ctypes" or module.startswith("ctypes."):
            self.acc.counts["ctypes"] += 1
        self._risky(module)

    # -- scopes

    def _function(self, node: ast.AST) -> None:
        self.fn_depth += 1
        self.generic_visit(node)
        self.fn_depth -= 1

    visit_FunctionDef = visit_AsyncFunctionDef = visit_Lambda = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        overrides = False
        for base in node.bases:
            q = self.qualify(base) or ""
            if q.startswith(COMMAND_PACKAGES) and q.rsplit(".", 1)[-1] in INSTALL_COMMANDS:
                overrides = True
        if not overrides:
            self.generic_visit(node)
            return
        self.acc.install["overridden_install_command"] = True
        saved = self.hook
        self.hook = True
        self.generic_visit(node)
        self.hook = saved

    # -- imports and name uses

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self._imported_module(a.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            return  # relative import: the package's own code
        mod = node.module or ""
        if mod == "ctypes" or mod.startswith("ctypes."):
            self.acc.counts["ctypes"] += 1
        self._risky(mod)
        for a in node.names:
            self._risky(f"{mod}.{a.name}")

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and (q := self._imported(node)):
            self._risky(q)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if q := self._imported(node):
            self._risky(q)  # a pure dotted chain: nothing below it to visit
        else:
            self.generic_visit(node)

    # -- calls

    def visit_Call(self, node: ast.Call) -> None:
        q = self.qualify(node.func)
        if q == "getattr" and len(node.args) >= 2:
            # getattr(builtins, "exec") / getattr(base64, "b64decode"): literal indirection.
            obj, attr = node.args[0], node.args[1]
            if isinstance(attr, ast.Constant) and isinstance(attr.value, str):
                owner = self.qualify(obj) if isinstance(obj, ast.Name | ast.Attribute) else None
                target = attr.value if owner in (None, "builtins", "__builtins__") else None
                target = target or f"{owner}.{attr.value}"
                if target in SUSPICIOUS_CALLS:
                    self.acc.counts[SUSPICIOUS_CALLS[target]] += 1
        elif q in SUSPICIOUS_CALLS:
            self.acc.counts[SUSPICIOUS_CALLS[q]] += 1
        elif q in DYNAMIC_IMPORTERS:
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                self._imported_module(first.value)  # literal: an ordinary import
            else:
                self.acc.counts["dynamic_import"] += 1
        if self.setup_py and q is not None and (q == "setup" or q.endswith(".setup")):
            for kw in node.keywords:
                if kw.arg == "cmdclass" and not _empty_literal(kw.value):
                    self.acc.install["setup_py_cmdclass"] = True
        self.generic_visit(node)

    # -- literals (FR-3.4, FR-3.5)

    def visit_Constant(self, node: ast.Constant) -> None:
        v = node.value
        if isinstance(v, bytes):
            v = v.decode("latin-1")
        if not isinstance(v, str):
            return
        if len(v) >= ENTROPY_MIN_LEN:
            e = shannon_entropy(v)
            self.acc.max_entropy = max(self.acc.max_entropy, e)
            if e >= ENTROPY_THRESHOLD:
                self.acc.high_entropy += 1
        self.acc.strings.append(v)


def _empty_literal(node: ast.expr) -> bool:
    return (isinstance(node, ast.Dict) and not node.keys) or (
        isinstance(node, ast.Constant) and node.value is None
    )


def _analyse_source(acc: _Acc, source: bytes | str, *, hook: bool, setup_py: bool) -> bool:
    """Parse and visit one source; False (and nothing raised) if it cannot be parsed."""
    try:
        with warnings.catch_warnings():  # e.g. invalid escape sequences in package code
            warnings.simplefilter("ignore")
            tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
        return False
    try:
        _Visitor(acc, tree, hook=hook, setup_py=setup_py).visit(tree)
    except RecursionError:
        return False  # pathologically deep AST: keep what was seen, count it as unparsed
    return True


def _read_capped(path: Path) -> bytes | None:
    with path.open("rb") as f:
        data = f.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        log.warning("oversize file not analysed: %s", path)
        return None
    return data


def _scan_network_literals(strings: list[str]) -> dict[str, list[str]]:
    urls: dict[str, None] = {}
    ips: dict[str, None] = {}
    domains: dict[str, None] = {}
    shorteners: dict[str, None] = {}
    url_hosts: set[str] = set()  # shortener hosts already reported with their full URL
    for s in strings:
        for url in _URL_RE.findall(s):
            url = url.rstrip(".,;:)]}")
            urls.setdefault(url)
            try:
                host = (urlsplit(url).hostname or "").lower()
            except ValueError:
                continue
            if host and not _is_ip(host):
                domains.setdefault(host)
                if host.removeprefix("www.") in URL_SHORTENERS:
                    shorteners.setdefault(url)
                    url_hosts.add(host)
        for cand in _IPV4_RE.findall(s) + _IPV6_RE.findall(s):
            if _is_raw_ip(cand):
                ips.setdefault(cand)
        for dom in _DOMAIN_RE.findall(s):
            dom = dom.lower().strip("-")
            if dom.rsplit(".", 1)[-1] in DOMAIN_TLDS or dom in URL_SHORTENERS:
                domains.setdefault(dom)
                if dom.removeprefix("www.") in URL_SHORTENERS and dom not in url_hosts:
                    shorteners.setdefault(dom)  # scheme-less "bit.ly/..." mention
    return {
        "urls": _capped(urls),
        "ip_literals": _capped(ips),
        "domains": _capped(domains),
        "shortener_urls": _capped(shorteners),
    }


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
    except ValueError:
        return False
    return True


# Documentation ranges are not globally routable but are what fixtures (and docs) use.
_DOC_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


_GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")


def _is_raw_ip(s: str) -> bool:
    """A valid, globally routable IP literal (or a documentation-range one, for fixtures).

    LAN, loopback, link-local, CGNAT, netmasks and other reserved values are what legitimate
    code and test suites hard-code (requests' sdist has 17 such literals); an exfiltration
    target is routable. A version string that is a valid public IPv4 (``1.2.3.4``) still
    counts: it is indistinguishable.
    """
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    if any(ip.version == n.version and ip in n for n in _DOC_NETS):
        return True
    # IPv6: only global unicast (2000::/3); Python calls odd reserved values like ::2 global.
    return ip.is_global and (ip.version == 4 or ip in _GLOBAL_UNICAST_V6)


# ---------------------------------------------------------------- per-file handlers


def _handle_pth(acc: _Acc, text: str) -> None:
    # site.py executes a .pth line iff it starts with "import " or "import\t".
    for line in text.splitlines():
        if line.startswith(("import ", "import\t")):
            acc.install["pth_import_lines"] = True
            _analyse_source(acc, line, hook=True, setup_py=False)


def _handle_pyproject(acc: _Acc, text: str) -> None:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        acc.syntax_errors += 1  # malformed TOML: a feature, like a .py syntax error
        return
    build = doc.get("build-system")
    if isinstance(build, dict) and build.get("build-backend"):
        acc.install["pep517_build_backend"] = True


# ---------------------------------------------------------------- public API


def analyze_dir(
    root: Path, filename: str, sha256: str, kind: ArtifactKind
) -> ArtifactStaticFeatures:
    """Static features of one already-extracted artifact directory.

    Per-file problems (syntax errors, undecodable bytes, oversize .py, malformed TOML) are
    counted in ``syntax_error_count``; an unreadable tree raises ``PipGuardError``.
    """
    root = Path(root)
    if not root.is_dir():
        raise PipGuardError(f"extracted artifact directory not found: {root}")

    def _walk_error(e: OSError) -> None:
        raise PipGuardError(f"cannot walk {root}: {e}") from e

    acc = _Acc()
    file_count = total_size = py_count = 0
    compiled = has_root_setup = False
    for dirpath, _dirs, files in os.walk(root, onerror=_walk_error):
        for fname in files:
            path = Path(dirpath, fname)
            try:
                st = path.lstat()
            except OSError as e:
                raise PipGuardError(f"cannot stat {path}: {e}") from e
            file_count += 1
            total_size += st.st_size
            suffix = path.suffix.lower()
            compiled = compiled or suffix in COMPILED_SUFFIXES
            if path.is_symlink() or (suffix != ".py" and suffix not in TEXT_SCAN_SUFFIXES):
                continue  # extraction rejects links; never follow one if it slipped through
            try:
                data = _read_capped(path)
            except OSError as e:
                raise PipGuardError(f"cannot read {path}: {e}") from e
            if suffix == ".py":
                py_count += 1
                # Only the project's own setup.py (root or the sdist's top folder) runs at
                # install time; vendored sub-projects' setup.py files never do.
                is_setup = fname == "setup.py" and len(path.relative_to(root).parts) <= 2
                has_root_setup = has_root_setup or is_setup
                ok = data is not None and _analyse_source(
                    acc, data, hook=is_setup, setup_py=is_setup
                )
                acc.syntax_errors += not ok
                continue
            if data is None:
                continue
            text = data.decode("utf-8", errors="replace")
            acc.strings.append(text)
            if suffix == ".pth":
                _handle_pth(acc, text)
            elif (
                kind is ArtifactKind.SDIST
                and fname == "pyproject.toml"
                # Only the project's own file (root or the sdist's top folder), not test data.
                and len(path.relative_to(root).parts) <= 2
            ):
                _handle_pyproject(acc, text)

    return ArtifactStaticFeatures(
        filename=filename,
        sha256=sha256,
        kind=kind,
        file_count=file_count,
        total_size=total_size,
        py_file_count=py_count,
        syntax_error_count=acc.syntax_errors,
        has_compiled_extensions=compiled,
        # An install-command override only runs via the project's own setup.py; classes in
        # vendored or test code of a setup.py-less (e.g. meson) sdist never execute.
        install=InstallIndicators(
            **(acc.install | ({} if has_root_setup else {"overridden_install_command": False}))
        ),
        suspicious=SuspiciousCounts(**acc.counts),
        max_string_entropy=round(acc.max_entropy, 4),
        high_entropy_string_count=acc.high_entropy,
        **_scan_network_literals(acc.strings),
        risky_import_categories=[c for c in ImportCategory if c in acc.categories],
        risky_import_modules=_capped(acc.modules),
    )


def analyze(pkg: FetchedPackage, *, snapshot: TopPackages | None = None) -> StaticFeatures:
    """FR-3: static features for every artifact plus the typosquat score."""
    if not pkg.artifacts:
        raise PipGuardError(f"{pkg.spec}: no artifacts to analyse")
    results = []
    for art in pkg.artifacts:
        if art.extracted_path is None:
            raise PipGuardError(f"{art.filename}: not extracted; refusing to analyse")
        results.append(analyze_dir(Path(art.extracted_path), art.filename, art.sha256, art.kind))
    top = snapshot or default_top_packages()
    return StaticFeatures(
        spec=pkg.spec,
        artifacts=results,
        typosquat=typosquat(pkg.spec.name, top),
        metadata=pkg.metadata,
    )
