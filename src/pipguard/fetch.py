"""Fetch the exact artifacts of a pinned package from PyPI (FR-2.1, FR-2.2, FR-2.4, FR-2.5).

Nothing here runs package code: we read PyPI JSON, stream files to disk while hashing,
and read wheel METADATA straight out of the zip. Every PyPI response and every downloaded
file is untrusted input. Any failure raises a ``FetchError`` (fail closed).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import time
import urllib.error
import urllib.request
import zipfile
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from email.parser import HeaderParser
from pathlib import Path
from typing import IO, Any
from urllib.parse import quote

from pipguard import __version__
from pipguard.errors import FetchError, HashMismatchError
from pipguard.models import (
    Artifact,
    ArtifactKind,
    FetchedPackage,
    PackageMetadata,
    PackageSpec,
    normalize_name,
)

log = logging.getLogger(__name__)

PYPI = "https://pypi.org/pypi"
USER_AGENT = f"pipguard/{__version__}"
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024  # big projects' release JSON runs to tens of MB
MAX_METADATA_BYTES = 1024 * 1024
MAX_REQUIREMENTS = 500
MAX_DEP_WHEELS = 50
MAX_DEP_DEPTH = 10
TRIES = 3
TIMEOUT_S = 30.0

# The sandbox image is python:3.12-slim-bookworm: glibc 2.36, so a manylinux wheel newer
# than 2_36 will not install there, and musllinux wheels never will (glibc, not musl).
SANDBOX_GLIBC = (2, 36)
_LEGACY_MANYLINUX = {"manylinux1": (2, 5), "manylinux2010": (2, 12), "manylinux2014": (2, 17)}
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SDIST_SUFFIXES = (".tar.gz", ".zip", ".tar.bz2", ".tgz", ".tar")

Opener = Callable[[urllib.request.Request, float], IO[bytes]]


class _NotFound(FetchError):
    """PyPI answered 404: retrying will not help."""


def _urlopen(req: urllib.request.Request, timeout: float) -> IO[bytes]:
    return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 (https enforced in _retry)


class PyPIClient:
    """The only thing that touches the network. Tests pass a fake ``opener``."""

    def __init__(
        self, opener: Opener = _urlopen, sleep: Callable[[float], None] = time.sleep
    ) -> None:
        self._opener = opener
        self._sleep = sleep

    def _retry[T](self, url: str, action: Callable[[], T]) -> T:
        if not url.startswith("https://"):  # urlopen also speaks file:// and ftp://
            raise FetchError(f"refusing non-https URL: {url!r}")
        last: Exception | None = None
        for attempt in range(TRIES):
            try:
                return action()
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    raise _NotFound(f"not found on PyPI: {url}") from e
                last = e
            except (OSError, ValueError) as e:  # URLError, timeouts, resets, bad JSON
                last = e
            if attempt < TRIES - 1:
                self._sleep(2**attempt)
        raise FetchError(f"{url}: failed after {TRIES} tries: {last}") from last

    def _read_capped(self, url: str, out: Callable[[bytes], None], cap: int) -> int:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
        total = 0
        with self._opener(req, TIMEOUT_S) as resp:
            while chunk := resp.read(64 * 1024):
                total += len(chunk)
                if total > cap:
                    raise FetchError(f"{url}: response exceeds {cap} bytes")
                out(chunk)
        return total

    def get_json(self, url: str) -> dict[str, Any]:
        def go() -> dict[str, Any]:
            buf = bytearray()
            self._read_capped(url, buf.extend, MAX_JSON_BYTES)
            data = json.loads(buf)
            if not isinstance(data, dict):
                raise ValueError("PyPI JSON is not an object")
            return data

        return self._retry(url, go)

    def download(self, url: str, path: Path, expected_sha256: str) -> int:
        """Stream ``url`` to ``path``, enforcing the size cap and SHA-256. Returns the size."""
        part = path.with_name(path.name + ".part")

        def go() -> int:
            h = hashlib.sha256()
            with part.open("wb") as f:

                def sink(chunk: bytes) -> None:
                    h.update(chunk)
                    f.write(chunk)

                size = self._read_capped(url, sink, MAX_DOWNLOAD_BYTES)
            if h.hexdigest() != expected_sha256:
                raise HashMismatchError(
                    f"{path.name}: sha256 {h.hexdigest()} != PyPI {expected_sha256}"
                )
            return size

        try:
            size = self._retry(url, go)
        except BaseException:
            part.unlink(missing_ok=True)
            raise
        part.replace(path)
        return size


# ---------------------------------------------------------------- wheel selection


def _wheel_tags(filename: str) -> tuple[str, str, str] | None:
    parts = filename.removesuffix(".whl").split("-")
    if not filename.endswith(".whl") or len(parts) not in (5, 6):
        return None
    return parts[-3], parts[-2], parts[-1]


def _platform_rank(plat: str) -> tuple[int, int, int] | None:
    """Higher is better; None if the sandbox (linux x86_64, glibc 2.36) cannot install it."""
    if plat == "any":
        return (3, 0, 0)
    if plat == "linux_x86_64":
        return (1, 0, 0)
    if not plat.endswith("_x86_64"):
        return None
    head = plat.removesuffix("_x86_64")
    if head in _LEGACY_MANYLINUX:
        glibc = _LEGACY_MANYLINUX[head]
    else:
        m = re.fullmatch(r"manylinux_(\d+)_(\d+)", head)
        if not m:
            return None  # musllinux, or something we do not recognise
        glibc = (int(m[1]), int(m[2]))
    return (2, *glibc) if glibc <= SANDBOX_GLIBC else None


def _wheel_rank(filename: str) -> tuple[tuple[int, int, int], int] | None:
    """Rank a wheel for the sandbox (CPython 3.12, linux x86_64), or None if incompatible.

    Pure ``py3-none-any`` beats manylinux (highest glibc that still fits), which beats
    ``linux_x86_64``. Among equals, a ``cp312`` ABI beats ``abi3``.
    """
    tags = _wheel_tags(filename)
    if tags is None:
        return None
    pys, abis, plats = (set(t.split(".")) for t in tags)
    abi_rank = -1
    if "none" in abis and pys & {"py3", "py312", "cp312"}:
        abi_rank = 0
    if "abi3" in abis and any(re.fullmatch(r"cp3(\d+)", p) and int(p[3:]) <= 12 for p in pys):
        abi_rank = 1
    if "cp312" in abis and "cp312" in pys:
        abi_rank = 2
    ranks = [r for p in plats if (r := _platform_rank(p))]
    if abi_rank < 0 or not ranks:
        return None
    return max(ranks), abi_rank


def _pick_wheel(files: list[dict[str, Any]]) -> dict[str, Any] | None:
    scored = [
        (rank, f["filename"])
        for f in files
        if f.get("packagetype") == "bdist_wheel"
        and isinstance(f.get("filename"), str)
        and (rank := _wheel_rank(f["filename"]))
    ]
    if not scored:
        return None
    best = max(scored)[1]  # filename breaks ties deterministically
    return next(f for f in files if f.get("filename") == best)


def _pick_sdist(files: list[dict[str, Any]]) -> dict[str, Any] | None:
    for suffix in _SDIST_SUFFIXES:
        for f in files:
            name = f.get("filename")
            if f.get("packagetype") == "sdist" and isinstance(name, str) and name.endswith(suffix):
                return f
    return None


def _download(client: PyPIClient, file: dict[str, Any], dest: Path, kind: ArtifactKind) -> Artifact:
    name = file.get("filename")
    url = file.get("url")
    sha = (file.get("digests") or {}).get("sha256")
    if not isinstance(name, str) or not _SAFE_FILENAME.match(name) or ".." in name:
        raise FetchError(f"unsafe filename from PyPI: {name!r}")
    if not isinstance(url, str) or not isinstance(sha, str) or not _SHA256.match(sha):
        raise FetchError(f"{name}: PyPI entry lacks a URL or a valid sha256 digest")
    if isinstance(file.get("size"), int) and file["size"] > MAX_DOWNLOAD_BYTES:
        raise FetchError(f"{name}: {file['size']} bytes exceeds the {MAX_DOWNLOAD_BYTES} cap")
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / name
    size = client.download(url, path, sha)
    tags = _wheel_tags(name) if kind is ArtifactKind.WHEEL else None
    return Artifact(
        filename=name,
        kind=kind,
        sha256=sha,
        python_tag=tags[0] if tags else None,
        platform_tag=tags[2] if tags else None,
        size=size,
        path=str(path),
    )


# ---------------------------------------------------------------- metadata (FR-2.4)


def _cap(s: object, n: int) -> str | None:
    return s[:n] if isinstance(s, str) and s else None


def _upload_time(f: dict[str, Any]) -> datetime | None:
    raw = f.get("upload_time_iso_8601") or f.get("upload_time")
    if not isinstance(raw, str):
        return None
    try:
        t = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _metadata(
    version_json: dict[str, Any], project_json: dict[str, Any], now: datetime
) -> PackageMetadata:
    info = version_json.get("info") or {}
    own = [t for f in version_json.get("urls") or [] if (t := _upload_time(f))]
    releases = project_json.get("releases") or {}
    # A release whose files were all deleted is an empty list; it does not count.
    firsts = [
        min(ts)
        for files in releases.values()
        if (ts := [t for f in files if (t := _upload_time(f))])
    ]
    release = min(own) if own else None
    first = min(firsts) if firsts else None
    raw_urls = info.get("project_urls") or {}
    urls = (
        {
            k[:100]: v[:500]
            for k, v in list(raw_urls.items())[:30]
            if isinstance(k, str) and isinstance(v, str)
        }
        if isinstance(raw_urls, dict)
        else {}
    )
    return PackageMetadata(
        release_date=release,
        first_release_date=first,
        version_count=len(firsts) if releases else None,
        maintainer_count=None,  # the PyPI JSON API does not expose maintainers
        days_since_release=(now - release).days if release else None,
        days_since_first_release=(now - first).days if first else None,
        project_urls=urls,
        summary=_cap(info.get("summary"), 500),
    )


# ---------------------------------------------------------------- requirements (FR-2.5)


def read_requires_dist(wheel: Path) -> list[str]:
    """``Requires-Dist`` lines from a wheel's METADATA, read from the zip without extracting."""
    try:
        with zipfile.ZipFile(wheel) as zf:
            metas = [
                i for i in zf.infolist() if re.fullmatch(r"[^/]+\.dist-info/METADATA", i.filename)
            ]
            if len(metas) != 1:
                raise FetchError(
                    f"{wheel.name}: expected one .dist-info/METADATA, found {len(metas)}"
                )
            if metas[0].file_size > MAX_METADATA_BYTES:
                raise FetchError(f"{wheel.name}: METADATA too large")
            with zf.open(metas[0]) as f:
                text = f.read(MAX_METADATA_BYTES + 1).decode("utf-8", errors="replace")
    except (zipfile.BadZipFile, OSError) as e:
        raise FetchError(f"{wheel.name}: unreadable wheel: {e}") from e
    reqs = HeaderParser().parsestr(text).get_all("Requires-Dist") or []
    return [str(r).strip()[:500] for r in reqs[:MAX_REQUIREMENTS]]


# ponytail: minimal PEP 440 subset, not `packaging`. Handles N(.N)* and .postN (local "+x"
# dropped). Epochs, pre/dev releases and `===` are treated as "cannot decide": such
# candidates are skipped and such specifiers make the requirement unresolvable (logged).
# Also ignores PEP 440's rule that `>V` excludes post-releases of V. Swap in `packaging`
# if this ever picks the wrong dependency version.
_VERSION = re.compile(r"(\d+(?:\.\d+)*)(?:\.?post(\d+))?")


def _parse_version(v: str) -> tuple[tuple[int, ...], int] | None:
    m = _VERSION.fullmatch(v.strip().lower().split("+")[0])
    if not m:
        return None
    rel = tuple(int(x) for x in m[1].split("."))
    while len(rel) > 1 and rel[-1] == 0:
        rel = rel[:-1]
    return rel, int(m[2]) if m[2] is not None else -1


def _clause_ok(op: str, target: str, v: tuple[tuple[int, ...], int]) -> bool:
    if target.endswith(".*") and op in ("==", "!="):
        prefix = _parse_version(target[:-2])
        if prefix is None:
            raise ValueError(target)
        n = len(target[:-2].split("."))
        padded = v[0] + (0,) * n
        hit = padded[:n] == (prefix[0] + (0,) * n)[:n]
        return hit if op == "==" else not hit
    t = _parse_version(target)
    if t is None:
        raise ValueError(target)
    if op == "~=":
        n = len(target.split(".")) - 1
        if n < 1:
            raise ValueError(target)
        return v >= t and (v[0] + (0,) * n)[:n] == (t[0] + (0,) * n)[:n]
    return {
        "==": v == t,
        "!=": v != t,
        ">=": v >= t,
        "<=": v <= t,
        ">": v > t,
        "<": v < t,
    }[op]


_CLAUSE = re.compile(r"\s*(~=|==|!=|>=|<=|>|<)\s*([A-Za-z0-9.*+!_-]+)\s*")


def _parse_specifier(spec: str) -> list[tuple[str, str]]:
    spec = spec.strip().removeprefix("(").removesuffix(")")
    out = []
    for clause in filter(None, (c.strip() for c in spec.split(","))):
        m = _CLAUSE.fullmatch(clause)
        if not m:
            raise ValueError(clause)
        out.append((m[1], m[2]))
    return out


# Marker environment of the sandbox image, not of the host.
SANDBOX_MARKERS = {
    "os_name": "posix",
    "sys_platform": "linux",
    "platform_system": "Linux",
    "platform_machine": "x86_64",
    "platform_python_implementation": "CPython",
    "implementation_name": "cpython",
    "python_version": "3.12",
    "python_full_version": "3.12.0",
    "implementation_version": "3.12.0",
    "extra": "",  # we never install extras, so `extra == "x"` requirements drop out
}
_VERSION_VARS = {"python_version", "python_full_version", "implementation_version"}
_MARKER_TOKEN = re.compile(
    r"\s*(?:(\()|(\))|('[^']*'|\"[^\"]*\")|(===|==|!=|<=|>=|~=|<|>|not\s+in\b|in\b)|"
    r"(and\b|or\b)|([A-Za-z_][A-Za-z0-9_.]*))"
)


def evaluate_marker(marker: str) -> bool:
    """Evaluate a PEP 508 marker against ``SANDBOX_MARKERS``. Raises ValueError if unsure."""
    toks: list[tuple[str, str]] = []
    pos = 0
    marker = marker.strip()
    while pos < len(marker):
        m = _MARKER_TOKEN.match(marker, pos)
        if not m or m.end() == pos:
            raise ValueError(f"bad marker: {marker!r}")
        group = m.lastindex or 0
        toks.append((["(", ")", "str", "op", "bool", "var"][group - 1], " ".join(m[group].split())))
        pos = m.end()
    i = 0

    def peek() -> tuple[str, str]:
        return toks[i] if i < len(toks) else ("end", "")

    def take(kind: str) -> str:
        nonlocal i
        k, v = peek()
        if k != kind:
            raise ValueError(f"bad marker: {marker!r}")
        i += 1
        return v

    def value() -> tuple[str, str | None]:  # (text, variable name or None for a literal)
        if peek()[0] == "str":
            return take("str")[1:-1], None
        name = take("var")
        if name not in SANDBOX_MARKERS:
            raise ValueError(f"unknown marker variable {name!r}")
        return SANDBOX_MARKERS[name], name

    def compare() -> bool:
        if peek()[0] == "(":
            take("(")
            r = expr()
            take(")")
            return r
        (lhs, lvar), op, (rhs, rvar) = value(), take("op"), value()
        if op == "in":
            return lhs in rhs
        if op == "not in":
            return lhs not in rhs
        if (lvar or rvar) in _VERSION_VARS and op != "===":
            ver, spec = (lhs, rhs) if lvar else (rhs, lhs)
            if not lvar:  # 'x' < python_version  ==  python_version > 'x'
                op = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}.get(op, op)
            parsed = _parse_version(ver)
            if parsed is None:
                raise ValueError(ver)
            return _clause_ok(op, spec, parsed)
        if op in ("==", "==="):
            return lhs == rhs
        if op == "!=":
            return lhs != rhs
        raise ValueError(f"cannot compare {lhs!r} {op} {rhs!r}")

    def conj() -> bool:
        r = compare()
        while peek() == ("bool", "and"):
            take("bool")
            r = compare() and r
        return r

    def expr() -> bool:
        r = conj()
        while peek() == ("bool", "or"):
            take("bool")
            r = conj() or r
        return r

    result = expr()
    if i != len(toks):
        raise ValueError(f"bad marker: {marker!r}")
    return result


_REQUIREMENT = re.compile(
    r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*([^;@]*?)\s*(?:;(.*))?"
)


def parse_requirement(req: str) -> tuple[str, list[tuple[str, str]]] | None:
    """``(name, clauses)`` if ``req`` applies to the sandbox, None if its marker excludes it.

    Raises ValueError for anything we cannot resolve deterministically (URLs, odd markers).
    """
    m = _REQUIREMENT.fullmatch(req)
    if not m:
        raise ValueError(f"unsupported requirement: {req!r}")
    if m[3] is not None and not evaluate_marker(m[3]):
        return None
    return m[1], _parse_specifier(m[2])


def _resolve_version(
    project: dict[str, Any], clauses: list[tuple[str, str]]
) -> dict[str, Any] | None:
    """Wheel file of the newest stable, non-yanked release that satisfies ``clauses``."""
    releases: dict[str, Any] = project.get("releases") or {}
    if len(clauses) == 1 and clauses[0][0] == "==" and clauses[0][1] in releases:
        candidates = [clauses[0][1]]  # exact pin: honour it even for a pre-release
    else:
        ok = []
        for v in releases:
            parsed = _parse_version(v)
            if parsed and all(_clause_ok(op, t, parsed) for op, t in clauses):
                ok.append((parsed, v))
        candidates = [v for _, v in sorted(ok, reverse=True)]
    for v in candidates:
        files = [f for f in releases[v] or [] if not f.get("yanked")]
        if files and (wheel := _pick_wheel(files)):
            return wheel
    return None


def _resolve_deps(
    client: PyPIClient, target: PackageSpec, requirements: list[str], dest: Path
) -> list[Artifact]:
    """Download wheels for the transitive closure of ``requirements`` (breadth first).

    These are preinstalled untraced in the sandbox so the target can import; they are not
    scanned. The first requirement seen for a name wins.
    """
    seen = {target.normalized_name}
    queue = deque((r, 1) for r in requirements)
    deps: list[Artifact] = []
    while queue:
        req, depth = queue.popleft()
        try:
            parsed = parse_requirement(req)
        except ValueError as e:
            log.warning("skipping requirement %r: %s", req, e)
            continue
        if parsed is None or normalize_name(parsed[0]) in seen:
            continue
        name, clauses = parsed
        seen.add(normalize_name(name))
        if depth > MAX_DEP_DEPTH:
            raise FetchError(f"dependency chain deeper than {MAX_DEP_DEPTH} at {name}")
        if len(deps) >= MAX_DEP_WHEELS:
            raise FetchError(f"more than {MAX_DEP_WHEELS} dependency wheels")
        try:
            project = client.get_json(f"{PYPI}/{quote(name)}/json")
            file = _resolve_version(project, clauses)
        except _NotFound:
            file = None
        except ValueError as e:
            log.warning("skipping requirement %r: %s", req, e)
            continue
        if file is None:
            log.warning("no sandbox-compatible wheel for requirement %r", req)
            continue
        art = _download(client, file, dest, ArtifactKind.WHEEL)
        deps.append(art)
        queue.extend((r, depth + 1) for r in read_requires_dist(Path(art.path)))
    return deps


# ---------------------------------------------------------------- entry points


def fetch(
    spec: PackageSpec,
    dest: Path,
    *,
    client: PyPIClient | None = None,
    now: datetime | None = None,
) -> FetchedPackage:
    """Resolve ``spec`` on PyPI, download its sandbox wheel and sdist, and their deps."""
    client = client or PyPIClient()
    now = now or datetime.now(UTC)
    name = quote(spec.name)
    version_json = client.get_json(f"{PYPI}/{name}/{quote(spec.version)}/json")
    project_json = client.get_json(f"{PYPI}/{name}/json")
    files = [f for f in version_json.get("urls") or [] if isinstance(f, dict)]
    wheel, sdist = _pick_wheel(files), _pick_sdist(files)
    if wheel is None and sdist is None:
        raise FetchError(f"{spec}: no sandbox-compatible wheel and no sdist on PyPI")
    artifacts = [
        _download(client, f, dest, kind)
        for f, kind in ((wheel, ArtifactKind.WHEEL), (sdist, ArtifactKind.SDIST))
        if f is not None
    ]
    requirements: list[str] = []
    deps: list[Artifact] = []
    if wheel is not None:
        requirements = read_requires_dist(Path(artifacts[0].path))
        deps = _resolve_deps(client, spec, requirements, dest / "deps")
    return FetchedPackage(
        spec=spec,
        artifacts=artifacts,
        metadata=_metadata(version_json, project_json, now),
        declared_requirements=requirements,
        declared_deps=deps,
    )


def primary_sha256(spec: PackageSpec, *, client: PyPIClient | None = None) -> str:
    """SHA-256 PyPI publishes for the artifact ``fetch`` would scan first (wheel, else sdist).

    One JSON request and no download, so a cache hit can skip every stage (FR-1.3).
    """
    client = client or PyPIClient()
    data = client.get_json(f"{PYPI}/{quote(spec.name)}/{quote(spec.version)}/json")
    files = [f for f in data.get("urls") or [] if isinstance(f, dict)]
    chosen = _pick_wheel(files) or _pick_sdist(files)
    sha = ((chosen or {}).get("digests") or {}).get("sha256")
    if not isinstance(sha, str) or len(sha) != 64:
        raise FetchError(f"{spec}: no artifact with a published sha256")
    return sha.lower()


def from_local_artifact(path: Path, dest: Path) -> FetchedPackage:
    """Wrap a local wheel or sdist (``--artifact``, FR-7.1). No network; metadata is missing."""
    name = path.name
    if not _SAFE_FILENAME.match(name):
        raise FetchError(f"unsafe artifact filename: {name!r}")
    tags = _wheel_tags(name)
    if tags:
        kind = ArtifactKind.WHEEL
        dist, version = name.split("-")[:2]
    elif name.endswith(_SDIST_SUFFIXES):
        kind = ArtifactKind.SDIST
        stem = next(name.removesuffix(s) for s in _SDIST_SUFFIXES if name.endswith(s))
        dist, _, version = stem.rpartition("-")
    else:
        raise FetchError(f"not a wheel or sdist: {name!r}")
    try:
        spec = PackageSpec(name=dist, version=version)
        if path.stat().st_size > MAX_DOWNLOAD_BYTES:
            raise FetchError(f"{name}: larger than {MAX_DOWNLOAD_BYTES} bytes")
        dest.mkdir(parents=True, exist_ok=True)
        copy = dest / name
        shutil.copyfile(path, copy)
    except (ValueError, OSError) as e:
        raise FetchError(f"cannot use local artifact {name!r}: {e}") from e
    art = Artifact(
        filename=name,
        kind=kind,
        sha256=hashlib.sha256(copy.read_bytes()).hexdigest(),
        python_tag=tags[0] if tags else None,
        platform_tag=tags[2] if tags else None,
        size=copy.stat().st_size,
        path=str(copy),
    )
    return FetchedPackage(
        spec=spec,
        artifacts=[art],
        metadata=PackageMetadata(),
        declared_requirements=read_requires_dist(copy) if tags else [],
        origin="local_artifact",
    )
