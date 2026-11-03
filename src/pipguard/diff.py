"""Pinned direct-dependency diff between PR base and head (FR-1.1, FR-1.2).

Parsing is deliberately conservative and dependency-free (no ``packaging``): an exact
``name==version`` pin is the only thing scanned; every other form becomes an
``unsupported`` entry with a specific reason, so nothing is silently dropped. Extras and
markers are reported unsupported (FR-1.4 is P2). Lockfiles and Poetry tables are out of
scope (FR-1.5).
"""

from __future__ import annotations

import codecs
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from pipguard.errors import PipGuardError
from pipguard.models import ChangeKind, DependencyChange, PackageSpec, normalize_name

_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
# pip strips comments that start a line or follow whitespace; `url#egg=` keeps its `#`.
_COMMENT = re.compile(r"(^|\s)#.*$")
_INCLUDES = ("-r", "--requirement", "-c", "--constraint")
_EDITABLE = ("-e", "--editable")
_INDEX_OPTIONS = ("-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--no-index")
_MAX_RAW = 500  # a requirement line longer than this is not a real pin


@dataclass(frozen=True)
class ParsedReq:
    """One requirement as written. Exactly one of ``spec`` / ``unsupported_reason`` is set."""

    raw: str
    name: str | None  # PEP 503-normalised; None when no name could be read (URL, path, -r)
    spec: PackageSpec | None = None
    unsupported_reason: str | None = None


def parse_requirement(line: str) -> ParsedReq:
    """Parse one PEP 508-ish requirement string (no comments, no options)."""
    raw = line.strip()[:_MAX_RAW]
    m = _NAME.match(raw)
    if m and raw[m.end() :].lstrip().startswith("@"):
        name = normalize_name(m.group(0))
        return ParsedReq(raw, name, unsupported_reason="direct URL reference (name @ url)")
    if "://" in raw or raw.startswith((".", "/", "\\", "~")) or re.match(r"^[A-Za-z]:[\\/]", raw):
        return ParsedReq(raw, None, unsupported_reason="URL or local path requirement")
    if not m:
        return ParsedReq(raw, None, unsupported_reason="unparseable requirement")
    name = normalize_name(m.group(0))
    rest = raw[m.end() :].strip()

    def bad(reason: str) -> ParsedReq:
        return ParsedReq(raw, name, unsupported_reason=reason)

    if rest.startswith("["):
        return bad("extras are not supported in v1 (FR-1.4)")
    if ";" in rest:
        return bad("environment markers are not supported in v1 (FR-1.4)")
    if not rest:
        return bad("unpinned: no version specifier")
    if rest.startswith("==="):
        return bad("arbitrary equality (===) is not an exact pin")
    if not rest.startswith("=="):
        if re.match(r"^(~=|>=|<=|!=|<|>)", rest):
            return bad(f"not an exact pin ({rest[:2].rstrip()} range)")
        return bad("unparseable requirement")
    version = rest[2:].strip()
    if "," in version:
        return bad("multiple version specifiers are not an exact pin")
    if "*" in version:
        return bad("wildcard version (==X.*) is not an exact pin")
    try:
        spec = PackageSpec(name=m.group(0), version=version)
    except ValidationError:
        return bad("invalid version in pin")
    return ParsedReq(raw, name, spec=spec)


def _logical_lines(text: str) -> list[str]:
    """Join backslash continuations, then strip comments and blanks."""
    out: list[str] = []
    buf = ""
    for physical in text.splitlines():
        if physical.endswith("\\"):
            buf += physical[:-1] + " "
            continue
        line = _COMMENT.sub("", buf + physical).strip()
        buf = ""
        if line:
            out.append(line)
    tail = _COMMENT.sub("", buf).strip()
    if tail:
        out.append(tail)
    return out


def parse_requirements(text: str) -> list[ParsedReq]:
    """Parse a ``requirements.txt``. Option lines are ignored; includes are unsupported."""
    reqs: list[ParsedReq] = []
    for line in _logical_lines(text):
        if line.startswith("-"):
            opt = re.split(r"[\s=]", line, maxsplit=1)[0]
            if opt in _INCLUDES:
                reqs.append(
                    ParsedReq(
                        line[:_MAX_RAW], None, unsupported_reason="included file not followed"
                    )
                )
            elif opt in _INDEX_OPTIONS:
                # pip would install from somewhere other than the PyPI artifact we scan.
                reqs.append(
                    ParsedReq(
                        line[:_MAX_RAW],
                        None,
                        unsupported_reason="index option changes where pip installs from",
                    )
                )
            elif opt in _EDITABLE:
                reqs.append(
                    ParsedReq(line[:_MAX_RAW], None, unsupported_reason="editable requirement")
                )
            continue  # --index-url, --hash on its own line, etc.: no dependency of its own
        # Per-requirement options such as `--hash=sha256:...` follow the requirement.
        reqs.append(parse_requirement(re.split(r"\s+--?[A-Za-z]", line, maxsplit=1)[0]))
    return reqs


def parse_pyproject(text: str) -> list[ParsedReq]:
    """PEP 621 ``[project] dependencies`` only. Malformed TOML is an error, not 'no deps'."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PipGuardError(f"invalid pyproject.toml: {exc}") from exc
    project = data.get("project", {})
    deps = project.get("dependencies", []) if isinstance(project, dict) else None
    if not isinstance(deps, list) or not all(isinstance(d, str) for d in deps):
        raise PipGuardError("pyproject.toml [project] dependencies is not a list of strings")
    return [parse_requirement(d) for d in deps]


def _parse_file(path: str, text: str) -> list[ParsedReq]:
    return parse_pyproject(text) if path.endswith(".toml") else parse_requirements(text)


def _identity(req: ParsedReq) -> str:
    """What must match for a requirement to count as unchanged."""
    if req.spec is not None:
        return f"=={req.spec.version}"
    return "".join(req.raw.split()).lower()


def diff_dependencies(
    base_files: dict[str, str], head_files: dict[str, str]
) -> list[DependencyChange]:
    """Added or changed requirements, per file (a move between files is rescanned).

    ADDED: the name (or, for nameless entries, the line) is not in that base file.
    CHANGED: the name is there but its pinned version, or pin-ness, differs.
    Removed and unchanged requirements produce nothing.
    """
    changes: list[DependencyChange] = []
    for path, head_text in head_files.items():
        base: dict[str, list[ParsedReq]] = {}
        for req in _parse_file(path, base_files.get(path, "")):
            base.setdefault(req.name or req.raw, []).append(req)
        for req in _parse_file(path, head_text):
            previous = base.get(req.name or req.raw)
            if previous and _identity(req) in {_identity(p) for p in previous}:
                continue
            prev_version = next((p.spec.version for p in previous or [] if p.spec), None)
            changes.append(
                DependencyChange(
                    raw=req.raw,
                    source_file=path,
                    kind=ChangeKind.CHANGED if previous else ChangeKind.ADDED,
                    spec=req.spec,
                    previous_version=prev_version,
                    unsupported_reason=req.unsupported_reason,
                )
            )
    return changes


def decode_requirements(data: bytes) -> str:
    """Decode like pip: honour a UTF-8/UTF-16/UTF-32 BOM, else UTF-8.

    pip reads a UTF-16 requirements file correctly; decoding it as UTF-8 would turn every
    line into an "unparseable" warn and let the dependencies through unscanned.
    """
    boms = (
        (codecs.BOM_UTF32_LE, "utf-32"),
        (codecs.BOM_UTF32_BE, "utf-32"),
        (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF16_LE, "utf-16"),
        (codecs.BOM_UTF16_BE, "utf-16"),
    )
    for bom, enc in boms:
        if data.startswith(bom):
            return data.decode(enc, errors="replace")
    return data.decode("utf-8", errors="replace")


def read_files_at(ref: str, paths: list[str], repo: Path = Path()) -> dict[str, str]:
    """Contents of ``paths`` at git ``ref`` via ``git show``. A missing file reads as empty.

    An unknown ref raises: a base we cannot read must not look like "no dependencies".
    """
    if not ref or ref.startswith("-"):
        raise PipGuardError(f"invalid git ref: {ref!r}")
    check = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        capture_output=True,
        check=False,
    )
    if check.returncode != 0:
        raise PipGuardError(f"git ref not found: {ref!r}")
    out: dict[str, str] = {}
    for path in paths:
        proc = subprocess.run(
            ["git", "-C", str(repo), "show", f"{ref}:{path}"], capture_output=True, check=False
        )
        out[path] = decode_requirements(proc.stdout) if proc.returncode == 0 else ""
    return out
