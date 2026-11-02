"""Defensive parser for ``strace -f`` output (FR-4.5, FR-4.11).

The trace text is attacker-influenced: the traced package chooses the paths, argv and
addresses that strace prints, and can even inject text into the stream. So this module:

- caps the whole input at 5 MB and every line at 64 KB before looking at it;
- uses only anchored or bounded regexes with no nested quantifiers, plus a linear
  hand-written argument splitter (no backtracking on hostile input);
- caps every extracted field (path 512, argv 32 x 256, address 64) and every
  observation list, and strips NUL/control characters;
- never evaluates anything and never Markdown-escapes (report.py escapes once, at render).

Unparseable lines are counted, never fatal. Field- and list-level caps set
``truncated`` but keep the observation; only an over-size *input* means the trace was
not fully parsed, which sandbox.py turns into ``incomplete:trace_truncated``.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from pipguard.models import ConnectAttempt, CredentialRead, FileWrite, Step, SubprocessCall

MAX_INPUT_BYTES = 5 * 1024 * 1024  # PRD performance: traces capped at 5 MB per package
MAX_LINE = 64 * 1024  # a legit line with -s 256 is far shorter; longer lines are cut
MAX_PATH = 512
MAX_ARGV_ITEMS = 32
MAX_ARG = 256
MAX_ADDRESS = 64
MAX_OBSERVATIONS = 100  # per category per step; a connect() loop must not balloon the report

# Writes here are expected (tmpfs mounts, devices, own /proc). Everything else is read-only
# in the container, so a write *attempt* outside them is the signal, even if it failed.
ALLOWED_WRITE_PREFIXES: tuple[str, ...] = (
    "/tmp",  # noqa: S108 - container paths, not host temp files
    "/sandbox/site-packages",
    "/sandbox/deps",
    "/home/sandbox/.cache",
    "/dev/null",
    "/dev/tty",
    "/dev/pts",
    "/dev/shm",  # noqa: S108
    "/proc/self",
)

# glibc's name-service code tries the nscd socket before reading /etc/passwd or resolving
# names (getpwuid, getaddrinfo). That is libc plumbing, not the package talking to anyone,
# and it would make W_CONNECT_INSTALL fire on ordinary code; so these two are dropped.
NSCD_SOCKETS = frozenset({"/var/run/nscd/socket", "/run/nscd/socket"})

# The container's WORKDIR. Relative AT_FDCWD paths resolve against it.
# ponytail: chdir() is not tracked; follow it if packages are seen evading via chdir.
SANDBOX_CWD = "/home/sandbox/project"

_WRITE_FLAGS = frozenset({"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"})

_PID = re.compile(r"(?:\[pid +)?(\d{1,10})\]? +")
_SYSCALL = re.compile(r"([a-z_][a-z0-9_]{0,31})\(")
_RESUMED = re.compile(r"<\.\.\. ([a-z_][a-z0-9_]{0,31}) resumed>")
_EXITED = re.compile(r"\+\+\+ exited with (\d{1,3}) \+\+\+")
_RET = re.compile(r" += (-?\d{1,20}|\?|0x[0-9a-fA-F]{1,16})")
_SPECIAL = re.compile(r'["(){}\[\],]')
_STR_END = re.compile(r'\\.|"', re.S)
_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|.)", re.S)
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_FLAG = re.compile(r"O_[A-Z]{1,16}")
_FAMILY = re.compile(r"sa_family=(AF_[A-Z0-9]{1,16})")
_PORT = re.compile(r"sin6?_port=htons\((\d{1,5})\)")
_INET = re.compile(r'inet_addr\("([0-9.]{1,15})"\)')
_INET6 = re.compile(r'inet_pton\(AF_INET6, "([0-9a-fA-F:.]{1,45})"')
_SUN = re.compile(r"sun_path=@?")
_UNFINISHED = " <unfinished ...>"
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "v": "\v", "f": "\f", "a": "\a", "b": "\b"}


@dataclass
class ParsedStep:
    """Observations from one traced step. sandbox.py merges two of these into a trace."""

    step: Step
    writes: list[FileWrite] = field(default_factory=list)
    credential_reads: list[CredentialRead] = field(default_factory=list)
    subprocesses: list[SubprocessCall] = field(default_factory=list)
    connects: list[ConnectAttempt] = field(default_factory=list)
    root_pid: int | None = None
    root_exit_code: int | None = None  # only if strace printed it (not with -qq)
    garbage_lines: int = 0
    truncated: bool = False  # some field, line or list was capped
    input_truncated: bool = False  # the input exceeded MAX_INPUT_BYTES: not fully parsed


@dataclass
class _State:
    out: ParsedStep
    creds: frozenset[str]
    allowed: tuple[str, ...]
    root_argv: list[str] | None = None
    root_exec_done: bool = False
    seen_exec: set[tuple[int, tuple[str, ...]]] = field(default_factory=set)
    seen: set[object] = field(default_factory=set)


def _clean(s: str, cap: int, out: ParsedStep) -> str:
    s = _CTRL.sub("", s)
    if len(s) > cap:
        out.truncated = True
        s = s[:cap]
    return s


def _string_end(s: str, start: int) -> int:
    """Index of the closing quote of the string opening at ``s[start]``, or -1."""
    i = start + 1
    while True:
        m = _STR_END.search(s, i)
        if m is None:
            return -1
        if m.group() == '"':
            return m.start()
        i = m.end()


def _unescape(m: re.Match[str]) -> str:
    e = m.group(1)
    if e[0] == "x" and len(e) == 3:
        return chr(int(e[1:], 16))
    if e[0] in "01234567":
        return chr(int(e, 8) & 0xFF)
    return _SIMPLE_ESCAPES.get(e, e)


def _decode(raw: str) -> str:
    # strace prints non-printable bytes as escapes; rebuild the bytes, then decode as UTF-8.
    latin = _ESCAPE.sub(_unescape, raw)
    return latin.encode("latin-1", "replace").decode("utf-8", "replace")


def decode_string(tok: str, cap: int, out: ParsedStep) -> str | None:
    """Decode a strace string token like ``"a\\x41"...``; None if it is not a string."""
    tok = tok.lstrip()
    if not tok.startswith('"'):
        return None
    end = _string_end(tok, 0)
    raw = tok[1:] if end < 0 else tok[1:end]
    if end < 0 or tok[end + 1 : end + 4] == "...":
        out.truncated = True  # strace (or our line cap) cut the string
    return _clean(_decode(raw), cap, out)


def split_args(s: str, start: int) -> tuple[list[str], str | None]:
    """Split ``s[start:]`` (after ``name(``) into top-level args and the text after ``)``.

    Linear: jumps between special characters, tracks bracket depth, skips quoted strings.
    An unterminated call (cut line, ``<unfinished ...>``) returns ``rest=None``.
    """
    args: list[str] = []
    depth = 0
    seg = i = start
    while True:
        m = _SPECIAL.search(s, i)
        if m is None:
            args.append(s[seg:].strip())
            return args, None
        c, j = m.group(), m.start()
        if c == '"':
            end = _string_end(s, j)
            if end < 0:
                args.append(s[seg:].strip())
                return args, None
            i = end + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0 and c == ")":
                args.append(s[seg:j].strip())
                return args, s[j + 1 :]
            depth = max(0, depth - 1)
        elif depth == 0:  # top-level comma
            args.append(s[seg:j].strip())
            seg = j + 1
        i = j + 1


def _argv(tok: str, out: ParsedStep) -> list[str]:
    """Parse ``["sh", "-c", "x"...]``, capped at MAX_ARGV_ITEMS x MAX_ARG."""
    argv: list[str] = []
    if not tok.startswith("["):
        return argv
    i = 1
    while i < len(tok):
        q = tok.find('"', i)
        if q < 0:
            break
        if len(argv) == MAX_ARGV_ITEMS:
            out.truncated = True
            break
        end = _string_end(tok, q)
        raw = tok[q + 1 :] if end < 0 else tok[q + 1 : end]
        if end < 0 or tok[end + 1 : end + 4] == "...":
            out.truncated = True
        argv.append(_clean(_decode(raw), MAX_ARG, out))
        if end < 0:
            break
        i = end + 1
    return argv


def _add[T](st: _State, bucket: list[T], key: object, item: T) -> None:
    if key in st.seen:
        return
    st.seen.add(key)
    if len(bucket) >= MAX_OBSERVATIONS:
        st.out.truncated = True
        return
    bucket.append(item)


def _is_allowed(path: str, allowed: Iterable[str]) -> bool:
    return any(path == p or path.startswith(p + "/") for p in allowed)


def _on_open(st: _State, name: str, args: list[str]) -> None:
    out = st.out
    path_i, flags_i = {"open": (0, 1), "creat": (0, -1), "openat": (1, 2), "openat2": (1, 2)}[name]
    if len(args) <= path_i:
        return
    path = decode_string(args[path_i], MAX_PATH, out)
    if path is None:
        return
    at_cwd = name in ("open", "creat") or args[0] == "AT_FDCWD"
    if path.startswith("/"):
        path = posixpath.normpath(path)
    elif at_cwd:
        path = posixpath.normpath(posixpath.join(SANDBOX_CWD, path))
    # else: relative to an unknown directory fd; kept as written and never "allowed".
    flags = set(_FLAG.findall(args[flags_i][:512])) if 0 <= flags_i < len(args) else set()
    if (name == "creat" or flags & _WRITE_FLAGS) and not (
        path.startswith("/") and _is_allowed(path, st.allowed)
    ):
        # Failed attempts (EROFS, EACCES) count: trying to write there is the signal.
        _add(st, out.writes, ("w", path), FileWrite(step=out.step, path=path))
    if path in st.creds:
        _add(st, out.credential_reads, ("c", path), CredentialRead(step=out.step, path=path))


def _on_exec(st: _State, pid: int, name: str, args: list[str], ok: bool) -> None:
    out = st.out
    path_i = 0 if name == "execve" else 1
    if len(args) <= path_i + 1:
        return
    was_truncated = out.truncated
    argv = _argv(args[path_i + 1], out)
    if not argv:
        path = decode_string(args[path_i], MAX_ARG, out)
        argv = [path] if path else []
    if not argv:
        return
    if pid == st.out.root_pid and not st.root_exec_done:
        # The command we launched ourselves (and its PATH-search ENOENT attempts) is not
        # behaviour of the package. A later execve by the root pid (os.execv) is.
        if st.root_argv is None:
            st.root_argv = argv
        if argv == st.root_argv:
            st.root_exec_done = ok
            out.truncated = was_truncated  # our own long -c program is not a capped field
            return
    key = (pid, tuple(argv))
    if key in st.seen_exec:  # PATH search: one attempt per directory, same argv
        return
    st.seen_exec.add(key)
    _add(st, out.subprocesses, key, SubprocessCall(step=out.step, argv=argv))


def _on_connect(st: _State, args: list[str]) -> None:
    out = st.out
    if len(args) < 2:
        return
    sa = args[1]
    fam_m = _FAMILY.search(sa)
    fam = fam_m.group(1) if fam_m else ""
    port: int | None = None
    if fam in ("AF_INET", "AF_INET6"):
        m = _INET.search(sa) if fam == "AF_INET" else _INET6.search(sa)
        address = m.group(1) if m else ""
        pm = _PORT.search(sa)
        port = int(pm.group(1)) if pm and int(pm.group(1)) <= 65535 else None
    elif fam == "AF_UNIX":
        m = _SUN.search(sa)
        address = (decode_string(sa[m.end() :], MAX_ADDRESS, out) or "") if m else ""
        if address in NSCD_SOCKETS:
            return
    else:
        fam = "other"
        address = ""
    address = _clean(address, MAX_ADDRESS, out)
    _add(
        st,
        out.connects,
        ("n", fam, address, port),
        ConnectAttempt(step=out.step, family=fam, address=address, port=port),
    )


def _handle(st: _State, pid: int, body: str) -> None:
    ms = _SYSCALL.match(body)
    if ms is None:
        st.out.garbage_lines += 1
        return
    if st.out.root_pid is None:
        st.out.root_pid = pid
    name = ms.group(1)
    if name not in ("open", "openat", "openat2", "creat", "execve", "execveat", "connect"):
        return
    args, rest = split_args(body, ms.end())
    rm = _RET.match(rest) if rest is not None else None
    ok = rm is not None and not rm.group(1).startswith("-")
    if name == "connect":
        _on_connect(st, args)
    elif name.startswith("exec"):
        _on_exec(st, pid, name, args, ok)
    else:
        _on_open(st, name, args)


def parse_strace(
    text: str,
    step: Step,
    *,
    credential_paths: Iterable[str],
    allowed_write_prefixes: Iterable[str] = ALLOWED_WRITE_PREFIXES,
) -> ParsedStep:
    """Parse ``strace -f -o FILE`` output for one step. Never raises on any input text."""
    out = ParsedStep(step=step)
    if len(text) > MAX_INPUT_BYTES:
        text = text[:MAX_INPUT_BYTES]
        out.truncated = out.input_truncated = True
    st = _State(
        out=out,
        creds=frozenset(posixpath.normpath(p) for p in credential_paths),
        allowed=tuple(allowed_write_prefixes),
    )
    pending: dict[int, str] = {}  # pid -> text of an <unfinished ...> call
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if not line:
            continue
        if len(line) > MAX_LINE:
            line = line[:MAX_LINE]
            out.truncated = True
        m = _PID.match(line)
        pid = int(m.group(1)) if m else 0
        body = line[m.end() :] if m else line
        if body.startswith("--- "):  # signal delivery
            continue
        if body.startswith("+++ "):
            em = _EXITED.match(body)
            if em and pid == out.root_pid:
                out.root_exit_code = int(em.group(1))
            continue
        rm = _RESUMED.match(body)
        if rm:
            prefix = pending.pop(pid, None)
            if prefix is None:
                out.garbage_lines += 1
                continue
            body = prefix + body[rm.end() :]
        if body.endswith(_UNFINISHED):
            pending[pid] = body[: -len(_UNFINISHED)][:MAX_LINE]
            continue
        _handle(st, pid, body)
    # A call still unfinished at the end (killed mid-syscall) is still an attempt.
    for pid, body in pending.items():
        _handle(st, pid, body)
    return out
