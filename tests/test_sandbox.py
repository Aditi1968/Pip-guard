"""sandbox.py with a fake Docker: flags, policy, fail-closed states, cleanup. No daemon."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from pipguard import sandbox
from pipguard.errors import SandboxError
from pipguard.models import (
    Artifact,
    Completeness,
    Config,
    FetchedPackage,
    PackageMetadata,
    PackageSpec,
    Timeouts,
)
from pipguard.sandbox import DockerResult, DockerRunner, docker_run_argv, policy_allows
from sandbox import runner

DIGEST = "sha256:" + "ab" * 32
ROOT_EXEC = '1 execve("/usr/local/bin/python", ["python", "-I"], 0x1 /* 3 vars */) = 0\n'
IMPORT_TRACE = ROOT_EXEC + (
    '1 openat(AT_FDCWD, "/home/sandbox/.aws/credentials", O_RDONLY|O_CLOEXEC) = 3\n'
    "1 connect(3, {sa_family=AF_INET, sin_port=htons(443), "
    'sin_addr=inet_addr("203.0.113.10")}, 16) = -1 ENETUNREACH (x)\n'
)


def _artifact(path: Path, kind: str = "wheel") -> Artifact:
    data = path.read_bytes()
    return Artifact(
        filename=path.name,
        kind=kind,  # type: ignore[arg-type]
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        path=str(path),
    )


def _pkg(tmp: Path, origin: str = "fixture", wheel: bool = True, deps: int = 0) -> FetchedPackage:
    arts = []
    if wheel:
        (tmp / "t-1.0-py3-none-any.whl").write_bytes(b"wheel")
        arts.append(_artifact(tmp / "t-1.0-py3-none-any.whl"))
    else:
        (tmp / "t-1.0.tar.gz").write_bytes(b"sdist")
        arts.append(_artifact(tmp / "t-1.0.tar.gz", "sdist"))
    dep_arts = []
    for i in range(deps):
        p = tmp / f"d{i}-1.0-py3-none-any.whl"
        p.write_bytes(b"dep")
        dep_arts.append(_artifact(p))
    return FetchedPackage(
        spec=PackageSpec(name="t", version="1.0"),
        artifacts=arts,
        metadata=PackageMetadata(),
        declared_deps=dep_arts,
        origin=origin,  # type: ignore[arg-type]
    )


def _step(step: str, trace: str = ROOT_EXEC, **kw: object) -> dict[str, object]:
    return {
        "step": step,
        "exit_code": 0,
        "wall_time_s": 1.0,
        "timed_out": False,
        "trace_b64": base64.b64encode(trace.encode()).decode(),
        "trace_truncated": False,
    } | kw


def _envelope(**kw: object) -> bytes:
    env: dict[str, object] = {
        "version": 1,
        "error": None,
        "steps": [_step("install"), _step("import", IMPORT_TRACE)],
        "modules": ["t"],
        "results": {"t": "ok"},
    } | kw
    body = json.dumps(env).encode()
    return b"PIPGUARD-ENVELOPE-V1 %d\n" % len(body) + body + b"\n"


class FakeDocker:
    def __init__(self, run_result: DockerResult | BaseException | None = None) -> None:
        self.calls: list[list[str]] = []
        self.inputs: list[bytes | None] = []
        self.timeouts: list[float] = []
        self.run_result = run_result or DockerResult(0, _envelope(), b"")
        self.inspect = DockerResult(0, DIGEST.encode() + b"\n", b"")

    def run(self, argv: list[str], *, input: bytes | None, timeout: float) -> DockerResult:
        self.calls.append(argv)
        self.inputs.append(input)
        self.timeouts.append(timeout)
        if argv[1] == "image":
            return self.inspect
        if argv[1] == "run":
            if isinstance(self.run_result, BaseException):
                raise self.run_result
            return self.run_result
        return DockerResult(0, b"", b"")

    def verbs(self) -> list[str]:
        return [c[1] for c in self.calls]


def _run(tmp: Path, docker: FakeDocker, **kw: object):  # type: ignore[no-untyped-def]
    pkg = kw.pop("pkg", None) or _pkg(tmp)
    return sandbox.run(
        pkg,  # type: ignore[arg-type]
        config=Config(timeouts=Timeouts(install_s=90, import_s=60)),
        fixtures_root=tmp,
        docker=docker,
        **kw,  # type: ignore[arg-type]
    )


# ------------------------------------------------------------------ argv (FR-4.7)


def test_docker_argv_has_every_hardening_flag_and_nothing_forbidden() -> None:
    argv = docker_run_argv("pipguard-x", "img:1", 90, 60)
    joined = " ".join(argv)
    for flag in [
        "--rm",
        "-i",
        "--network none",
        "--read-only",
        "--tmpfs /tmp:rw,size=256m,mode=1777",
        "--tmpfs /sandbox/site-packages:rw,size=512m,mode=1777",
        "--tmpfs /sandbox/deps:rw,size=512m,mode=1777",
        "--tmpfs /home/sandbox/.cache:rw,size=256m,mode=1777",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        f"--security-opt seccomp={sandbox.SECCOMP_PROFILE}",
        "--memory 1g",
        "--pids-limit 256",
        "--user 10001:10001",
        "--name pipguard-x",
    ]:
        assert flag in joined, flag
    assert sandbox.SECCOMP_PROFILE.is_file()
    for bad in ["--privileged", "--cap-add", "unconfined", "--mount", "docker.sock", "-e", "-v"]:
        assert bad not in argv, bad
    assert "unconfined" not in joined and "docker.sock" not in joined
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--network"] == ["none"]
    assert not any(a.startswith(("--network=", "--volume", "--env", "-v=")) for a in argv)
    assert ",exec" not in joined
    assert argv[argv.index("img:1") :] == ["img:1", "python", "-I", sandbox.RUNNER, "90", "60"]


# ------------------------------------------------------------------ policy (FR-4.10)


def test_policy(tmp_path: Path) -> None:
    inside = _pkg(tmp_path)
    assert policy_allows(inside, pr_candidate=False, fixtures_root=tmp_path)[0]
    other = tmp_path / "elsewhere"
    other.mkdir()
    assert not policy_allows(inside, pr_candidate=False, fixtures_root=other)[0]
    # default root is the repo's tests/fixtures; tmp_path is outside it
    assert not policy_allows(inside, pr_candidate=True)[0]
    pypi = inside.model_copy(update={"origin": "pypi"})
    assert policy_allows(pypi, pr_candidate=True, fixtures_root=tmp_path) == (True, "PR candidate")
    assert not policy_allows(pypi, pr_candidate=False, fixtures_root=tmp_path)[0]
    local = inside.model_copy(update={"origin": "local_artifact"})
    assert not policy_allows(local, pr_candidate=False, fixtures_root=tmp_path)[0]
    assert policy_allows(local, pr_candidate=True, fixtures_root=tmp_path)[0]


def test_fixture_policy_checks_dependency_paths_too(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    pkg = _pkg(root)
    outside = tmp_path / "evil-1.0-py3-none-any.whl"
    outside.write_bytes(b"x")
    pkg = pkg.model_copy(update={"declared_deps": [_artifact(outside)]})
    assert not policy_allows(pkg, pr_candidate=False, fixtures_root=root)[0]


def test_policy_denial_starts_no_container(tmp_path: Path) -> None:
    d = FakeDocker()
    t = _run(tmp_path, d, pkg=_pkg(tmp_path, origin="local_artifact"), pr_candidate=False)
    assert t.completeness is Completeness.SKIPPED_POLICY
    assert d.calls == []


def test_no_wheel_starts_no_container(tmp_path: Path) -> None:
    d = FakeDocker()
    t = _run(tmp_path, d, pkg=_pkg(tmp_path, wheel=False))
    assert t.completeness is Completeness.NO_WHEEL
    assert d.calls == []


# ------------------------------------------------------------------ happy path


def test_complete_run_merges_steps_and_records_digest(tmp_path: Path) -> None:
    d = FakeDocker()
    t = _run(tmp_path, d, pkg=_pkg(tmp_path, deps=2))
    assert t.completeness is Completeness.COMPLETE
    assert t.image_digest == DIGEST
    assert t.imported_modules == ["t"]
    assert [c.path for c in t.credential_reads] == ["/home/sandbox/.aws/credentials"]
    assert [(c.step, c.address, c.port) for c in t.connects] == [("import", "203.0.113.10", 443)]
    assert [s.step for s in t.steps] == ["install", "import"]
    assert t.artifact_sha256 == hashlib.sha256(b"wheel").hexdigest()
    assert d.verbs() == ["image", "run", "rm"]
    run_argv = d.calls[1]
    name = run_argv[run_argv.index("--name") + 1]
    assert d.calls[2] == ["docker", "rm", "-f", name]
    assert d.timeouts[1] == 2 * 90 + 60 + 30
    with tarfile.open(fileobj=io.BytesIO(d.inputs[1] or b"")) as tf:
        assert sorted(tf.getnames()) == [
            "deps/d0-1.0-py3-none-any.whl",
            "deps/d1-1.0-py3-none-any.whl",
            "target/t-1.0-py3-none-any.whl",
        ]


def test_each_run_uses_a_fresh_container_name(tmp_path: Path) -> None:
    d = FakeDocker()
    _run(tmp_path, d)
    _run(tmp_path, d)
    names = [c[c.index("--name") + 1] for c in d.calls if c[1] == "run"]
    assert len(set(names)) == 2 and all(n.startswith("pipguard-") for n in names)


# ------------------------------------------------------------------ fail closed


@pytest.mark.parametrize(
    ("envelope", "state"),
    [
        ({"error": "dependency preinstall failed", "steps": []}, Completeness.SANDBOX_ERROR),
        (
            {"steps": [_step("install"), _step("import", exit_code=None, timed_out=True)]},
            Completeness.TIMEOUT,
        ),
        ({"steps": [_step("install", exit_code=1)], "modules": []}, Completeness.SANDBOX_ERROR),
        ({"steps": [_step("install")], "modules": []}, Completeness.NO_IMPORTABLE_MODULE),
        ({"results": {"t": "RuntimeError"}}, Completeness.IMPORT_FAILED),
        ({"results": {}}, Completeness.IMPORT_FAILED),
        ({"steps": [_step("install"), _step("import", exit_code=1)]}, Completeness.IMPORT_FAILED),
        (
            {"steps": [_step("install"), _step("import", trace_truncated=True)]},
            Completeness.TRACE_TRUNCATED,
        ),
    ],
)
def test_incomplete_states(
    tmp_path: Path, envelope: dict[str, object], state: Completeness
) -> None:
    t = _run(tmp_path, FakeDocker(DockerResult(0, _envelope(**envelope), b"")))
    assert t.completeness is state
    assert t.completeness_reason


def test_import_failure_keeps_observations_and_sanitises_exception_name(tmp_path: Path) -> None:
    env = _envelope(results={"t": "Bad <b>name</b>"})
    t = _run(tmp_path, FakeDocker(DockerResult(0, env, b"")))
    assert t.completeness is Completeness.IMPORT_FAILED
    assert "t (error)" in t.completeness_reason
    assert t.connects and t.credential_reads


def test_trace_over_package_cap_is_truncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sandbox, "MAX_INPUT_BYTES", len(ROOT_EXEC) + 10)
    t = _run(tmp_path, FakeDocker())
    assert t.completeness is Completeness.TRACE_TRUNCATED
    assert t.truncated


def test_timeout_kills_and_removes(tmp_path: Path) -> None:
    d = FakeDocker(subprocess.TimeoutExpired("docker", 1))
    t = _run(tmp_path, d)
    assert t.completeness is Completeness.TIMEOUT
    assert d.verbs() == ["image", "run", "kill", "rm"]
    assert d.calls[2][2] == d.calls[3][3]  # same container name


def test_docker_cli_missing_is_sandbox_error(tmp_path: Path) -> None:
    d = FakeDocker(FileNotFoundError("docker"))
    t = _run(tmp_path, d)
    assert t.completeness is Completeness.SANDBOX_ERROR
    assert d.verbs()[-1] == "rm"


def test_rm_runs_even_on_unexpected_exception(tmp_path: Path) -> None:
    d = FakeDocker(KeyError("bug"))
    with pytest.raises(KeyError):
        _run(tmp_path, d)
    assert d.verbs()[-1] == "rm"


def test_rm_failure_is_logged_not_raised(tmp_path: Path) -> None:
    class RmTimesOut(FakeDocker):
        def run(self, argv: list[str], *, input: bytes | None, timeout: float) -> DockerResult:
            if argv[1] == "rm":
                raise subprocess.TimeoutExpired("docker", timeout)
            return super().run(argv, input=input, timeout=timeout)

    assert _run(tmp_path, RmTimesOut()).completeness is Completeness.COMPLETE


def test_missing_image_is_sandbox_error(tmp_path: Path) -> None:
    d = FakeDocker()
    d.inspect = DockerResult(1, b"", b"No such image")
    t = _run(tmp_path, d)
    assert t.completeness is Completeness.SANDBOX_ERROR
    assert d.verbs() == ["image"]


@pytest.mark.parametrize(
    "stdout",
    [
        b"",
        b"hello",
        b"PIPGUARD-ENVELOPE-V1 5\n{oops",
        b"PIPGUARD-ENVELOPE-V1 2\n{}",
        _envelope(version=2),
        _envelope(modules=["../evil"]),
        _envelope(steps=[_step("install", trace_b64="!!!not base64")]),
        b"junk" + _envelope(),
    ],
)
def test_garbled_envelope_is_sandbox_error(tmp_path: Path, stdout: bytes) -> None:
    t = _run(tmp_path, FakeDocker(DockerResult(125, stdout, b"docker: Error response\n")))
    assert t.completeness is Completeness.SANDBOX_ERROR


def test_oversize_output_is_trace_truncated(tmp_path: Path) -> None:
    t = _run(tmp_path, FakeDocker(DockerResult(0, _envelope(), b"", stdout_overflow=True)))
    assert t.completeness is Completeness.TRACE_TRUNCATED
    assert t.truncated


def test_image_digest_validates_output() -> None:
    d = FakeDocker()
    assert sandbox.image_digest("img", d) == DIGEST
    d.inspect = DockerResult(0, b"sha256:short\n", b"")
    with pytest.raises(SandboxError):
        sandbox.image_digest("img", d)


# ------------------------------------------------------------------ DockerRunner (real subprocess)


def test_docker_runner_caps_stdout_and_feeds_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox, "MAX_STDOUT", 10)
    code = "import sys; data = sys.stdin.read(); sys.stdout.write(data * 3)"
    res = DockerRunner().run([sys.executable, "-c", code], input=b"abcdef", timeout=30)
    assert res.returncode == 0
    assert res.stdout == b"abcdefabcd" and res.stdout_overflow


def test_docker_runner_timeout_kills() -> None:
    with pytest.raises(subprocess.TimeoutExpired):
        DockerRunner().run(
            [sys.executable, "-c", "import time; time.sleep(30)"], input=None, timeout=0.5
        )


# ------------------------------------------------------------------ in-container runner helpers


def test_runner_programs_compile() -> None:
    compile(runner.PIP_PROGRAM, "<pip>", "exec")
    compile(runner.IMPORT_PROGRAM, "<import>", "exec")
    # attribution: deps go on sys.path without .pth processing; only the target is a site dir
    assert "sys.path.append('/sandbox/deps')" in runner.IMPORT_PROGRAM
    assert "addsitedir('/sandbox/site-packages')" in runner.IMPORT_PROGRAM
    assert "addsitedir('/sandbox/deps')" not in runner.IMPORT_PROGRAM


def test_runner_modules_from_top_level_then_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "SITE", str(tmp_path))
    assert runner.modules() == []
    info = tmp_path / "x-1.0.dist-info"
    info.mkdir()
    (info / "RECORD").write_text(
        "pkg/__init__.py,,\npkg/sub.py,,\nmod.py,,\nx-1.0.dist-info/RECORD,,\n"
        "__pycache__/a.pyc,,\nx-1.0.data/scripts/s,,\nbad-name.py,,\nREADME,,\n"
    )
    assert runner.modules() == ["pkg", "mod"]
    (info / "top_level.txt").write_text("alpha\n../evil\nbeta\nalpha\n")
    assert runner.modules() == ["alpha", "beta"]


def test_runner_drain_caps() -> None:
    buf = bytearray()
    flags = {"truncated": False}
    runner._drain(io.BytesIO(b"x" * 100), buf, 40, flags)  # type: ignore[arg-type]
    assert len(buf) == 40 and flags["truncated"]
