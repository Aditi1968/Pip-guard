"""Run a target wheel in the hardened, network-less container and trace it (FR-4).

Host side only builds a tar, runs the ``docker`` CLI with list arguments, and parses
text. No package code ever runs here. Everything the container sends back is untrusted:
stdout is read with a byte cap, the envelope is validated with a strict pydantic model,
and the trace goes through the defensive parser in trace.py.

Every failure mode returns a ``BehaviorTrace`` with an ``incomplete``/``skipped`` state
(fail closed); only programmer errors raise.
"""

from __future__ import annotations

import base64
import binascii
import io
import json
import logging
import os
import re
import subprocess
import tarfile
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from pipguard.errors import SandboxError
from pipguard.models import (
    BehaviorTrace,
    Completeness,
    Config,
    FetchedPackage,
    StepResult,
)
from pipguard.trace import MAX_INPUT_BYTES, ParsedStep, parse_strace

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
SECCOMP_PROFILE = REPO_ROOT / "sandbox" / "seccomp-default.json"
CREDENTIAL_MANIFEST = REPO_ROOT / "sandbox" / "manifest.json"
FIXTURES_ROOT = REPO_ROOT / "tests" / "fixtures"
DEFAULT_IMAGE = "pipguard-sandbox:local"
RUNNER = "/opt/pipguard/runner.py"
MAX_STDOUT = 12 * 1024 * 1024  # envelope holds <= 5 MB of trace as base64 plus a little JSON
MAX_STDERR = 64 * 1024
DOCKER_CALL_TIMEOUT_S = 30  # inspect / kill / rm: Docker Desktop can hang
_MARKER = re.compile(rb"PIPGUARD-ENVELOPE-V1 (\d{1,9})\n")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_EXC_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,63}")

_Module = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")]


def docker_run_argv(name: str, image: str, install_s: int, import_s: int) -> list[str]:
    """The exact FR-4.7 command. Fixed flags; nothing here may be relaxed (CLAUDE.md)."""
    return [
        "docker", "run", "--rm", "-i", "--name", name,
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=256m,mode=1777",  # noqa: S108 - container path
        "--tmpfs", "/sandbox/site-packages:rw,size=512m,mode=1777",
        "--tmpfs", "/sandbox/deps:rw,size=512m,mode=1777",
        "--tmpfs", "/home/sandbox/.cache:rw,size=256m,mode=1777",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        # Passed explicitly: some daemons (Docker Desktop) report seccomp=unconfined.
        "--security-opt", f"seccomp={SECCOMP_PROFILE}",
        "--memory", "1g", "--memory-swap", "1g",
        "--pids-limit", "256",
        "--user", "10001:10001",
        image,
        "python", "-I", RUNNER, str(install_s), str(import_s),
    ]  # fmt: skip


# ---------------------------------------------------------------- docker CLI wrapper


@dataclass(frozen=True)
class DockerResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_overflow: bool = False


class Docker(Protocol):
    def run(self, argv: list[str], *, input: bytes | None, timeout: float) -> DockerResult: ...


def _pump(stream: io.BufferedReader, buf: bytearray, cap: int, over: list[bool]) -> None:
    while chunk := stream.read(65536):
        room = cap - len(buf)
        if len(chunk) > room:
            over[0] = True
        buf.extend(chunk[: max(room, 0)])


class DockerRunner:
    """``subprocess`` wrapper with a byte cap on stdout. Tests inject a fake instead."""

    def run(self, argv: list[str], *, input: bytes | None, timeout: float) -> DockerResult:
        # MSYS_NO_PATHCONV: Git Bash on Windows would rewrite /tmp-style arguments.
        env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        out, err, over = bytearray(), bytearray(), [False]
        assert proc.stdout is not None and proc.stderr is not None
        threads = [
            threading.Thread(target=_pump, args=(proc.stdout, out, MAX_STDOUT, over)),
            threading.Thread(target=_pump, args=(proc.stderr, err, MAX_STDERR, [False])),
        ]
        if input is not None:
            threads.append(threading.Thread(target=_feed, args=(proc.stdin, input)))
        for t in threads:
            t.daemon = True
            t.start()
        try:
            rc = proc.wait(timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise
        for t in threads:
            t.join(10)
        return DockerResult(rc, bytes(out), bytes(err), over[0])


def _feed(stdin: io.BufferedWriter, data: bytes) -> None:
    try:
        stdin.write(data)
        stdin.close()
    except OSError:  # container exited early; its result says why
        pass


def image_digest(image: str, docker: Docker | None = None) -> str:
    """Image ID (``sha256:...``) recorded in the trace and the cache key."""
    try:
        res = (docker or DockerRunner()).run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image],
            input=None,
            timeout=DOCKER_CALL_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxError(f"cannot run docker to inspect {image}: {exc}") from exc
    digest = res.stdout.decode(errors="replace").strip()
    if res.returncode != 0 or not _DIGEST.fullmatch(digest):
        raise SandboxError(f"cannot inspect sandbox image {image}")
    return digest


# ---------------------------------------------------------------- policy (FR-4.10)


def _inside(path: str, root: Path) -> bool:
    return Path(path).resolve().is_relative_to(root.resolve())


def policy_allows(
    pkg: FetchedPackage, *, pr_candidate: bool, fixtures_root: Path = FIXTURES_ROOT
) -> tuple[bool, str]:
    """FR-4.10: execute only our own fixtures and packages a PR actually proposes.

    - ``origin == "pypi"``: allowed only when the caller marks it as a PR candidate.
    - ``origin == "fixture"``: allowed only when every artifact file (target, sdist,
      dependency wheels) resolves inside ``fixtures_root``. ``origin`` is set by our own
      code, so this ties "fixture" to files we control rather than to a label.
    - ``origin == "local_artifact"``: only when the caller marks it as a PR candidate, i.e.
      a wheel the PR itself ships (the demo's ``--local-index``). ``pipguard scan
      --artifact`` and the evaluation batch runner never set that flag, so arbitrary local
      files and the archived malware corpus are never executed.
    """
    if pkg.origin == "pypi":
        return (True, "PR candidate") if pr_candidate else (False, "not proposed by a PR")
    if pkg.origin == "fixture":
        files = [a.path for a in (*pkg.artifacts, *pkg.declared_deps)]
        if files and all(_inside(p, fixtures_root) for p in files):
            return True, "pip guard fixture"
        return False, "fixture artifact outside the fixtures directory"
    if pkg.origin == "local_artifact" and pr_candidate:
        return True, "wheel proposed by the PR"
    return False, "local artifacts are analysed statically only"


# ---------------------------------------------------------------- envelope


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _EnvStep(_Strict):
    step: Literal["install", "import"]
    exit_code: int | None
    wall_time_s: float = Field(ge=0, le=86400)
    timed_out: bool
    trace_b64: str = Field(max_length=MAX_STDOUT)
    trace_truncated: bool


class _Envelope(_Strict):
    version: Literal[1]
    error: str | None = Field(default=None, max_length=200)
    steps: list[_EnvStep] = Field(max_length=2)
    modules: list[_Module] = Field(max_length=50)
    results: dict[_Module, Annotated[str, Field(max_length=200)]] = Field(max_length=50)


def _parse_envelope(stdout: bytes) -> _Envelope | None:
    m = _MARKER.match(stdout)
    if m is None:
        return None
    body = stdout[m.end() : m.end() + int(m.group(1))]
    try:
        return _Envelope.model_validate(json.loads(body))
    except (ValueError, ValidationError):
        return None


def _tar(pkg: FetchedPackage, wheel_path: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(wheel_path, arcname=f"target/{Path(wheel_path).name}")
        for dep in pkg.declared_deps:
            if dep.kind == "wheel":
                tf.add(dep.path, arcname=f"deps/{Path(dep.path).name}")
    return buf.getvalue()


def _credential_paths() -> list[str]:
    return list(json.loads(CREDENTIAL_MANIFEST.read_text(encoding="utf-8"))["files"])


# ---------------------------------------------------------------- run


def _verdict_state(env: _Envelope, truncated: bool) -> tuple[Completeness, str]:
    """Fail closed: COMPLETE only when every step ran to the end and was fully parsed."""
    if env.error:
        return Completeness.SANDBOX_ERROR, env.error
    if any(s.timed_out for s in env.steps):
        step = next(s.step for s in env.steps if s.timed_out)
        return Completeness.TIMEOUT, f"{step} step timed out"
    if truncated:
        return Completeness.TRACE_TRUNCATED, "trace exceeded the 5 MB cap"
    install = next((s for s in env.steps if s.step == "install"), None)
    if install is None or install.exit_code != 0:
        code = None if install is None else install.exit_code
        return Completeness.SANDBOX_ERROR, f"target install failed (exit {code})"
    if not env.modules:
        return Completeness.NO_IMPORTABLE_MODULE, "no importable top-level module"
    imp = next((s for s in env.steps if s.step == "import"), None)
    failed = [m for m in env.modules if env.results.get(m) != "ok"]
    if imp is None or imp.exit_code != 0 or failed:
        detail = ", ".join(
            f"{m} ({r if _EXC_NAME.fullmatch(r := env.results.get(m, 'no result')) else 'error'})"
            for m in failed[:5]
        )
        return Completeness.IMPORT_FAILED, f"import failed: {detail or 'interpreter exited'}"
    return Completeness.COMPLETE, ""


def run(
    pkg: FetchedPackage,
    *,
    config: Config,
    image: str = DEFAULT_IMAGE,
    pr_candidate: bool = False,
    fixtures_root: Path = FIXTURES_ROOT,
    docker: Docker | None = None,
) -> BehaviorTrace:
    """Install and import ``pkg``'s wheel in the sandbox and return what strace saw."""
    docker = docker or DockerRunner()
    wheel = pkg.wheel

    def result(state: Completeness, reason: str, **kw: object) -> BehaviorTrace:
        return BehaviorTrace(
            spec=pkg.spec,
            artifact_sha256=wheel.sha256 if wheel else None,
            completeness=state,
            completeness_reason=reason,
            **kw,  # type: ignore[arg-type]
        )

    allowed, why = policy_allows(pkg, pr_candidate=pr_candidate, fixtures_root=fixtures_root)
    if not allowed:
        return result(Completeness.SKIPPED_POLICY, why)
    if wheel is None:
        return result(Completeness.NO_WHEEL, "no wheel for the sandbox platform")
    try:
        digest = image_digest(image, docker)
    except SandboxError as exc:
        return result(Completeness.SANDBOX_ERROR, f"sandbox image unavailable: {exc}")

    t = config.timeouts
    name = f"pipguard-{uuid.uuid4().hex}"
    argv = docker_run_argv(name, image, t.install_s, t.import_s)
    # Backstop only: the runner enforces per-step timeouts itself and still reports.
    # Budget: dependency preinstall (install_s) + traced install + import + slack.
    outer = 2 * t.install_s + t.import_s + 30
    try:
        res = docker.run(argv, input=_tar(pkg, wheel.path), timeout=outer)
    except subprocess.TimeoutExpired:
        _quiet(docker, ["docker", "kill", name])
        return result(
            Completeness.TIMEOUT, "sandbox exceeded its overall time limit", image_digest=digest
        )
    except OSError as exc:
        return result(
            Completeness.SANDBOX_ERROR, f"cannot start docker: {exc}", image_digest=digest
        )
    finally:
        _quiet(docker, ["docker", "rm", "-f", name])  # destroyed after every run

    if res.stdout_overflow:
        return result(
            Completeness.TRACE_TRUNCATED, "sandbox output exceeded its cap",
            image_digest=digest, truncated=True,
        )  # fmt: skip
    env = _parse_envelope(res.stdout)
    if env is None:
        first = res.stderr.decode(errors="replace").strip().splitlines()[:1]
        why = f"no valid result from the sandbox (exit {res.returncode})"
        log.warning("%s: %s", why, first[0][:200] if first else "")
        return result(Completeness.SANDBOX_ERROR, why, image_digest=digest)

    parsed: list[ParsedStep] = []
    budget = MAX_INPUT_BYTES
    truncated = False
    creds = _credential_paths()
    for s in env.steps:
        try:
            raw = base64.b64decode(s.trace_b64, validate=True)
        except (binascii.Error, ValueError):
            return result(Completeness.SANDBOX_ERROR, "garbled trace", image_digest=digest)
        if len(raw) > budget or s.trace_truncated:
            truncated = True
        raw, budget = raw[:budget], max(0, budget - len(raw))
        p = parse_strace(raw.decode("utf-8", "replace"), s.step, credential_paths=creds)
        if p.garbage_lines:
            log.info("%s trace: %d unparsed line(s)", s.step, p.garbage_lines)
        truncated = truncated or p.input_truncated
        parsed.append(p)

    state, reason = _verdict_state(env, truncated)
    return result(
        state,
        reason,
        image_digest=digest,
        steps=[
            StepResult(
                step=s.step, exit_code=s.exit_code, wall_time_s=s.wall_time_s, timed_out=s.timed_out
            )
            for s in env.steps
        ],
        imported_modules=[m for m in env.modules if env.results.get(m) == "ok"],
        writes_outside_allowed=[w for p in parsed for w in p.writes],
        credential_reads=[c for p in parsed for c in p.credential_reads],
        subprocesses=[x for p in parsed for x in p.subprocesses],
        connects=[c for p in parsed for c in p.connects],
        truncated=truncated or any(p.truncated for p in parsed),
    )


def _quiet(docker: Docker, argv: list[str]) -> None:
    try:
        docker.run(argv, input=None, timeout=DOCKER_CALL_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("%s failed: %s", " ".join(argv[:2]), exc)
