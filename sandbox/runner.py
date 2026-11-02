"""In-container runner (FR-4.1, FR-4.2, FR-4.6). Runs as PID 1 inside the sandbox.

    python -I /opt/pipguard/runner.py INSTALL_TIMEOUT_S IMPORT_TIMEOUT_S  < input.tar

Input tar: ``target/<one wheel>`` and ``deps/*.whl``. Interpreters run with ``-I -B``:
isolated (no PYTHON* env, no cwd on sys.path) and no .pyc writes (-I ignores
PYTHONDONTWRITEBYTECODE; stdlib .pyc writes would otherwise show up as write attempts on
the read-only root). Steps:
  1. untar into /tmp/in;
  2. untraced: pip install the dependency wheels into /sandbox/deps;
  3. traced: pip install --no-deps the target into /sandbox/site-packages;
  4. traced: one interpreter adds /sandbox/deps to sys.path (no .pth processing, so
     dependency start-up hooks never run in the traced step), then
     site.addsitedir('/sandbox/site-packages') (target .pth files run, as in a real
     environment), then imports each top-level module of the target.
Output: exactly one envelope on stdout, ``PIPGUARD-ENVELOPE-V1 <len>\\n<json>\\n``.

Trace transport: strace writes to ``-o /dev/stderr``, a pipe this runner reads, not to a
file in /tmp the package could rewrite. The traced programs move their own fds 1/2 to
log files before any package code runs, so package output cannot enter the trace pipe
or this runner's stdout. This runner also makes itself non-dumpable, so a same-uid
package cannot open /proc/1/fd/1 to forge the envelope.

Only stdlib; this file is our code, never package code.
"""

# pyright: reportAttributeAccessIssue=false
# (Linux-only module: os.killpg/SIGKILL are absent from the Windows stubs.)
from __future__ import annotations

import base64
import contextlib
import ctypes
import io
import json
import os
import signal
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path

IN = Path("/tmp/in")  # noqa: S108 - container path
SITE = "/sandbox/site-packages"
DEPS = "/sandbox/deps"
RESULTS = "/tmp/import_results.json"  # noqa: S108
TRACE_CAP = 5 * 1024 * 1024  # per package, both steps together
MAX_MODULES = 50
MARKER = b"PIPGUARD-ENVELOPE-V1"
STRACE = ["strace", "-f", "-qq", "-s", "256", "-e", "trace=network,process,file"]

# Both traced programs first move fds 1/2 to a log file (see module docstring).
_REDIRECT = (
    "import os,sys\n"
    "fd=os.open('/tmp/{log}',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)\n"
    "os.dup2(fd,1);os.dup2(fd,2);os.close(fd)\n"
)
# pip builds a user-agent even with --no-index, and its vendored `distro` probes the OS
# by spawning `lsb_release -a` and `uname -rs`. That is pip's plumbing, not the package,
# and it would put two subprocesses into every install trace; switch the probe off.
PIP_PROGRAM = _REDIRECT.format(log="pip.log") + (
    "try:\n"
    "    from pip._vendor.distro import distro as d\n"
    "    d._distro=d.LinuxDistribution(include_lsb=False,include_uname=False)\n"
    "except Exception:\n"
    "    pass\n"
    "import runpy\nsys.argv=['pip',*sys.argv[1:]]\n"
    "runpy.run_module('pip',run_name='__main__',alter_sys=True)\n"
)
IMPORT_PROGRAM = _REDIRECT.format(log="import.log") + (
    "import importlib,json,site\n"
    f"sys.path.append({DEPS!r})\n"
    f"site.addsitedir({SITE!r})\n"
    "res={}\n"
    "for m in sys.argv[1:]:\n"
    "    try:\n"
    "        mod=importlib.import_module(m)\n"
    # The module must come from the target's install dir: a name that resolves to the
    # stdlib or a dependency means the target's own code never ran (fail closed).
    "        locs=[getattr(mod,'__file__',None) or '',*getattr(mod,'__path__',[])]\n"
    f"        ok=any(os.path.realpath(p).startswith({SITE + '/'!r}) for p in locs if p)\n"
    "        res[m]='ok' if ok else 'NotFromTarget'\n"
    "    except BaseException as e:\n"
    "        res[m]=type(e).__name__[:64]\n"
    f"with open({RESULTS!r},'w') as f:json.dump(res,f)\n"
)


def _no_dump() -> None:
    with contextlib.suppress(OSError, AttributeError):
        ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 0


def _drain(pipe: io.BufferedReader, buf: bytearray, cap: int, flags: dict[str, bool]) -> None:
    while chunk := pipe.read(65536):
        room = cap - len(buf)
        if len(chunk) > room:
            flags["truncated"] = True
        buf.extend(chunk[: max(room, 0)])


def traced(step: str, argv: list[str], timeout: int, budget: list[int]) -> dict:
    """Run ``argv`` under strace; return the step record with its base64 trace."""
    buf = bytearray()
    flags = {"truncated": False}
    start = time.monotonic()
    proc = subprocess.Popen(
        [*STRACE, "-o", "/dev/stderr", *argv],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert proc.stderr is not None
    reader = threading.Thread(target=_drain, args=(proc.stderr, buf, budget[0], flags))
    reader.start()
    timed_out = False
    try:
        code: int | None = proc.wait(timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        # TERM first so strace can flush what it has, then KILL the whole group.
        for sig, grace in ((signal.SIGTERM, 2), (signal.SIGKILL, 5)):
            try:
                os.killpg(proc.pid, sig)
                proc.wait(grace)
                break
            except (subprocess.TimeoutExpired, ProcessLookupError):
                continue
        code = None
    reader.join(5)
    budget[0] -= len(buf)
    return {
        "step": step,
        "exit_code": code,
        "wall_time_s": round(time.monotonic() - start, 3),
        "timed_out": timed_out,
        "trace_b64": base64.b64encode(bytes(buf)).decode(),
        "trace_truncated": flags["truncated"],
    }


def modules() -> list[str]:
    """Top-level modules actually installed under SITE, read from the filesystem.

    Not from the package's own top_level.txt / RECORD: a malicious wheel could list `json`
    there, the runner would import the stdlib module, and an unexecuted package would look
    "complete". Package dirs (with any .py inside, so namespace packages count) and top-level
    .py files are importable; metadata, scripts and caches are not.
    """
    site = Path(SITE)
    names: list[str] = []
    for entry in sorted(site.iterdir()) if site.is_dir() else []:
        if entry.is_symlink():
            continue
        if entry.is_file() and entry.suffix == ".py":
            names.append(entry.stem)
        elif (
            entry.is_dir()
            and not entry.name.endswith((".dist-info", ".data", ".egg-info"))
            and entry.name not in ("__pycache__", "bin")
            and any(entry.rglob("*.py"))
        ):
            names.append(entry.name)
    return list(dict.fromkeys(n for n in names if n.isidentifier()))[:MAX_MODULES]


def main() -> None:
    install_s, import_s = int(sys.argv[1]), int(sys.argv[2])
    _no_dump()
    env: dict = {"version": 1, "error": None, "steps": [], "modules": [], "results": {}}
    budget = [TRACE_CAP]
    try:
        IN.mkdir(parents=True)
        with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as tf:
            tf.extractall(IN, filter="data")
        targets = sorted((IN / "target").glob("*.whl"))
        deps = sorted((IN / "deps").glob("*.whl"))
        if len(targets) != 1:
            raise ValueError("expected exactly one target wheel")
        if deps:
            # --no-deps: the host already resolved the closure; a missing dependency
            # then fails the traced import, which is reported as import_failed.
            pre = subprocess.run(
                [sys.executable, "-I", "-B", "-m", "pip", "install", "--no-deps", "--no-index",
                 "--find-links", str(IN / "deps"), "--target", DEPS, *map(str, deps)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=install_s, check=False,
            )  # fmt: skip
            if pre.returncode:
                env["error"] = "dependency preinstall failed"
                return
        pip = [sys.executable, "-I", "-B", "-c", PIP_PROGRAM, "install", "--no-deps", "--no-index",
               "--target", SITE, str(targets[0])]  # fmt: skip
        env["steps"].append(traced("install", pip, install_s, budget))
        if env["steps"][-1]["exit_code"] != 0:
            return
        env["modules"] = mods = modules()
        if not mods:
            return
        imp = [sys.executable, "-I", "-B", "-c", IMPORT_PROGRAM, *mods]
        env["steps"].append(traced("import", imp, import_s, budget))
        try:
            env["results"] = json.loads(Path(RESULTS).read_text()[:65536])
        except (OSError, ValueError):
            env["results"] = {}
    except subprocess.TimeoutExpired:
        env["error"] = "dependency preinstall timed out"
    except Exception as exc:  # report, never crash without an envelope
        env["error"] = f"runner error: {type(exc).__name__}"
    finally:
        data = json.dumps(env).encode()
        sys.stdout.buffer.write(MARKER + b" %d\n" % len(data) + data + b"\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
