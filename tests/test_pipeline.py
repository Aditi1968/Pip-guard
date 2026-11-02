import hashlib
from collections.abc import Mapping
from pathlib import Path

from pipguard.cache import VerdictCache
from pipguard.errors import FetchError
from pipguard.models import (
    Artifact,
    ArtifactKind,
    BehaviorTrace,
    ChangeKind,
    Completeness,
    Config,
    CredentialRead,
    DependencyChange,
    FetchedPackage,
    Level,
    PackageMetadata,
    PackageSpec,
    StageStatus,
)
from pipguard.pipeline import ScanOptions, scan_artifact, scan_changes, scan_spec
from pipguard.scoring import RULES_ONLY
from scripts.make_wheel import build_wheel

QUIET = {"quietpkg/__init__.py": "VALUE = 1\n"}


def _pkg(wheel: Path, spec: PackageSpec) -> FetchedPackage:
    art = Artifact(
        filename=wheel.name,
        kind=ArtifactKind.WHEEL,
        sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
        python_tag="py3",
        platform_tag="any",
        size=wheel.stat().st_size,
        path=str(wheel),
    )
    return FetchedPackage(spec=spec, artifacts=[art], metadata=PackageMetadata())


def _fetcher(tmp_path: Path, files: Mapping[str, str | bytes] = QUIET):
    def fetcher(spec: PackageSpec, dest: Path) -> FetchedPackage:
        return _pkg(build_wheel(tmp_path / "wheels", spec.name, spec.version, files), spec)

    return fetcher


def _opts(tmp_path: Path, **kw: object) -> ScanOptions:
    kw.setdefault("sandbox", False)
    kw.setdefault("fetcher", _fetcher(tmp_path))
    return ScanOptions(config=Config(), model=RULES_ONLY, **kw)  # type: ignore[arg-type]


SPEC = PackageSpec(name="quietpkg", version="1.0")


def test_static_only_benign_is_allow(tmp_path: Path) -> None:
    r = scan_spec(SPEC, _opts(tmp_path), tmp_path / "w")
    assert r.verdict.level is Level.ALLOW
    c = r.verdict.coverage
    assert (c.fetch, c.static, c.sandbox) == (
        StageStatus.COMPLETED,
        StageStatus.COMPLETED,
        StageStatus.SKIPPED,
    )
    assert r.static is not None and {"extract", "static", "fetch"} <= set(r.timings)


def test_fetch_failure_is_error(tmp_path: Path) -> None:
    def boom(spec: PackageSpec, dest: Path) -> FetchedPackage:
        raise FetchError("PyPI unreachable")

    r = scan_spec(SPEC, _opts(tmp_path, fetcher=boom), tmp_path / "w")
    assert r.verdict.level is Level.ERROR
    assert r.verdict.coverage.fetch is StageStatus.FAILED
    assert "PyPI unreachable" in r.verdict.reasons[0]


def test_corrupt_archive_is_error(tmp_path: Path) -> None:
    def corrupt(spec: PackageSpec, dest: Path) -> FetchedPackage:
        bad = tmp_path / "quietpkg-1.0-py3-none-any.whl"
        bad.write_bytes(b"not a zip")
        return _pkg(bad, spec)

    r = scan_spec(SPEC, _opts(tmp_path, fetcher=corrupt), tmp_path / "w")
    assert r.verdict.level is Level.ERROR and "unsafe archive" in r.verdict.reasons[0]


def _sandbox_returning(trace_kw: dict[str, object]):
    def run(pkg: FetchedPackage, **kw: object) -> BehaviorTrace:
        return BehaviorTrace(spec=pkg.spec, artifact_sha256=pkg.artifacts[0].sha256, **trace_kw)  # type: ignore[arg-type]

    return run


def test_incomplete_sandbox_fails_closed(tmp_path: Path) -> None:
    opts = _opts(
        tmp_path,
        sandbox=True,
        sandbox_run=_sandbox_returning({"completeness": Completeness.TIMEOUT}),
        image_digest=lambda image: "sha256:img",
    )
    r = scan_spec(SPEC, opts, tmp_path / "w")
    assert r.verdict.level is Level.INCOMPLETE and r.trace is not None


def test_sandbox_credential_exfil_blocks(tmp_path: Path) -> None:
    from pipguard.models import SubprocessCall

    opts = _opts(
        tmp_path,
        sandbox=True,
        sandbox_run=_sandbox_returning(
            {
                "completeness": Completeness.COMPLETE,
                "credential_reads": [
                    CredentialRead(step="import", path="/home/sandbox/.aws/credentials")
                ],
                "subprocesses": [SubprocessCall(step="import", argv=["sh", "-c", "curl x"])],
            }
        ),
        image_digest=lambda image: "sha256:img",
    )
    r = scan_spec(SPEC, opts, tmp_path / "w")
    assert r.verdict.level is Level.BLOCK
    assert r.verdict.coverage.sandbox is StageStatus.COMPLETED


def test_unexpected_crash_is_error_not_allow(tmp_path: Path) -> None:
    def crash(pkg: FetchedPackage, **kw: object) -> BehaviorTrace:
        raise RuntimeError("boom")

    opts = _opts(tmp_path, sandbox=True, sandbox_run=crash, image_digest=lambda i: "d")
    r = scan_spec(SPEC, opts, tmp_path / "w")
    assert r.verdict.level is Level.ERROR
    assert "RuntimeError" in r.verdict.reasons[0]


def test_missing_image_is_error(tmp_path: Path) -> None:
    from pipguard.errors import SandboxError

    def no_image(image: str) -> str:
        raise SandboxError("no such image")

    r = scan_spec(SPEC, _opts(tmp_path, sandbox=True, image_digest=no_image), tmp_path / "w")
    assert r.verdict.level is Level.ERROR
    assert r.verdict.coverage.sandbox is StageStatus.FAILED


def test_cache_hit_and_fork_read_only(tmp_path: Path) -> None:
    db = VerdictCache(tmp_path / "c.sqlite")
    ro = scan_spec(SPEC, _opts(tmp_path, cache=db, read_only_cache=True), tmp_path / "a")
    assert not ro.verdict.cache_hit
    first = scan_spec(SPEC, _opts(tmp_path, cache=db), tmp_path / "b")
    assert not first.verdict.cache_hit  # the read-only run wrote nothing
    second = scan_spec(SPEC, _opts(tmp_path, cache=db), tmp_path / "c")
    assert second.verdict.cache_hit and second.verdict.level is first.verdict.level
    db.close()


def test_scan_changes_reports_unsupported_and_scanned(tmp_path: Path) -> None:
    changes = [
        DependencyChange(
            raw="quietpkg==1.0", source_file="r.txt", kind=ChangeKind.ADDED, spec=SPEC
        ),
        DependencyChange(
            raw="other>=2",
            source_file="r.txt",
            kind=ChangeKind.ADDED,
            spec=None,
            unsupported_reason="range specifier",
        ),
    ]
    report = scan_changes(changes, _opts(tmp_path), tmp_path / "w", notes=["n"])
    assert [v.level for v in report.verdicts] == [Level.ALLOW, Level.WARN]
    assert report.notes == ["n"] and "quietpkg==1.0" in report.stage_timings_s


def test_local_index(tmp_path: Path) -> None:
    index = tmp_path / "index"
    build_wheel(index, "quietpkg", "1.0", QUIET)

    def pypi(spec: PackageSpec, dest: Path) -> FetchedPackage:
        raise FetchError("not on PyPI either")

    opts = _opts(tmp_path, local_index=index, fetcher=pypi)
    assert scan_spec(SPEC, opts, tmp_path / "w").verdict.level is Level.ALLOW
    # Not in the index: falls through to the normal fetch, whose failure is an error.
    missing = scan_spec(PackageSpec(name="quietpkg", version="2.0"), opts, tmp_path / "x")
    assert missing.verdict.level is Level.ERROR
    assert "not on PyPI either" in missing.verdict.reasons[0]


def test_local_index_refuses_dependencies(tmp_path: Path) -> None:
    index = tmp_path / "index"
    build_wheel(index, "quietpkg", "1.0", QUIET, requires=["dep==1"])
    opts = ScanOptions(config=Config(), model=RULES_ONLY, sandbox=False, local_index=index)
    assert scan_spec(SPEC, opts, tmp_path / "w").verdict.level is Level.ERROR


def test_scan_artifact(tmp_path: Path) -> None:
    wheel = build_wheel(tmp_path / "wh", "quietpkg", "1.0", QUIET)
    opts = ScanOptions(config=Config(), model=RULES_ONLY, sandbox=False)
    assert scan_artifact(wheel, opts, tmp_path / "w").verdict.level is Level.ALLOW
    bad = scan_artifact(tmp_path / "nope.txt", opts, tmp_path / "x")
    assert bad.verdict.level is Level.ERROR
