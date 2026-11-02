"""End-to-end scan of one package: fetch -> extract -> static -> sandbox -> score.

The CLI and the Action are thin shells over this module. Every failure path ends in a
``Verdict`` (never an exception and never ``allow``): fail closed is enforced here, in one
place, rather than in each caller.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pipguard import SCANNER_VERSION
from pipguard.cache import VerdictCache
from pipguard.config import config_hash
from pipguard.errors import ExtractionError, FetchError, PipGuardError
from pipguard.extract import extract_package
from pipguard.fetch import fetch, from_local_artifact
from pipguard.log import correlation_id
from pipguard.models import (
    ArtifactRef,
    BehaviorTrace,
    Config,
    Coverage,
    DependencyChange,
    FetchedPackage,
    ModelArtifact,
    PackageSpec,
    ScanReport,
    StageStatus,
    StaticFeatures,
    Verdict,
    normalize_name,
)
from pipguard.scoring import error_verdict, score, unsupported_verdict
from pipguard.static import analyze

log = logging.getLogger("pipguard.pipeline")

DEFAULT_IMAGE = "pipguard-sandbox:local"  # the tag action/action.yml builds

SandboxRun = Callable[..., BehaviorTrace]


@dataclass
class ScanOptions:
    config: Config
    model: ModelArtifact
    sandbox: bool = True
    pr_candidate: bool = False  # FR-4.10: only PR-proposed packages (and fixtures) run
    image: str = DEFAULT_IMAGE
    cache: VerdictCache | None = None
    read_only_cache: bool = False  # fork PRs never write the cache (FR-1.3)
    # Resolve specs from a directory of wheels instead of PyPI (demo repo, Track C).
    local_index: Path | None = None
    fetcher: Callable[[PackageSpec, Path], FetchedPackage] | None = None
    sandbox_run: SandboxRun | None = None
    image_digest: Callable[[str], str] | None = None


@dataclass
class ScanResult:
    verdict: Verdict
    trace: BehaviorTrace | None = None
    timings: dict[str, float] = field(default_factory=dict)
    static: StaticFeatures | None = None  # kept for `pipguard explain`


def _refs(pkg: FetchedPackage) -> list[ArtifactRef]:
    return [ArtifactRef(filename=a.filename, sha256=a.sha256, kind=a.kind) for a in pkg.artifacts]


def _from_local_index(spec: PackageSpec, index: Path, dest: Path) -> FetchedPackage | None:
    """``spec``'s wheel from ``index``, or None if the index does not have it.

    Wheels in the index take precedence; everything else is fetched from PyPI as usual, so
    the demo's planted package comes from the repo while real bumps still hit PyPI.

    ponytail: demo-only resolver, wheels with no Requires-Dist; resolve deps from the same
    directory if a demo package ever needs them.
    """
    want = normalize_name(spec.name).replace("-", "_")
    for wheel in sorted(index.glob("*.whl")):
        dist, _, rest = wheel.name.partition("-")
        if normalize_name(dist).replace("-", "_") == want and rest.startswith(f"{spec.version}-"):
            pkg = from_local_artifact(wheel, dest)
            if pkg.declared_requirements:
                raise FetchError(f"{spec}: local index does not resolve dependencies")
            return pkg
    return None


def _sandbox(pkg: FetchedPackage, opts: ScanOptions) -> BehaviorTrace:
    if opts.sandbox_run is None:
        from pipguard import sandbox  # lazy: static-only scans need no Docker

        return sandbox.run(
            pkg, config=opts.config, image=opts.image, pr_candidate=opts.pr_candidate
        )
    return opts.sandbox_run(
        pkg, config=opts.config, image=opts.image, pr_candidate=opts.pr_candidate
    )


def _image_digest(opts: ScanOptions) -> str | None:
    if not opts.sandbox:
        return None
    if opts.image_digest is not None:
        return opts.image_digest(opts.image)
    from pipguard import sandbox

    return sandbox.image_digest(opts.image)


def scan_fetched(raw: str, pkg: FetchedPackage, opts: ScanOptions, workdir: Path) -> ScanResult:
    """Everything after fetch, for a package already on disk."""
    timings: dict[str, float] = {}
    refs = _refs(pkg)
    model_version = opts.model.model_version
    primary = pkg.wheel or pkg.sdist
    cfg_hash = config_hash(opts.config)

    t = time.monotonic()
    try:
        pkg = extract_package(pkg, workdir / "extracted")
    except ExtractionError as exc:
        cov = Coverage(fetch=StageStatus.COMPLETED, static=StageStatus.FAILED, artifacts=refs)
        return ScanResult(
            error_verdict(
                raw, pkg.spec, f"unsafe archive: {exc}", coverage=cov, model_version=model_version
            )
        )
    timings["extract"] = time.monotonic() - t

    digest: str | None = None
    if opts.sandbox:
        try:
            digest = _image_digest(opts)
        except PipGuardError as exc:
            cov = Coverage(fetch=StageStatus.COMPLETED, sandbox=StageStatus.FAILED, artifacts=refs)
            return ScanResult(
                error_verdict(
                    raw,
                    pkg.spec,
                    f"sandbox image unavailable: {exc}",
                    coverage=cov,
                    model_version=model_version,
                )
            )

    if opts.cache is not None and primary is not None:
        hit = opts.cache.get(primary.sha256, SCANNER_VERSION, model_version, cfg_hash, digest)
        if hit is not None:
            return ScanResult(
                hit,
                opts.cache.get_trace(
                    primary.sha256, SCANNER_VERSION, model_version, cfg_hash, digest
                )
                if digest
                else None,
                {"cache": 0.0},
            )

    t = time.monotonic()
    static = analyze(pkg)
    timings["static"] = time.monotonic() - t

    trace: BehaviorTrace | None = None
    if opts.sandbox:
        t = time.monotonic()
        trace = _sandbox(pkg, opts)
        timings["sandbox"] = time.monotonic() - t

    t = time.monotonic()
    verdict = score(
        static, trace, pkg, config=opts.config, sandbox_requested=opts.sandbox, model=opts.model
    )
    timings["scoring"] = time.monotonic() - t

    if opts.cache is not None and primary is not None:
        opts.cache.put(
            verdict,
            artifact_sha256=primary.sha256,
            config_hash=cfg_hash,
            image_digest=digest,
            trace=trace,
            read_only=opts.read_only_cache,
        )
    return ScanResult(verdict, trace, timings, static)


def scan_spec(
    spec: PackageSpec, opts: ScanOptions, workdir: Path, raw: str | None = None
) -> ScanResult:
    """Scan ``name==version``. Never raises for package or environment problems."""
    raw = raw or str(spec)
    t = time.monotonic()
    try:
        pkg = None
        if opts.local_index is not None:
            pkg = _from_local_index(spec, opts.local_index, workdir / "download")
        if pkg is None:
            fetcher = opts.fetcher or fetch
            pkg = fetcher(spec, workdir / "download")
    except FetchError as exc:
        cov = Coverage(fetch=StageStatus.FAILED, not_evaluated=["package (download failed)"])
        return ScanResult(
            error_verdict(
                raw,
                spec,
                f"fetch failed: {exc}",
                coverage=cov,
                model_version=opts.model.model_version,
            )
        )
    fetch_s = time.monotonic() - t
    result = _guarded(raw, spec, opts, lambda: scan_fetched(raw, pkg, opts, workdir))
    result.timings.setdefault("fetch", fetch_s)
    return result


def scan_artifact(path: Path, opts: ScanOptions, workdir: Path) -> ScanResult:
    """``--artifact``: scan a local wheel or sdist (FR-7.1)."""
    raw = path.name
    try:
        pkg = from_local_artifact(path, workdir / "download")
    except FetchError as exc:
        cov = Coverage(fetch=StageStatus.FAILED)
        return ScanResult(
            error_verdict(
                raw,
                None,
                f"cannot read artifact: {exc}",
                coverage=cov,
                model_version=opts.model.model_version,
            )
        )
    return _guarded(raw, pkg.spec, opts, lambda: scan_fetched(raw, pkg, opts, workdir))


def _guarded(
    raw: str, spec: PackageSpec | None, opts: ScanOptions, fn: Callable[[], ScanResult]
) -> ScanResult:
    """Any crash past this point is an ``error`` verdict: an unexamined package never passes."""
    try:
        return fn()
    except PipGuardError as exc:
        reason = f"scan failed: {exc}"
    except Exception as exc:
        log.exception("unexpected scanner failure for %s", raw)
        reason = f"internal scanner error ({type(exc).__name__}); failing closed"
    return ScanResult(error_verdict(raw, spec, reason, model_version=opts.model.model_version))


def scan_changes(
    changes: list[DependencyChange],
    opts: ScanOptions,
    workdir: Path,
    notes: list[str] | None = None,
) -> ScanReport:
    """Scan every added/changed dependency from a PR diff into one report."""
    verdicts: list[Verdict] = []
    traces: dict[str, BehaviorTrace] = {}
    timings: dict[str, dict[str, float]] = {}
    for i, change in enumerate(changes):
        if change.spec is None:
            verdicts.append(unsupported_verdict(change, model_version=opts.model.model_version))
            continue
        result = scan_spec(change.spec, opts, workdir / f"pkg{i}", raw=change.raw)
        verdicts.append(result.verdict)
        timings[str(change.spec)] = result.timings
        if result.trace is not None:
            traces[str(change.spec)] = result.trace
    return ScanReport(
        scanner_version=SCANNER_VERSION,
        correlation_id=correlation_id.get(),
        generated_at=datetime.now(UTC),
        verdicts=verdicts,
        stage_timings_s=timings,
        traces=traces,
        notes=notes or [],
    )


def report_for(results: list[ScanResult], notes: list[str] | None = None) -> ScanReport:
    """Wrap single-package results (``pipguard scan``) in the same report shape."""
    return ScanReport(
        scanner_version=SCANNER_VERSION,
        correlation_id=correlation_id.get(),
        generated_at=datetime.now(UTC),
        verdicts=[r.verdict for r in results],
        stage_timings_s={r.verdict.raw_spec: r.timings for r in results},
        traces={r.verdict.raw_spec: r.trace for r in results if r.trace is not None},
        notes=notes or [],
    )
