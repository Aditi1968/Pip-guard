"""Versioned stage contracts (PRD: "Stage contracts").

Every stage takes and returns one of these models, so stages can be built, tested and
cached independently. Each top-level model carries ``schema_version``; bump it on any
breaking field change so cached results from an older contract are rejected.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = 1


_NAME_RE = re.compile(r"^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")


def normalize_name(name: str) -> str:
    """PEP 503 normalisation: lowercase, runs of ``-_.`` collapsed to ``-``."""
    return re.sub(r"[-_.]+", "-", name).lower()


class _Model(BaseModel):
    # Frozen + forbid: contracts are values, and a typo in a field name is a bug, not data.
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------- spec & fetch (FR-1, FR-2)


class PackageSpec(_Model):
    """An exactly pinned direct dependency, ``name==version`` (FR-1.1)."""

    schema_version: int = SCHEMA_VERSION
    name: str = Field(max_length=200)
    version: str = Field(max_length=100)

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if not _NAME_RE.match(v):
            raise ValueError(f"invalid package name: {v!r}")
        return v

    @field_validator("version")
    @classmethod
    def _valid_version(cls, v: str) -> str:
        if not _VERSION_RE.match(v):
            raise ValueError(f"invalid version: {v!r}")
        return v

    @property
    def normalized_name(self) -> str:
        return normalize_name(self.name)

    @classmethod
    def parse(cls, text: str) -> PackageSpec:
        """Parse ``name==version``. Anything that is not an exact pin raises ValueError."""
        name, sep, version = text.strip().partition("==")
        if not sep or not name.strip() or not version.strip() or "=" in version:
            raise ValueError(f"not an exact pin (name==version): {text!r}")
        return cls(name=name.strip(), version=version.strip())

    def __str__(self) -> str:
        return f"{self.name}=={self.version}"


class ArtifactKind(StrEnum):
    WHEEL = "wheel"
    SDIST = "sdist"


class Artifact(_Model):
    """One downloaded file, identified by its verified SHA-256 (FR-2.1, FR-2.2)."""

    filename: str
    kind: ArtifactKind
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    python_tag: str | None = None  # wheels only, e.g. "py3"
    platform_tag: str | None = None  # wheels only, e.g. "any"
    size: int = Field(ge=0)
    path: str  # local path of the downloaded file (untrusted contents)
    extracted_path: str | None = None  # set once safely extracted (FR-2.3)


class PackageMetadata(_Model):
    """PyPI metadata features (FR-2.4). ``None`` means missing, never zero."""

    release_date: datetime | None = None
    first_release_date: datetime | None = None
    version_count: int | None = None
    maintainer_count: int | None = None  # PyPI JSON does not always expose this
    days_since_release: int | None = None
    days_since_first_release: int | None = None
    project_urls: dict[str, str] = Field(default_factory=dict)
    summary: str | None = None


class FetchedPackage(_Model):
    """Output of ``fetch.fetch(spec)``: the exact artifacts plus what the sandbox needs."""

    schema_version: int = SCHEMA_VERSION
    spec: PackageSpec
    artifacts: list[Artifact]
    metadata: PackageMetadata
    # Requirement strings from the target wheel's METADATA (Requires-Dist), as published.
    declared_requirements: list[str] = Field(default_factory=list)
    # Wheels for the declared dependencies, preinstalled untraced in the sandbox (FR-2.5).
    declared_deps: list[Artifact] = Field(default_factory=list)
    # Where this package came from; the sandbox policy guard reads it (FR-4.10).
    origin: Literal["pypi", "local_artifact", "fixture"] = "pypi"

    @property
    def wheel(self) -> Artifact | None:
        return next((a for a in self.artifacts if a.kind is ArtifactKind.WHEEL), None)

    @property
    def sdist(self) -> Artifact | None:
        return next((a for a in self.artifacts if a.kind is ArtifactKind.SDIST), None)


# ---------------------------------------------------------------- static (FR-3)


class ImportCategory(StrEnum):
    NETWORK = "network"
    SUBPROCESS = "subprocess"
    FILESYSTEM = "filesystem"
    ENVIRONMENT = "environment"


class InstallIndicators(_Model):
    """Install-time indicators: *present*, never claimed as executed (FR-3.2)."""

    setup_py_cmdclass: bool = False
    overridden_install_command: bool = False  # install / develop / egg_info subclassed
    pth_import_lines: bool = False
    pep517_build_backend: bool = False  # sdist only


class SuspiciousCounts(_Model):
    """Suspicious-indicator counts (FR-3.3). Legitimate code uses all of these."""

    exec: int = 0
    eval: int = 0
    compile: int = 0
    dynamic_import: int = 0  # __import__ / importlib.import_module with a non-literal arg
    b64decode: int = 0
    zlib_decompress: int = 0
    marshal_loads: int = 0
    pickle_loads: int = 0
    ctypes: int = 0

    @property
    def total(self) -> int:
        return sum(self.model_dump().values())


class ArtifactStaticFeatures(_Model):
    """Static features for one artifact (wheel or sdist)."""

    filename: str
    sha256: str
    kind: ArtifactKind
    file_count: int = 0
    total_size: int = 0
    py_file_count: int = 0
    syntax_error_count: int = 0  # FR-3.1: a feature, not a failure
    has_compiled_extensions: bool = False
    install: InstallIndicators = Field(default_factory=InstallIndicators)
    suspicious: SuspiciousCounts = Field(default_factory=SuspiciousCounts)
    max_string_entropy: float = 0.0  # FR-3.4
    high_entropy_string_count: int = 0
    urls: list[str] = Field(default_factory=list)  # FR-3.5, capped and deduplicated
    ip_literals: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    shortener_urls: list[str] = Field(default_factory=list)
    # FR-3.7: categories imported at module top level or inside install-hook code.
    risky_import_categories: list[ImportCategory] = Field(default_factory=list)
    risky_import_modules: list[str] = Field(default_factory=list)


class TyposquatResult(_Model):
    """Typosquat score against a frozen, dated snapshot (FR-3.6)."""

    distance: int | None = None  # None when nothing is within the search radius
    target: str | None = None
    target_rank: int | None = None  # 1-based rank in the snapshot
    snapshot_date: date
    fired: bool = False


class StaticFeatures(_Model):
    """Output of ``static.analyze(pkg)``."""

    schema_version: int = SCHEMA_VERSION
    spec: PackageSpec
    artifacts: list[ArtifactStaticFeatures]
    typosquat: TyposquatResult
    metadata: PackageMetadata


# ---------------------------------------------------------------- behaviour (FR-4)


class Completeness(StrEnum):
    COMPLETE = "complete"
    TIMEOUT = "incomplete:timeout"
    IMPORT_FAILED = "incomplete:import_failed"
    NO_IMPORTABLE_MODULE = "incomplete:no_importable_module"
    NO_WHEEL = "incomplete:no_wheel"
    SANDBOX_ERROR = "incomplete:sandbox_error"
    TRACE_TRUNCATED = "incomplete:trace_truncated"
    SKIPPED_POLICY = "skipped:policy"

    @property
    def is_complete(self) -> bool:
        return self is Completeness.COMPLETE


Step = Literal["install", "import"]


class ConnectAttempt(_Model):
    step: Step
    family: str  # AF_INET / AF_INET6 / AF_UNIX / other
    address: str
    port: int | None = None


class CredentialRead(_Model):
    step: Step
    path: str


class SubprocessCall(_Model):
    step: Step
    argv: list[str]


class FileWrite(_Model):
    step: Step
    path: str


class StepResult(_Model):
    step: Step
    exit_code: int | None  # None if killed
    wall_time_s: float
    timed_out: bool = False


class BehaviorTrace(_Model):
    """Output of ``sandbox.run(pkg)``: target wheel only, ``--no-deps`` (FR-4.5).

    Environment-variable reads and DNS names are deliberately absent: strace cannot
    observe them, and the schema only holds what the tracer can actually see.
    """

    schema_version: int = SCHEMA_VERSION
    spec: PackageSpec
    artifact_sha256: str | None = None
    image_digest: str | None = None
    completeness: Completeness
    completeness_reason: str = ""
    steps: list[StepResult] = Field(default_factory=list)
    imported_modules: list[str] = Field(default_factory=list)
    writes_outside_allowed: list[FileWrite] = Field(default_factory=list)
    credential_reads: list[CredentialRead] = Field(default_factory=list)
    subprocesses: list[SubprocessCall] = Field(default_factory=list)
    connects: list[ConnectAttempt] = Field(default_factory=list)
    truncated: bool = False  # some fields or lines were capped (FR-4.11)


# ---------------------------------------------------------------- verdict (FR-5)


class Level(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    ERROR = "error"
    INCOMPLETE = "incomplete"


class StageStatus(StrEnum):
    COMPLETED = "completed"
    SKIPPED = "skipped"  # by choice: --no-sandbox, policy, cache hit
    FAILED = "failed"
    NOT_RUN = "not_run"  # an earlier stage failed


class ArtifactRef(_Model):
    filename: str
    sha256: str
    kind: ArtifactKind


class Coverage(_Model):
    """Which stages completed, on which artifacts, and what was not evaluated."""

    fetch: StageStatus = StageStatus.NOT_RUN
    static: StageStatus = StageStatus.NOT_RUN
    sandbox: StageStatus = StageStatus.NOT_RUN
    scoring: StageStatus = StageStatus.NOT_RUN
    sandbox_completeness: Completeness | None = None
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    not_evaluated: list[str] = Field(default_factory=list)


class Thresholds(_Model):
    # 0.5 / 0.85 are placeholders until chosen on validation data (FR-5.8).
    warn: float = Field(default=0.5, ge=0, le=1)
    block: float = Field(default=0.85, ge=0, le=1)

    @model_validator(mode="after")
    def _ordered(self) -> Thresholds:
        if self.warn > self.block:
            raise ValueError("warn threshold must not exceed block threshold")
        return self


class ModelArtifact(_Model):
    """A trained scorer, versioned together with its thresholds and data (FR-5.2, FR-5.8).

    Produced by ``scripts/eval/train.py``, loaded by ``scoring.py``. Logistic regression is
    stored as plain coefficients so inference needs no scikit-learn at runtime.
    """

    schema_version: int = SCHEMA_VERSION
    model_version: str
    kind: Literal["rules", "logreg", "lightgbm"]
    feature_names: list[str] = Field(default_factory=list)
    # Feature standardisation applied before the linear model: (x - mean) / scale.
    feature_means: list[float] = Field(default_factory=list)
    feature_scales: list[float] = Field(default_factory=list)
    coefficients: list[float] = Field(default_factory=list)
    intercept: float = 0.0
    # Platt scaling on the validation fold; when None the output is labelled "score".
    platt_a: float | None = None
    platt_b: float | None = None
    lightgbm_model: str | None = None  # LightGBM text dump, only if that rung is adopted
    thresholds: Thresholds = Field(default_factory=Thresholds)
    training_manifest_sha256: str | None = None
    typosquat_snapshot_date: date | None = None
    trained_at: datetime | None = None

    @model_validator(mode="after")
    def _shapes(self) -> ModelArtifact:
        if self.kind == "logreg":
            n = len(self.feature_names)
            if not n or {
                len(self.coefficients),
                len(self.feature_means),
                len(self.feature_scales),
            } != {n}:
                raise ValueError("logreg artifact needs one coefficient/mean/scale per feature")
        return self


class Verdict(_Model):
    """Output of ``scoring.score(...)`` (FR-5.3)."""

    schema_version: int = SCHEMA_VERSION
    spec: PackageSpec | None  # None only for an unparseable spec reported as unsupported
    raw_spec: str
    level: Level
    score: float | None = Field(default=None, ge=0, le=1)
    score_label: Literal["score", "calibrated probability"] = "score"
    reasons: list[str] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    overrides: list[str] = Field(default_factory=list)
    rule_hits: list[str] = Field(default_factory=list)
    scanner_version: str
    model_version: str
    thresholds: Thresholds = Field(default_factory=Thresholds)
    cache_hit: bool = False

    @model_validator(mode="after")
    def _explained(self) -> Verdict:
        # FR-5.4 / success criteria: every warn/block (and every failure) says why.
        if self.level is not Level.ALLOW and not self.reasons:
            raise ValueError(f"a {self.level} verdict needs at least one reason")
        return self


# ---------------------------------------------------------------- diff, config, report


class ChangeKind(StrEnum):
    ADDED = "added"
    CHANGED = "changed"


class DependencyChange(_Model):
    """One added/changed direct dependency from the PR diff (FR-1.1, FR-1.2)."""

    raw: str  # the requirement line as written in head
    source_file: str
    kind: ChangeKind
    spec: PackageSpec | None  # None when the requirement is not an exact pin
    previous_version: str | None = None
    unsupported_reason: str | None = None

    @model_validator(mode="after")
    def _either(self) -> DependencyChange:
        if (self.spec is None) == (self.unsupported_reason is None):
            raise ValueError("exactly one of spec / unsupported_reason must be set")
        return self


class Timeouts(_Model):
    install_s: int = Field(default=90, gt=0)
    import_s: int = Field(default=60, gt=0)


class Config(_Model):
    """``pipguard.toml`` (FR-7.2)."""

    thresholds: Thresholds = Field(default_factory=Thresholds)
    timeouts: Timeouts = Field(default_factory=Timeouts)
    watched_files: list[str] = Field(default_factory=lambda: ["requirements.txt", "pyproject.toml"])
    # Per-package allowlist: still fully scanned and reported, verdict capped at warn.
    allowlist: list[str] = Field(default_factory=list)

    @field_validator("allowlist")
    @classmethod
    def _normalise(cls, v: list[str]) -> list[str]:
        return sorted({normalize_name(n) for n in v})


class ScanReport(_Model):
    """The JSON report artifact (FR-6.3)."""

    schema_version: int = SCHEMA_VERSION
    scanner_version: str
    correlation_id: str
    generated_at: datetime
    verdicts: list[Verdict]
    stage_timings_s: dict[str, dict[str, float]] = Field(default_factory=dict)
    traces: dict[str, BehaviorTrace] = Field(default_factory=dict)  # non-allow only
    notes: list[str] = Field(default_factory=list)
