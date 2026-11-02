"""SQLite verdict cache (FR-1.3). Best-effort, never load-bearing.

The file travels between CI runs in the GitHub Actions cache, so a restored file is
untrusted input: every failure (corrupt file, foreign schema, oversized or invalid row,
versions that do not match the key) is a cache *miss* plus a warning, never a crash and
never a trusted verdict.

Only ``allow``/``warn``/``block`` are cached. ``error`` and ``incomplete`` describe a run
that failed, not the artifact, so they are always retried.

The behavioural result is reused only for the identical artifact hash *and* runtime image
digest (PRD), so ``image_digest`` is part of the key; ``None`` (stored as ``''``) is a
static-only verdict and never matches a sandboxed lookup.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from pydantic import ValidationError

from pipguard.models import SCHEMA_VERSION, BehaviorTrace, Level, Verdict

log = logging.getLogger("pipguard.cache")

CACHE_SCHEMA = 1  # PRAGMA user_version; bump on any table change
MAX_ROW_BYTES = 6 * 1024 * 1024  # 5 MB trace cap + verdict headroom
CACHEABLE = frozenset({Level.ALLOW, Level.WARN, Level.BLOCK})

_DDL = """
CREATE TABLE IF NOT EXISTS verdicts (
    artifact_sha256 TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    model_version TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    verdict_json TEXT NOT NULL,
    trace_json TEXT,
    PRIMARY KEY (artifact_sha256, scanner_version, model_version, config_hash, image_digest)
)
"""


class VerdictCache:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._db: sqlite3.Connection | None = None
        try:
            db = sqlite3.connect(path, timeout=5)
            # Restored file is hostile until proven otherwise: no schema-defined functions,
            # check page integrity, refuse anything that is not a well-formed database.
            db.execute("PRAGMA trusted_schema = OFF")
            db.execute("PRAGMA cell_size_check = ON")
            if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise sqlite3.DatabaseError("quick_check failed")
            if db.execute("PRAGMA user_version").fetchone()[0] != CACHE_SCHEMA:
                db.execute("DROP TABLE IF EXISTS verdicts")  # older/foreign schema: start over
                db.execute(f"PRAGMA user_version = {CACHE_SCHEMA}")
            db.execute(_DDL)
            db.commit()
            self._db = db
        except sqlite3.Error as exc:
            log.warning("verdict cache unusable, continuing without it: %s", exc)

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    def _row(self, key: tuple[str, str, str, str, str]) -> tuple[str, str | None] | None:
        if self._db is None:
            return None
        try:
            return self._db.execute(
                "SELECT verdict_json, trace_json FROM verdicts WHERE artifact_sha256 = ?"
                " AND scanner_version = ? AND model_version = ? AND config_hash = ?"
                " AND image_digest = ?"
                " AND length(verdict_json) + coalesce(length(trace_json), 0) <= ?",
                (*key, MAX_ROW_BYTES),
            ).fetchone()
        except sqlite3.Error as exc:
            log.warning("verdict cache read failed: %s", exc)
            return None

    def get(
        self,
        artifact_sha256: str,
        scanner_version: str,
        model_version: str,
        config_hash: str,
        image_digest: str | None = None,
    ) -> Verdict | None:
        """The cached verdict, or None on miss or on anything untrustworthy."""
        key = (artifact_sha256, scanner_version, model_version, config_hash, image_digest or "")
        row = self._row(key)
        if row is None:
            return None
        try:
            if not isinstance(row[0], str):
                raise TypeError("verdict_json is not text")
            verdict = Verdict.model_validate_json(row[0])
        except (ValidationError, TypeError, ValueError) as exc:
            log.warning("discarding invalid cached verdict: %s", exc)
            return None
        if not _consistent(verdict, artifact_sha256, scanner_version, model_version):
            log.warning("discarding cached verdict whose versions do not match its key")
            return None
        return verdict.model_copy(update={"cache_hit": True})

    def get_trace(
        self,
        artifact_sha256: str,
        scanner_version: str,
        model_version: str,
        config_hash: str,
        image_digest: str,
    ) -> BehaviorTrace | None:
        """The cached behavioural trace for this exact artifact and sandbox image."""
        key = (artifact_sha256, scanner_version, model_version, config_hash, image_digest)
        row = self._row(key)
        if row is None or row[1] is None:
            return None
        try:
            if not isinstance(row[1], str):
                raise TypeError("trace_json is not text")
            trace = BehaviorTrace.model_validate_json(row[1])
        except (ValidationError, TypeError, ValueError) as exc:
            log.warning("discarding invalid cached trace: %s", exc)
            return None
        if (
            trace.schema_version != SCHEMA_VERSION
            or trace.artifact_sha256 != artifact_sha256
            or trace.image_digest != image_digest
        ):
            log.warning("discarding cached trace whose artifact/image do not match its key")
            return None
        return trace

    def put(
        self,
        verdict: Verdict,
        *,
        artifact_sha256: str,
        config_hash: str,
        image_digest: str | None = None,
        trace: BehaviorTrace | None = None,
        read_only: bool,
    ) -> bool:
        """Store a verdict. Returns whether it was written.

        ``read_only`` is set on fork PRs (FR-1.3): their results never seed the cache.
        """
        if read_only or self._db is None:
            return False
        if verdict.level not in CACHEABLE:
            return False
        if not _consistent(
            verdict, artifact_sha256, verdict.scanner_version, verdict.model_version
        ):
            log.warning("not caching a verdict that does not cover artifact %s", artifact_sha256)
            return False
        if trace is not None and (
            trace.artifact_sha256 != artifact_sha256 or trace.image_digest != image_digest
        ):
            log.warning("not caching a trace for a different artifact or image")
            return False
        verdict_json = verdict.model_copy(update={"cache_hit": False}).model_dump_json()
        trace_json = trace.model_dump_json() if trace is not None else None
        if len(verdict_json) + len(trace_json or "") > MAX_ROW_BYTES:
            log.warning("not caching an oversized verdict for %s", artifact_sha256)
            return False
        try:
            self._db.execute(
                "INSERT OR REPLACE INTO verdicts VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    artifact_sha256,
                    verdict.scanner_version,
                    verdict.model_version,
                    config_hash,
                    image_digest or "",
                    verdict_json,
                    trace_json,
                ),
            )
            self._db.commit()
        except sqlite3.Error as exc:
            log.warning("verdict cache write failed: %s", exc)
            return False
        return True


def _consistent(verdict: Verdict, sha256: str, scanner_version: str, model_version: str) -> bool:
    """A cached row is trusted only if its own content agrees with the key it sits under."""
    return (
        verdict.schema_version == SCHEMA_VERSION
        and verdict.level in CACHEABLE
        and verdict.scanner_version == scanner_version
        and verdict.model_version == model_version
        and sha256 in {a.sha256 for a in verdict.coverage.artifacts}
    )
