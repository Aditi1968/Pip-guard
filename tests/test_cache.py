from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from pipguard import cache as cache_mod
from pipguard.cache import VerdictCache
from pipguard.models import (
    ArtifactKind,
    ArtifactRef,
    BehaviorTrace,
    Completeness,
    Coverage,
    Level,
    PackageSpec,
    Verdict,
)

SHA = "a" * 64
SPEC = PackageSpec(name="foo", version="1.0")


def verdict(level: Level = Level.ALLOW, sha: str = SHA, **kw: object) -> Verdict:
    return Verdict(
        spec=SPEC,
        raw_spec="foo==1.0",
        level=level,
        reasons=[] if level is Level.ALLOW else ["because"],
        coverage=Coverage(
            artifacts=[ArtifactRef(filename="foo.whl", sha256=sha, kind=ArtifactKind.WHEEL)]
        ),
        scanner_version="s1",
        model_version="m1",
        **kw,  # type: ignore[arg-type]
    )


KEY = (SHA, "s1", "m1", "cfg")


@pytest.fixture
def cache(tmp_path: Path) -> VerdictCache:
    return VerdictCache(tmp_path / "c.sqlite")


def test_round_trip_sets_cache_hit(cache: VerdictCache) -> None:
    v = verdict(Level.WARN)
    assert cache.put(v, artifact_sha256=SHA, config_hash="cfg", read_only=False)
    got = cache.get(*KEY)
    assert got is not None and got.cache_hit
    assert got.model_copy(update={"cache_hit": False}) == v


def test_miss_on_any_key_difference(cache: VerdictCache) -> None:
    cache.put(verdict(), artifact_sha256=SHA, config_hash="cfg", read_only=False)
    assert cache.get("b" * 64, "s1", "m1", "cfg") is None
    assert cache.get(SHA, "s2", "m1", "cfg") is None
    assert cache.get(SHA, "s1", "m2", "cfg") is None
    assert cache.get(SHA, "s1", "m1", "other") is None
    assert cache.get(*KEY, image_digest="sha256:img") is None  # static-only != sandboxed


def test_fork_read_only_skips_write(cache: VerdictCache) -> None:
    assert not cache.put(verdict(), artifact_sha256=SHA, config_hash="cfg", read_only=True)
    assert cache.get(*KEY) is None


@pytest.mark.parametrize("level", [Level.ERROR, Level.INCOMPLETE])
def test_failed_runs_never_cached(cache: VerdictCache, level: Level) -> None:
    assert not cache.put(verdict(level), artifact_sha256=SHA, config_hash="cfg", read_only=False)


def test_verdict_not_covering_artifact_not_cached(cache: VerdictCache) -> None:
    v = verdict(sha="c" * 64)
    assert not cache.put(v, artifact_sha256=SHA, config_hash="cfg", read_only=False)


def test_trace_round_trip_and_image_digest(cache: VerdictCache) -> None:
    trace = BehaviorTrace(
        spec=SPEC,
        artifact_sha256=SHA,
        image_digest="sha256:img",
        completeness=Completeness.COMPLETE,
    )
    assert cache.put(
        verdict(),
        artifact_sha256=SHA,
        config_hash="cfg",
        image_digest="sha256:img",
        trace=trace,
        read_only=False,
    )
    assert cache.get_trace(*KEY, image_digest="sha256:img") == trace
    assert cache.get(*KEY, image_digest="sha256:img") is not None
    assert cache.get_trace(*KEY, image_digest="sha256:other") is None
    # A trace for a different image is refused at write time.
    assert not cache.put(
        verdict(),
        artifact_sha256=SHA,
        config_hash="cfg",
        image_digest="sha256:x",
        trace=trace,
        read_only=False,
    )


def test_corrupt_file_is_a_miss(tmp_path: Path) -> None:
    p = tmp_path / "c.sqlite"
    p.write_bytes(b"this is not a sqlite database" * 100)
    c = VerdictCache(p)
    assert c.get(*KEY) is None
    assert not c.put(verdict(), artifact_sha256=SHA, config_hash="cfg", read_only=False)
    c.close()


def test_foreign_schema_with_current_version_is_a_miss(tmp_path: Path) -> None:
    p = tmp_path / "c.sqlite"
    db = sqlite3.connect(p)
    db.execute("CREATE TABLE verdicts (x)")
    db.execute(f"PRAGMA user_version = {cache_mod.CACHE_SCHEMA}")
    db.commit()
    db.close()
    c = VerdictCache(p)
    assert c.get(*KEY) is None
    assert not c.put(verdict(), artifact_sha256=SHA, config_hash="cfg", read_only=False)


def test_old_schema_is_dropped(tmp_path: Path) -> None:
    p = tmp_path / "c.sqlite"
    db = sqlite3.connect(p)
    db.execute("CREATE TABLE verdicts (x)")
    db.commit()
    db.close()
    c = VerdictCache(p)
    assert c.put(verdict(), artifact_sha256=SHA, config_hash="cfg", read_only=False)
    assert c.get(*KEY) is not None


def _poke(path: Path, sql: str, params: tuple[object, ...]) -> None:
    db = sqlite3.connect(path)
    db.execute(sql, params)
    db.commit()
    db.close()


@pytest.mark.parametrize(
    "payload",
    [
        "{not json",
        b"binary",
        '{"level": "allow"}',
        # Valid verdict, but it claims a different scanner version than its key.
        verdict().model_copy(update={"scanner_version": "s0"}).model_dump_json(),
        # Valid verdict at a level that must never come from the cache.
        verdict(Level.ERROR).model_dump_json(),
        verdict().model_copy(update={"schema_version": 0}).model_dump_json(),
    ],
)
def test_hostile_rows_are_misses(tmp_path: Path, payload: object) -> None:
    p = tmp_path / "c.sqlite"
    VerdictCache(p).close()
    _poke(p, "INSERT INTO verdicts VALUES (?, ?, ?, ?, '', ?, NULL)", (*KEY, payload))
    assert VerdictCache(p).get(*KEY) is None


def test_hostile_trace_rows_are_misses(tmp_path: Path) -> None:
    p = tmp_path / "c.sqlite"
    VerdictCache(p).close()
    other = BehaviorTrace(
        spec=SPEC, artifact_sha256="d" * 64, image_digest="img", completeness=Completeness.COMPLETE
    )
    _poke(
        p,
        "INSERT INTO verdicts VALUES (?, ?, ?, ?, 'img', ?, ?)",
        (*KEY, verdict().model_dump_json(), other.model_dump_json()),
    )
    c = VerdictCache(p)
    assert c.get_trace(*KEY, image_digest="img") is None
    _poke(p, "UPDATE verdicts SET trace_json = ?", ("{bad",))
    assert c.get_trace(*KEY, image_digest="img") is None
    _poke(p, "UPDATE verdicts SET trace_json = NULL", ())
    assert c.get_trace(*KEY, image_digest="img") is None


def test_oversized_row_is_a_miss(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "c.sqlite"
    c = VerdictCache(p)
    c.put(verdict(), artifact_sha256=SHA, config_hash="cfg", read_only=False)
    monkeypatch.setattr(cache_mod, "MAX_ROW_BYTES", 10)
    assert c.get(*KEY) is None
    assert not c.put(verdict(Level.WARN), artifact_sha256=SHA, config_hash="cfg", read_only=False)


def test_unopenable_path_is_a_miss(tmp_path: Path) -> None:
    c = VerdictCache(tmp_path)  # a directory, not a file
    assert c.get(*KEY) is None
    assert c.get_trace(*KEY, image_digest="x") is None
    c.close()


def test_sqlite_error_during_read_is_a_miss(cache: VerdictCache) -> None:
    assert cache._db is not None
    cache._db.execute("DROP TABLE verdicts")
    assert cache.get(*KEY) is None
