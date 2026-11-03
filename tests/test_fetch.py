import hashlib
import io
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

import pytest

from pipguard import fetch as fetch_mod
from pipguard.errors import FetchError, HashMismatchError
from pipguard.fetch import (
    PyPIClient,
    _parse_specifier,
    _parse_version,
    _wheel_rank,
    evaluate_marker,
    fetch,
    from_local_artifact,
    parse_requirement,
    read_requires_dist,
)
from pipguard.models import ArtifactKind, PackageSpec
from scripts.make_wheel import build_wheel

NOW = datetime(2026, 1, 11, tzinfo=UTC)
PYPI = "https://pypi.org/pypi"


class FakePyPI:
    """In-memory PyPI: URL -> bytes, or an exception (or a list of them, consumed in order)."""

    def __init__(self) -> None:
        self.routes: dict[str, Any] = {}
        self.calls: list[urllib.request.Request] = []
        self.sleeps: list[float] = []
        self.projects: dict[str, dict[str, list[dict[str, Any]]]] = {}

    def opener(self, req: urllib.request.Request, timeout: float) -> IO[bytes]:
        self.calls.append(req)
        r = self.routes.get(req.full_url)
        if isinstance(r, list):
            r = r.pop(0) if len(r) > 1 else r[0]
        if r is None:
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", None, None)  # type: ignore[arg-type]
        if isinstance(r, Exception):
            raise r
        return io.BytesIO(r)

    def client(self) -> PyPIClient:
        return PyPIClient(opener=self.opener, sleep=self.sleeps.append)

    def file(
        self,
        filename: str,
        data: bytes,
        uploaded: str = "2025-01-01T00:00:00Z",
        yanked: bool = False,
        sha: str | None = None,
    ) -> dict[str, Any]:
        url = f"https://files.example/{filename}"
        self.routes[url] = data
        return {
            "filename": filename,
            "packagetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
            "url": url,
            "digests": {"sha256": sha or hashlib.sha256(data).hexdigest()},
            "size": len(data),
            "upload_time_iso_8601": uploaded,
            "yanked": yanked,
        }

    def release(self, name: str, version: str, files: list[dict[str, Any]], **info: Any) -> None:
        self.projects.setdefault(name, {})[version] = files
        self.routes[f"{PYPI}/{name}/{version}/json"] = json.dumps(
            {"info": {"name": name, "version": version, **info}, "urls": files}
        ).encode()
        self.routes[f"{PYPI}/{name}/json"] = json.dumps(
            {"info": {"name": name}, "releases": self.projects[name]}
        ).encode()


def _wheel_bytes(tmp: Path, name: str, version: str, requires: list[str] | None = None) -> bytes:
    files: dict[str, str | bytes] = {f"{name.replace('-', '_')}/__init__.py": ""}
    return build_wheel(tmp / f"src-{name}-{version}", name, version, files, requires).read_bytes()


def _sdist_bytes() -> bytes:
    return b"\x1f\x8b fake sdist bytes"  # fetch never opens sdists


# ---------------------------------------------------------------- wheel selection


@pytest.mark.parametrize(
    ("filename", "ok"),
    [
        ("a-1-py3-none-any.whl", True),
        ("a-1-py2.py3-none-any.whl", True),
        ("a-1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", True),
        ("a-1-cp312-cp312-manylinux1_x86_64.whl", True),
        ("a-1-cp38-abi3-manylinux_2_28_x86_64.whl", True),
        ("a-1-cp312-cp312-linux_x86_64.whl", True),
        ("a-1-cp312-cp312-manylinux_2_17_aarch64.whl", False),
        ("a-1-cp312-cp312-win_amd64.whl", False),
        ("a-1-cp312-cp312-macosx_11_0_x86_64.whl", False),
        ("a-1-cp312-cp312-musllinux_1_1_x86_64.whl", False),  # sandbox is glibc
        ("a-1-cp312-cp312-manylinux_2_39_x86_64.whl", False),  # newer than bookworm glibc
        ("a-1-cp311-cp311-manylinux_2_17_x86_64.whl", False),
        ("a-1-py2-none-any.whl", False),
        ("a-1.tar.gz", False),
    ],
)
def test_wheel_compatibility(filename: str, ok: bool) -> None:
    assert (_wheel_rank(filename) is not None) is ok


def test_wheel_ranking() -> None:
    order = [
        "a-1-py3-none-any.whl",
        "a-1-cp312-cp312-manylinux_2_28_x86_64.whl",
        "a-1-cp38-abi3-manylinux_2_28_x86_64.whl",
        "a-1-cp312-cp312-manylinux2014_x86_64.whl",
        "a-1-cp312-cp312-linux_x86_64.whl",
    ]
    ranks = [_wheel_rank(f) for f in order]
    assert ranks == sorted(ranks, reverse=True)  # type: ignore[type-var]


# ---------------------------------------------------------------- fetch


def test_fetch_pure_wheel_and_sdist(tmp_path: Path) -> None:
    pypi = FakePyPI()
    whl = _wheel_bytes(tmp_path, "demo", "1.0")
    pypi.release("demo", "0.1", [pypi.file("demo-0.1.tar.gz", b"old", "2020-01-01T00:00:00Z")])
    pypi.release("demo", "0.2", [])  # all files deleted: not a counted version
    pypi.release(
        "demo",
        "1.0",
        [
            pypi.file("demo-1.0-cp312-cp312-win_amd64.whl", whl, "2026-01-02T00:00:00Z"),
            pypi.file("demo-1.0-py3-none-any.whl", whl, "2026-01-01T12:00:00Z"),
            pypi.file("demo-1.0.tar.gz", _sdist_bytes(), "2026-01-01T10:00:00Z"),
        ],
        summary="x" * 1000,
        project_urls={"Source": "https://example.org/demo"},
    )
    pkg = fetch(
        PackageSpec(name="demo", version="1.0"), tmp_path / "dl", client=pypi.client(), now=NOW
    )

    wheel, sdist = pkg.wheel, pkg.sdist
    assert wheel and sdist
    assert wheel.filename == "demo-1.0-py3-none-any.whl"
    assert (wheel.python_tag, wheel.platform_tag) == ("py3", "any")
    assert wheel.sha256 == hashlib.sha256(whl).hexdigest()
    assert wheel.size == len(whl) and Path(wheel.path).read_bytes() == whl
    assert sdist.kind is ArtifactKind.SDIST and sdist.python_tag is None
    m = pkg.metadata
    assert m.release_date == datetime(2026, 1, 1, 10, tzinfo=UTC)
    assert m.first_release_date == datetime(2020, 1, 1, tzinfo=UTC)
    assert m.version_count == 2
    assert m.maintainer_count is None  # missing, not zero
    assert (m.days_since_release, m.days_since_first_release) == (
        9,
        (NOW - datetime(2020, 1, 1, tzinfo=UTC)).days,
    )
    assert m.summary == "x" * 500
    assert m.project_urls == {"Source": "https://example.org/demo"}
    assert pkg.origin == "pypi" and pkg.declared_deps == []
    assert all(r.get_header("User-agent", "").startswith("pipguard/") for r in pypi.calls)


def test_fetch_picks_cp312_manylinux_x86_64(tmp_path: Path) -> None:
    pypi = FakePyPI()
    whl = _wheel_bytes(tmp_path, "fast", "2.0")
    names = [
        "fast-2.0-cp312-cp312-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
        "fast-2.0-cp312-cp312-win_amd64.whl",
        "fast-2.0-cp312-cp312-macosx_11_0_x86_64.whl",
        "fast-2.0-cp312-cp312-musllinux_1_1_x86_64.whl",
        "fast-2.0-cp311-cp311-manylinux_2_17_x86_64.whl",
        "fast-2.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
    ]
    pypi.release("fast", "2.0", [pypi.file(n, whl) for n in names])
    pkg = fetch(
        PackageSpec(name="fast", version="2.0"), tmp_path / "dl", client=pypi.client(), now=NOW
    )
    assert [a.filename for a in pkg.artifacts] == [names[-1]]
    assert pkg.artifacts[0].platform_tag == "manylinux_2_17_x86_64.manylinux2014_x86_64"


def test_fetch_sdist_only(tmp_path: Path) -> None:
    pypi = FakePyPI()
    pypi.release(
        "slow",
        "1.0",
        [
            pypi.file("slow-1.0-cp312-cp312-win_amd64.whl", b"w"),
            pypi.file("slow-1.0.tar.gz", _sdist_bytes()),
        ],
    )
    pkg = fetch(
        PackageSpec(name="slow", version="1.0"), tmp_path / "dl", client=pypi.client(), now=NOW
    )
    assert pkg.wheel is None and pkg.sdist is not None
    assert pkg.declared_requirements == [] and pkg.declared_deps == []


def test_fetch_no_usable_artifacts(tmp_path: Path) -> None:
    pypi = FakePyPI()
    pypi.release("none", "1.0", [pypi.file("none-1.0-cp312-cp312-win_amd64.whl", b"w")])
    with pytest.raises(FetchError, match="no sandbox-compatible wheel and no sdist"):
        fetch(PackageSpec(name="none", version="1.0"), tmp_path, client=pypi.client(), now=NOW)


def test_fetch_unknown_version_is_error_without_retry(tmp_path: Path) -> None:
    pypi = FakePyPI()
    with pytest.raises(FetchError, match="not found"):
        fetch(PackageSpec(name="ghost", version="1.0"), tmp_path, client=pypi.client())
    assert len(pypi.calls) == 1 and pypi.sleeps == []


def test_hash_mismatch(tmp_path: Path) -> None:
    pypi = FakePyPI()
    pypi.release("demo", "1.0", [pypi.file("demo-1.0.tar.gz", b"tampered", sha="a" * 64)])
    with pytest.raises(HashMismatchError):
        fetch(PackageSpec(name="demo", version="1.0"), tmp_path / "dl", client=pypi.client())
    assert list((tmp_path / "dl").iterdir()) == []  # no partial or unverified file left
    assert pypi.sleeps == []  # a mismatch is not retried


def test_download_over_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pypi = FakePyPI()
    entry = pypi.file("demo-1.0.tar.gz", b"x" * 200_000)
    entry["size"] = 10  # PyPI's declared size is not trusted: the stream is counted
    pypi.release("demo", "1.0", [entry])
    monkeypatch.setattr(fetch_mod, "MAX_DOWNLOAD_BYTES", 100_000)
    with pytest.raises(FetchError, match="exceeds"):
        fetch(PackageSpec(name="demo", version="1.0"), tmp_path / "dl", client=pypi.client())
    assert list((tmp_path / "dl").iterdir()) == []


def test_declared_size_over_cap_skips_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pypi = FakePyPI()
    entry = pypi.file("demo-1.0.tar.gz", b"x")
    entry["size"] = 10**9
    pypi.release("demo", "1.0", [entry])
    with pytest.raises(FetchError, match="cap"):
        fetch(PackageSpec(name="demo", version="1.0"), tmp_path / "dl", client=pypi.client())
    assert not any(r.full_url == entry["url"] for r in pypi.calls)


def test_retry_then_fail(tmp_path: Path) -> None:
    pypi = FakePyPI()
    url = f"{PYPI}/demo/1.0/json"
    pypi.routes[url] = urllib.error.URLError("connection reset")
    with pytest.raises(FetchError, match="after 3 tries"):
        fetch(PackageSpec(name="demo", version="1.0"), tmp_path, client=pypi.client())
    assert len(pypi.calls) == 3 and pypi.sleeps == [1, 2]


def test_retry_then_succeed() -> None:
    pypi = FakePyPI()
    url = f"{PYPI}/demo/json"
    pypi.routes[url] = [TimeoutError("slow"), b"not json", b'{"releases": {}}']
    assert pypi.client().get_json(url) == {"releases": {}}
    assert pypi.sleeps == [1, 2]


def test_refuses_non_https(tmp_path: Path) -> None:
    pypi = FakePyPI()
    entry = pypi.file("demo-1.0.tar.gz", b"x")
    entry["url"] = "file:///etc/passwd"
    pypi.release("demo", "1.0", [entry])
    with pytest.raises(FetchError, match="non-https"):
        fetch(PackageSpec(name="demo", version="1.0"), tmp_path, client=pypi.client())


@pytest.mark.parametrize("bad", ["../evil.tar.gz", "a/b.tar.gz", "..tar.gz"])
def test_refuses_unsafe_filename(tmp_path: Path, bad: str) -> None:
    pypi = FakePyPI()
    pypi.release("demo", "1.0", [pypi.file(bad, b"x")])
    with pytest.raises(FetchError, match="unsafe filename"):
        fetch(PackageSpec(name="demo", version="1.0"), tmp_path, client=pypi.client())


# ---------------------------------------------------------------- declared deps (FR-2.5)


def test_declared_deps_markers_and_transitive_chain(tmp_path: Path) -> None:
    pypi = FakePyPI()
    reqs = [
        "dep-a>=1.0,<2",
        "winonly; sys_platform == 'win32'",
        "testdep; extra == 'test'",
        "oldpy; python_version < '3.8'",
        "urldep @ https://example.org/x.whl",
        "missing-dep",
    ]
    pypi.release(
        "app",
        "1.0",
        [pypi.file("app-1.0-py3-none-any.whl", _wheel_bytes(tmp_path, "app", "1.0", reqs))],
    )
    for v in ("0.9", "1.0", "2.0rc1", "3.0"):
        pypi.release(
            "dep-a",
            v,
            [pypi.file(f"dep_a-{v}-py3-none-any.whl", _wheel_bytes(tmp_path, "dep-a", v))],
        )
    pypi.release(
        "dep-a",
        "1.6",
        [pypi.file("dep_a-1.6-py3-none-any.whl", b"yanked", yanked=True)],
    )
    pypi.release(  # newest in range but no sandbox wheel: falls back to 1.5
        "dep-a", "1.7", [pypi.file("dep_a-1.7-cp312-cp312-win_amd64.whl", b"w")]
    )
    a15 = _wheel_bytes(tmp_path, "dep-a", "1.5", ["dep-b==2.0", "app"])  # cycle back to target
    pypi.release("dep-a", "1.5", [pypi.file("dep_a-1.5-py3-none-any.whl", a15)])
    b2 = _wheel_bytes(tmp_path, "dep-b", "2.0", ["dep-a>=0.1; python_version >= '3.10'"])
    pypi.release("dep-b", "2.0", [pypi.file("dep_b-2.0-cp312-cp312-manylinux2014_x86_64.whl", b2)])

    pkg = fetch(
        PackageSpec(name="app", version="1.0"), tmp_path / "dl", client=pypi.client(), now=NOW
    )
    assert pkg.declared_requirements == reqs
    assert [d.filename for d in pkg.declared_deps] == [
        "dep_a-1.5-py3-none-any.whl",
        "dep_b-2.0-cp312-cp312-manylinux2014_x86_64.whl",
    ]
    assert all(Path(d.path).parent == tmp_path / "dl" / "deps" for d in pkg.declared_deps)
    requested = {r.full_url for r in pypi.calls}
    assert f"{PYPI}/winonly/json" not in requested and f"{PYPI}/testdep/json" not in requested


def test_declared_deps_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fetch_mod, "MAX_DEP_WHEELS", 2)
    pypi = FakePyPI()
    pypi.release(
        "app",
        "1.0",
        [pypi.file("app-1.0-py3-none-any.whl", _wheel_bytes(tmp_path, "app", "1.0", ["d1"]))],
    )
    for i in (1, 2, 3):
        w = _wheel_bytes(tmp_path, f"d{i}", "1.0", [f"d{i + 1}"])
        pypi.release(f"d{i}", "1.0", [pypi.file(f"d{i}-1.0-py3-none-any.whl", w)])
    with pytest.raises(FetchError, match="more than 2"):
        fetch(
            PackageSpec(name="app", version="1.0"), tmp_path / "dl", client=pypi.client(), now=NOW
        )


def test_declared_deps_depth_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fetch_mod, "MAX_DEP_DEPTH", 1)
    pypi = FakePyPI()
    pypi.release(
        "app",
        "1.0",
        [pypi.file("app-1.0-py3-none-any.whl", _wheel_bytes(tmp_path, "app", "1.0", ["d1"]))],
    )
    for i in (1, 2):
        w = _wheel_bytes(tmp_path, f"d{i}", "1.0", [f"d{i + 1}"])
        pypi.release(f"d{i}", "1.0", [pypi.file(f"d{i}-1.0-py3-none-any.whl", w)])
    with pytest.raises(FetchError, match="deeper"):
        fetch(
            PackageSpec(name="app", version="1.0"), tmp_path / "dl", client=pypi.client(), now=NOW
        )


def test_read_requires_dist_rejects_bad_wheel(tmp_path: Path) -> None:
    bad = tmp_path / "x-1-py3-none-any.whl"
    bad.write_bytes(b"not a zip")
    with pytest.raises(FetchError):
        read_requires_dist(bad)


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        ("sys_platform == 'linux'", True),
        ('sys_platform == "win32"', False),
        ("python_version >= '3.8' and platform_machine == 'x86_64'", True),
        ("python_version < '3.8' or os_name == 'nt'", False),
        ("(python_version < '3.8' or os_name == 'posix') and extra == ''", True),
        ("extra == 'test'", False),
        ("'3.10' <= python_version", True),
        ("python_full_version != '3.12.*'", False),
        ("'linux' in sys_platform", True),
        ("platform_python_implementation not in 'PyPy Jython'", True),
        ("implementation_name == 'cpython'", True),
    ],
)
def test_evaluate_marker(marker: str, expected: bool) -> None:
    assert evaluate_marker(marker) is expected


@pytest.mark.parametrize(
    "marker", ["unknown_var == 'x'", "python_version >", "os_name == 'a' and", "sys_platform < 'z'"]
)
def test_evaluate_marker_unsure(marker: str) -> None:
    with pytest.raises(ValueError):
        evaluate_marker(marker)


def test_versions_and_specifiers() -> None:
    v = _parse_version
    assert v("1.0") == v("1.0.0") == v("1")
    assert v("1.0") < v("1.0.post1") < v("1.0.1") < v("1.10")  # type: ignore[operator]
    assert v("2.0rc1") is None and v("1!2.0") is None and v("1.0+local") == v("1.0")

    def ok(spec: str, version: str) -> bool:
        parsed = v(version)
        assert parsed is not None
        return all(fetch_mod._clause_ok(op, t, parsed) for op, t in _parse_specifier(spec))

    assert ok(">=1.0,<2", "1.9") and not ok(">=1.0,<2", "2.0")
    assert ok("~=1.4", "1.9") and not ok("~=1.4", "2.0") and not ok("~=1.4.2", "1.5")
    assert ok("==1.4.*", "1.4.7") and not ok("!=1.4.*", "1.4.0")
    assert ok("(>1.0, !=1.5)", "1.6") and not ok(">1.0,!=1.5", "1.5")
    assert ok("", "0.1")
    with pytest.raises(ValueError):
        _parse_specifier(">=1.0 junk")
    with pytest.raises(ValueError):
        ok(">=2.0rc1", "2.0")


def test_parse_requirement() -> None:
    assert parse_requirement("Foo[bar] (>=1.0) ; python_version >= '3'") == ("Foo", [(">=", "1.0")])
    assert parse_requirement("foo; os_name == 'nt'") is None
    with pytest.raises(ValueError):
        parse_requirement("foo @ https://example.org/foo.whl")


# ---------------------------------------------------------------- --artifact (FR-7.1)


def test_from_local_wheel(tmp_path: Path) -> None:
    whl = build_wheel(tmp_path / "src", "my-pkg", "1.2", {"my_pkg/__init__.py": ""}, ["dep>=1"])
    pkg = from_local_artifact(whl, tmp_path / "dl")
    assert pkg.origin == "local_artifact"
    assert str(pkg.spec) == "my_pkg==1.2"
    art = pkg.artifacts[0]
    assert art.kind is ArtifactKind.WHEEL and art.python_tag == "py3"
    assert art.sha256 == hashlib.sha256(whl.read_bytes()).hexdigest()
    assert Path(art.path).parent == tmp_path / "dl"
    assert pkg.declared_requirements == ["dep>=1"] and pkg.declared_deps == []
    assert pkg.metadata.release_date is None and pkg.metadata.version_count is None


def test_from_local_sdist_and_rejects(tmp_path: Path) -> None:
    sd = tmp_path / "my-pkg-0.3.tar.gz"
    sd.write_bytes(b"x")
    pkg = from_local_artifact(sd, tmp_path / "dl")
    assert (pkg.spec.name, pkg.spec.version) == ("my-pkg", "0.3")
    assert pkg.artifacts[0].kind is ArtifactKind.SDIST
    other = tmp_path / "notes.txt"
    other.write_text("x")
    with pytest.raises(FetchError):
        from_local_artifact(other, tmp_path / "dl")
    with pytest.raises(FetchError):
        from_local_artifact(tmp_path / "gone-1.0.tar.gz", tmp_path / "dl")


def test_primary_sha256_without_downloading(tmp_path: Path) -> None:
    from pipguard.fetch import primary_sha256

    pypi = FakePyPI()
    whl = _wheel_bytes(tmp_path, "demo", "1.0")
    pypi.release(
        "demo",
        "1.0",
        [
            pypi.file("demo-1.0-py3-none-any.whl", whl, "2026-01-01T00:00:00Z"),
            pypi.file("demo-1.0.tar.gz", _sdist_bytes(), "2026-01-01T00:00:00Z"),
        ],
    )
    spec = PackageSpec(name="demo", version="1.0")
    assert primary_sha256(spec, client=pypi.client()) == hashlib.sha256(whl).hexdigest()
    pypi.release("empty", "1.0", [])
    with pytest.raises(FetchError):
        primary_sha256(PackageSpec(name="empty", version="1.0"), client=pypi.client())
