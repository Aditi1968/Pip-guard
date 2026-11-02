"""Static analysis (FR-3). Fixtures are analysed as text and never executed."""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pipguard import static
from pipguard.errors import PipGuardError
from pipguard.models import (
    Artifact,
    ArtifactKind,
    ArtifactStaticFeatures,
    FetchedPackage,
    ImportCategory,
    PackageMetadata,
    PackageSpec,
    SuspiciousCounts,
)
from pipguard.static import TopPackages, analyze, analyze_dir, typosquat

SHA = "0" * 64
SNAP_DATE = date(2026, 11, 1)


def run(root: Path, kind: ArtifactKind = ArtifactKind.WHEEL) -> ArtifactStaticFeatures:
    return analyze_dir(root, "x.whl", SHA, kind)


def pair(fixtures_dir: Path, name: str) -> tuple[ArtifactStaticFeatures, ArtifactStaticFeatures]:
    base = fixtures_dir / "static" / name
    return run(base / "suspicious"), run(base / "benign")


def src(tmp_path: Path, code: str, fname: str = "mod.py") -> ArtifactStaticFeatures:
    (tmp_path / fname).write_text(code, encoding="utf-8")
    return run(tmp_path)


def counts(**kw: int) -> SuspiciousCounts:
    return SuspiciousCounts(**kw)


# ---------------------------------------------------------------- fixture pairs


def test_cmdclass_pair(fixtures_dir: Path) -> None:
    bad, good = pair(fixtures_dir, "cmdclass")
    assert bad.install.setup_py_cmdclass and bad.install.overridden_install_command
    # setup.py is install-hook code; the override's body too (import inside run()).
    assert bad.risky_import_categories == [ImportCategory.NETWORK, ImportCategory.SUBPROCESS]
    assert bad.risky_import_modules == ["socket", "os.system"]
    assert not good.install.setup_py_cmdclass
    assert not good.install.overridden_install_command


def test_pth_pair(fixtures_dir: Path) -> None:
    bad, good = pair(fixtures_dir, "pth")
    assert bad.install.pth_import_lines
    assert ImportCategory.SUBPROCESS in bad.risky_import_categories
    assert bad.ip_literals == ["203.0.113.7"]
    assert not good.install.pth_import_lines
    assert good.risky_import_categories == []


def test_pep517_backend_only_in_sdist(fixtures_dir: Path) -> None:
    base = fixtures_dir / "static" / "pep517"
    assert run(base / "suspicious", ArtifactKind.SDIST).install.pep517_build_backend
    # Same file in a wheel is not a build-time indicator: wheels are not built.
    assert not run(base / "benign", ArtifactKind.WHEEL).install.pep517_build_backend


def test_exec_b64_pair(fixtures_dir: Path) -> None:
    bad, good = pair(fixtures_dir, "exec_b64")
    assert bad.suspicious == counts(exec=1, b64decode=1)
    # Legitimate decoding is still reported, with the exact count, but nothing else fires.
    assert good.suspicious == counts(b64decode=1)


def test_dynamic_import_pair(fixtures_dir: Path) -> None:
    bad, good = pair(fixtures_dir, "dynamic_import")
    assert bad.suspicious == counts(dynamic_import=2)
    assert good.suspicious == counts()


def test_marshal_pickle_pair(fixtures_dir: Path) -> None:
    bad, good = pair(fixtures_dir, "marshal_pickle")
    assert bad.suspicious == counts(marshal_loads=1, pickle_loads=1)
    assert good.suspicious == counts()


def test_ctypes_pair(fixtures_dir: Path) -> None:
    bad, good = pair(fixtures_dir, "ctypes")
    assert bad.suspicious == counts(ctypes=1)
    assert good.suspicious == counts()


def test_entropy_pair(fixtures_dir: Path) -> None:
    bad, good = pair(fixtures_dir, "entropy")
    assert bad.high_entropy_string_count == 1
    assert bad.max_string_entropy >= static.ENTROPY_THRESHOLD
    assert good.high_entropy_string_count == 0
    assert 0 < good.max_string_entropy < static.ENTROPY_THRESHOLD


def test_network_literals_pair(fixtures_dir: Path) -> None:
    bad, good = pair(fixtures_dir, "network_literals")
    assert bad.urls == ["http://45.33.12.9:8080/beacon", "https://bit.ly/3xYz"]
    assert bad.ip_literals == ["45.33.12.9"]
    assert bad.shortener_urls == ["https://bit.ly/3xYz"]
    assert "bit.ly" in bad.domains
    assert good.urls == ["https://docs.python.org/3/"]
    assert good.domains == ["docs.python.org"]
    assert good.ip_literals == []  # loopback is not a raw-IP indicator
    assert good.shortener_urls == []


def test_risky_imports_pair(fixtures_dir: Path) -> None:
    bad, good = pair(fixtures_dir, "risky_imports")
    assert bad.risky_import_categories == [
        ImportCategory.NETWORK,
        ImportCategory.SUBPROCESS,
        ImportCategory.ENVIRONMENT,
    ]
    assert bad.risky_import_modules == ["socket", "subprocess", "os.environ"]
    # socket and os.environ only inside a function body: nothing at import time.
    assert good.risky_import_categories == []
    assert good.risky_import_modules == []


def test_typosquat_fixture_package(fixtures_dir: Path) -> None:
    root = fixtures_dir / "static" / "typosquat" / "requets"
    art = Artifact(
        filename="requets-1.0-py3-none-any.whl",
        kind=ArtifactKind.WHEEL,
        sha256=SHA,
        size=1,
        path="unused",
        extracted_path=str(root),
    )
    pkg = FetchedPackage(
        spec=PackageSpec(name="requets", version="1.0"),
        artifacts=[art],
        metadata=PackageMetadata(),
        origin="fixture",
    )
    sf = analyze(pkg, snapshot=small_top())
    assert sf.typosquat.fired and sf.typosquat.target == "requests"
    assert sf.artifacts[0].py_file_count == 1
    assert sf.artifacts[0].suspicious == counts()


# ---------------------------------------------------------------- file handling


def test_syntax_error_counted_not_fatal(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "nul.py").write_bytes(b"x = 1\x00\n")
    (tmp_path / "ok.py").write_text("eval('1')\n", encoding="utf-8")
    f = run(tmp_path)
    assert f.py_file_count == 3
    assert f.syntax_error_count == 2
    assert f.suspicious.eval == 1


def test_oversize_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(static, "MAX_FILE_BYTES", 10)
    (tmp_path / "big.py").write_text("exec('x')  # long enough\n", encoding="utf-8")
    (tmp_path / "setup.cfg").write_text("url = http://evil.example.com/\n", encoding="utf-8")
    f = run(tmp_path)
    assert f.syntax_error_count == 1  # oversize .py is counted as unparsed
    assert f.suspicious.exec == 0  # and never read
    assert f.urls == []
    assert f.file_count == 2 and f.total_size > 20


def test_deep_nesting_does_not_crash(tmp_path: Path) -> None:
    f = src(tmp_path, "x = " + "(" * 5000 + "1" + ")" * 5000 + "\n")
    assert f.syntax_error_count == 1


def test_counts_and_compiled_extensions(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "_fast.cpython-312-x86_64-linux-gnu.so").write_bytes(b"\x7fELF")
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    f = run(tmp_path)
    assert f.has_compiled_extensions
    assert (f.file_count, f.py_file_count, f.total_size) == (2, 1, 4)


def test_malformed_pyproject_counted(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[build-system\n", encoding="utf-8")
    f = run(tmp_path, ArtifactKind.SDIST)
    assert f.syntax_error_count == 1
    assert not f.install.pep517_build_backend


def test_missing_dir_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(PipGuardError):
        run(tmp_path / "nope")


def test_analyze_requires_extraction(tmp_path: Path) -> None:
    art = Artifact(filename="a.whl", kind=ArtifactKind.WHEEL, sha256=SHA, size=1, path="a.whl")
    pkg = FetchedPackage(
        spec=PackageSpec(name="a", version="1"), artifacts=[art], metadata=PackageMetadata()
    )
    with pytest.raises(PipGuardError, match="not extracted"):
        analyze(pkg, snapshot=small_top())
    empty = pkg.model_copy(update={"artifacts": []})
    with pytest.raises(PipGuardError):
        analyze(empty, snapshot=small_top())


# ---------------------------------------------------------------- AST details


def test_alias_resolution(tmp_path: Path) -> None:
    f = src(
        tmp_path,
        "import base64 as b\n"
        "from base64 import b64decode as d, urlsafe_b64decode\n"
        "import zlib as z\n"
        "from marshal import loads as ml\n"
        "import builtins\n"
        "b.b64decode('')\nd('')\nurlsafe_b64decode('')\nz.decompress(b'')\nml(b'')\n"
        "builtins.exec('1')\n__builtins__.eval('1')\ncompile('1', 'f', 'exec')\n",
    )
    assert f.suspicious == counts(b64decode=3, zlib_decompress=1, marshal_loads=1, exec=1, eval=1,
                                  compile=1)  # fmt: skip


def test_getattr_indirection(tmp_path: Path) -> None:
    f = src(
        tmp_path,
        "import builtins, base64\n"
        "getattr(builtins, 'exec')('1')\n"
        "getattr(__builtins__, 'eval')\n"
        "getattr(base64, 'b64decode')('')\n"
        "getattr(obj, 'exec')\n"  # unknown owner: not a builtin lookup
        "getattr(builtins, name)\n",  # non-literal: cannot tell
    )
    assert f.suspicious == counts(exec=1, eval=1, b64decode=1)


def test_ctypes_variants_and_literal_import(tmp_path: Path) -> None:
    f = src(
        tmp_path,
        "from ctypes import CDLL\nimport ctypes.util\n__import__('ctypes')\nfrom . import ctypes\n",
    )
    assert f.suspicious == counts(ctypes=3)


def test_risky_contexts(tmp_path: Path) -> None:
    f = src(
        tmp_path,
        "from os import system as sh\nimport os\nimport shutil\n"
        "os.execvp('a', [])\nlambda: os.getenv('X')\nopen('f')\n"
        "class C:\n    x = __import__('getpass')\n"
        "socket = 1\nprint(socket)\n",  # a plain variable named socket is not an import
    )
    assert f.risky_import_categories == [
        ImportCategory.SUBPROCESS,
        ImportCategory.FILESYSTEM,
        ImportCategory.ENVIRONMENT,
    ]
    assert f.risky_import_modules == ["os.system", "shutil", "os.execvp", "open", "getpass"]


def test_setup_py_everything_is_hook_code(tmp_path: Path) -> None:
    f = src(
        tmp_path,
        "import setuptools\n"
        "def helper():\n    import requests\n"
        "setuptools.setup(name='x', cmdclass=None)\n",
        fname="setup.py",
    )
    assert f.risky_import_modules == ["requests"]
    assert not f.install.setup_py_cmdclass


def test_overridden_command_via_module_import(tmp_path: Path) -> None:
    code = "from distutils.command import egg_info\nclass E(egg_info.egg_info):\n    pass\n"
    # Without a root setup.py nothing would run the override (e.g. a meson sdist's
    # vendored code), so it is not an install-time indicator.
    assert not src(tmp_path, code).install.overridden_install_command
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup()\n")
    assert run(tmp_path).install.overridden_install_command


def test_nested_setup_py_is_not_an_install_hook(tmp_path: Path) -> None:
    nested = tmp_path / "pkg-1.0" / "tests" / "examples"
    nested.mkdir(parents=True)
    (nested / "setup.py").write_text("from setuptools import setup\nsetup(cmdclass={'x': 1})\n")
    assert not run(tmp_path).install.setup_py_cmdclass


def test_bytes_and_ipv6_literals(tmp_path: Path) -> None:
    f = src(
        tmp_path,
        "a = b'ftp://files.evil.ru/x'\nb = '2001:db8::1'\nc = '::1'\nd = '0.0.0.0'\n"
        "e = 'pkg.module.py visit evil.xyz'\nf = 'http://[::1'\n",
    )
    assert f.urls == ["ftp://files.evil.ru/x", "http://[::1"]
    assert f.ip_literals == ["2001:db8::1"]
    assert f.domains == ["files.evil.ru", "evil.xyz"]


def test_lists_capped(tmp_path: Path) -> None:
    body = "".join(f"u{i} = 'http://h{i}.example.com/{'a' * 300}'\n" for i in range(80))
    f = src(tmp_path, body)
    assert len(f.urls) == static.MAX_LIST
    assert all(len(u) <= static.MAX_ITEM_CHARS for u in f.urls)


def test_shannon_entropy() -> None:
    assert static.shannon_entropy("") == 0.0
    assert static.shannon_entropy("aaaa") == 0.0
    assert static.shannon_entropy("abcd") == pytest.approx(2.0)


# ---------------------------------------------------------------- fuzzing


@settings(
    max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    name=st.sampled_from(["m.py", "setup.py", "x.pth", "pyproject.toml", "setup.cfg"]),
    data=st.one_of(st.binary(max_size=2000), st.text(max_size=2000).map(str.encode)),
)
def test_analyze_dir_never_raises(tmp_path: Path, name: str, data: bytes) -> None:
    (tmp_path / name).write_bytes(data)
    f = analyze_dir(tmp_path, "x", SHA, ArtifactKind.SDIST)
    assert f.file_count >= 1


# ---------------------------------------------------------------- typosquat (FR-3.6)


def small_top() -> TopPackages:
    # rank 1..: requests is top-100 and top-500; filler pushes "farname" past rank 500.
    names = ["boto3", "requests", "numpy", "Django"]
    names += [f"filler{i}" for i in range(600)]
    names += ["farname"]
    return TopPackages(names=tuple(names), snapshot_date=SNAP_DATE)


@pytest.mark.parametrize(
    ("name", "dist", "target", "fired"),
    [
        ("requets", 1, "requests", True),  # transposition-free deletion
        ("reqeusts", 1, "requests", True),  # transposition: DL counts it as 1
        ("Requests_", 1, "requests", True),  # PEP 503: "requests-"
        ("nmupyy", 2, "numpy", True),  # distance 2 to a top-100 name
        ("django", None, None, False),  # itself (normalised), excluded
        ("farnam", 1, "farname", False),  # distance 1 but rank > 500
        ("completely-different", None, None, False),
    ],
)
def test_typosquat(name: str, dist: int | None, target: str | None, fired: bool) -> None:
    r = typosquat(name, small_top())
    assert (r.distance, r.target, r.fired) == (dist, target, fired)
    assert r.snapshot_date == SNAP_DATE


def test_typosquat_excludes_itself_and_reports_rank() -> None:
    r = typosquat("requests", small_top())
    assert r.target != "requests"
    assert typosquat("requets", small_top()).target_rank == 2


def test_typosquat_prefers_firing_candidate() -> None:
    # The nearest name is low-ranked (no fire) but a farther top-100 name fires: report that.
    top = TopPackages(
        names=("numpy", *(f"f{i}" for i in range(600)), "numpay"), snapshot_date=SNAP_DATE
    )
    r = typosquat("numpai", top)  # numpay: d=1 rank 602 (no fire); numpy: d=2 rank 1 (fires)
    assert (r.target, r.distance, r.fired) == ("numpy", 2, True)


def test_committed_snapshot() -> None:
    raw = json.loads(static.TOP_PACKAGES_PATH.read_text(encoding="utf-8"))
    assert len(raw["names"]) == 5000 == len(set(raw["names"]))
    assert raw["source"].startswith("https://")
    top = static.load_top_packages()
    assert top.snapshot_date == date.fromisoformat(raw["snapshot_date"])
    assert top.rank["requests"] <= 100
    start = time.perf_counter()
    r = typosquat("requets", top)
    assert time.perf_counter() - start < 0.05
    assert r.fired and r.target == "requests"


def test_bad_snapshot(tmp_path: Path) -> None:
    p = tmp_path / "s.json"
    p.write_text("{}", encoding="utf-8")
    with pytest.raises(PipGuardError):
        static.load_top_packages(p)


def test_lan_and_link_local_ips_are_not_raw_ip_indicators() -> None:
    from pipguard.static import _is_raw_ip

    for local in (
        "192.168.1.1",
        "10.0.0.5",
        "172.16.3.4",
        "169.254.169.254",
        "fe80::1",
        "255.255.255.0",
        "::2",
        "100.64.0.1",
    ):
        assert not _is_raw_ip(local), local
    for routable in ("45.33.12.9", "203.0.113.7", "2001:db8::1", "8.8.8.8"):
        assert _is_raw_ip(routable), routable


def test_popular_package_is_not_a_typosquat_of_another() -> None:
    from pipguard.static import TopPackages, typosquat

    top = TopPackages(names=("pip", "requests", "six"), snapshot_date=date(2026, 11, 1))
    r = typosquat("six", top)
    assert r.distance is None and not r.fired
    assert typosquat("requets", top).fired
