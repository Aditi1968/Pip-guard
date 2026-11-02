import tomllib
from pathlib import Path

from demo.build_wheels import build
from pipguard.config import load_config
from pipguard.models import Config, Level
from pipguard.pipeline import ScanOptions, scan_artifact
from pipguard.scoring import RULES_ONLY

DEMO = Path(__file__).parents[1] / "demo"


def test_demo_config_is_valid() -> None:
    cfg = load_config(DEMO / "template" / "pipguard.toml")
    assert cfg.timeouts.import_s == 30
    tomllib.loads((DEMO / "template" / "pipguard.toml").read_text())


def test_planted_wheel_blocks_statically(tmp_path: Path) -> None:
    wheels = build(tmp_path / "wheels")
    planted = next(w for w in wheels if w.name.startswith("requets-"))
    opts = ScanOptions(config=Config(), model=RULES_ONLY, sandbox=False)
    v = scan_artifact(planted, opts, tmp_path / "w").verdict
    # Static alone already blocks on the typosquat; the sandbox adds behavioural reasons.
    assert v.level is Level.BLOCK
    assert any("requests" in r for r in v.reasons)


def test_demo_workflow_is_read_only_and_never_target() -> None:
    wf = (DEMO / "template" / ".github" / "workflows" / "pipguard.yml").read_text()
    assert "pull_request_target" not in wf.replace("never pull_request_target", "")
    assert "continue-on-error: true" not in wf.replace("Never add `continue-on-error: true`", "")
    assert "contents: read" in wf
