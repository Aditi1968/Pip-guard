"""``pipguard`` CLI (FR-7). Thin shell: parse, call the pipeline, print, exit.

Exit codes (FR-7.4): 0 allow/warn, 1 warn with --fail-on-warn, 2 block, 3 error/incomplete.
Any crash inside the CLI itself also exits 3: the gate never fails open.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import typer

from pipguard import SCANNER_VERSION
from pipguard.cache import VerdictCache
from pipguard.config import load_config, parse_config
from pipguard.diff import diff_dependencies, read_files_at
from pipguard.errors import PipGuardError
from pipguard.log import new_correlation_id, setup_logging
from pipguard.models import Config, PackageSpec, ScanReport
from pipguard.pipeline import DEFAULT_IMAGE, ScanOptions, report_for, scan_artifact, scan_spec
from pipguard.pipeline import scan_changes as run_changes
from pipguard.report import exit_code, render_comment, render_summary, write_report_artifact
from pipguard.scoring import load_model

app = typer.Typer(no_args_is_help=True, add_completion=False, help=__doc__)

EXIT_ERROR = 3

ConfigOpt = typer.Option(Path("pipguard.toml"), "--config", help="pipguard.toml path")
ModelOpt = typer.Option(None, "--model", help="model artifact JSON (default: packaged)")
ImageOpt = typer.Option(DEFAULT_IMAGE, "--image", help="sandbox image tag")
FailOnWarnOpt = typer.Option(False, "--fail-on-warn", help="exit 1 when any verdict is warn")


def _fail(msg: str) -> typer.Exit:
    typer.echo(f"error: {msg}", err=True)
    return typer.Exit(EXIT_ERROR)


def _options(config: Path | Config, model: Path | None, **kw: object) -> ScanOptions:
    try:
        cfg = config if isinstance(config, Config) else load_config(config)
        return ScanOptions(config=cfg, model=load_model(model), **kw)  # type: ignore[arg-type]
    except PipGuardError as exc:
        raise _fail(str(exc)) from exc


def _ci_config(config: Path, base: str, head: str, repo: Path) -> tuple[Path | Config, list[str]]:
    """The config that governs a PR is the BASE ref's, never the PR's own.

    Otherwise a PR could set ``watched_files = []``, allowlist its own package or raise the
    thresholds, and pass the check it is meant to face. An absolute ``--config`` outside the
    repository is the operator's explicit choice and is used as given.
    """
    if config.is_absolute():
        return config, []
    rel = config.as_posix()
    try:
        base_text = read_files_at(base, [rel], repo)[rel]
        head_text = read_files_at(head, [rel], repo)[rel]
        cfg = parse_config(base_text, f"{rel}@{base}")
    except PipGuardError as exc:
        raise _fail(str(exc)) from exc
    notes = []
    if base_text != head_text:
        notes.append(f"{rel} changed in this PR; the base branch's version was used for this scan")
    return cfg, notes


def _pretty(report: ScanReport) -> str:
    rows = [f"{'package':<32} {'verdict':<10} reasons"]
    for v in report.verdicts:
        name = str(v.spec) if v.spec else v.raw_spec
        rows.append(f"{name[:32]:<32} {v.level.value:<10} {'; '.join(v.reasons[:3]) or '-'}")
        c = v.coverage
        rows.append(
            f"{'':<32} {'':<10} coverage: fetch {c.fetch}, static {c.static}, "
            f"sandbox {c.sandbox} ({c.sandbox_completeness or '-'})"
        )
    return "\n".join(rows)


@app.command()
def scan(
    spec: str = typer.Argument(None, help="Exact pin, e.g. requests==2.31.0"),
    artifact: Path = typer.Option(None, "--artifact", help="scan a local wheel or sdist"),
    pretty: bool = typer.Option(False, "--pretty", help="human table instead of JSON"),
    no_sandbox: bool = typer.Option(False, "--no-sandbox", help="static analysis only"),
    fail_on_warn: bool = FailOnWarnOpt,
    config: Path = ConfigOpt,
    model: Path = ModelOpt,
    image: str = ImageOpt,
) -> None:
    """Scan one exactly pinned package (or a local artifact) and print the report."""
    setup_logging()
    new_correlation_id()
    if (spec is None) == (artifact is None):
        raise _fail("give exactly one of SPEC or --artifact")
    parsed: PackageSpec | None = None
    if spec is not None:
        try:
            parsed = PackageSpec.parse(spec)
        except ValueError as exc:
            raise _fail(str(exc)) from exc
    # A package the developer asks about by name is one they propose to add (PRD use case 4).
    opts = _options(
        config, model, sandbox=not no_sandbox, image=image, pr_candidate=parsed is not None
    )
    with tempfile.TemporaryDirectory(prefix="pipguard-") as tmp:
        work = Path(tmp)
        result = (
            scan_spec(parsed, opts, work)
            if parsed is not None
            else scan_artifact(artifact, opts, work)
        )
    report = report_for([result])
    typer.echo(_pretty(report) if pretty else report.model_dump_json(indent=2))
    raise typer.Exit(exit_code([result.verdict.level], fail_on_warn=fail_on_warn))


@app.command()
def ci(
    base: str = typer.Option(..., "--base", help="git ref of the PR base"),
    head: str = typer.Option("HEAD", "--head", help="git ref of the PR head"),
    summary: Path = typer.Option(None, "--summary", help="append job-summary Markdown here"),
    report: Path = typer.Option(None, "--report", help="write gzip JSON report here"),
    cache: Path = typer.Option(None, "--cache", help="SQLite verdict cache file"),
    read_only_cache: bool = typer.Option(
        False, "--read-only-cache", help="fork PR: read the cache, never write it"
    ),
    comment_file: Path = typer.Option(None, "--comment-file", help="write PR comment body"),
    local_index: Path = typer.Option(
        None, "--local-index", help="resolve specs from a directory of wheels (demo)"
    ),
    no_sandbox: bool = typer.Option(False, "--no-sandbox", help="static analysis only"),
    repo: Path = typer.Option(Path(), "--repo", help="git repository root"),
    fail_on_warn: bool = FailOnWarnOpt,
    config: Path = ConfigOpt,
    model: Path = ModelOpt,
    image: str = ImageOpt,
) -> None:
    """Diff pinned dependencies between two refs, scan the changes, report (Action mode)."""
    setup_logging()
    new_correlation_id()
    cfg, cfg_notes = _ci_config(config, base, head, repo)
    vcache = VerdictCache(cache) if cache is not None else None
    opts = _options(
        cfg,
        model,
        sandbox=not no_sandbox,
        image=image,
        pr_candidate=True,
        cache=vcache,
        read_only_cache=read_only_cache,
        local_index=local_index,
    )
    try:
        files = opts.config.watched_files
        changes = diff_dependencies(
            read_files_at(base, files, repo), read_files_at(head, files, repo)
        )
    except PipGuardError as exc:
        raise _fail(f"dependency diff failed: {exc}") from exc
    notes = cfg_notes + (["cache is read-only on fork PRs"] if read_only_cache else [])
    with tempfile.TemporaryDirectory(prefix="pipguard-") as tmp:
        result = run_changes(changes, opts, Path(tmp), notes=notes)
    if vcache is not None:
        vcache.close()
    md = render_summary(result, fail_on_warn=fail_on_warn, fork_pr=read_only_cache)
    if summary is not None:
        with summary.open("a", encoding="utf-8") as fh:
            fh.write(md)
    if report is not None:
        write_report_artifact(result, report)
    if comment_file is not None:
        comment_file.write_text(render_comment(result, fail_on_warn=fail_on_warn), encoding="utf-8")
    typer.echo(md)
    raise typer.Exit(exit_code([v.level for v in result.verdicts], fail_on_warn=fail_on_warn))


@app.command()
def explain(
    spec: str = typer.Argument(..., help="Exact pin, e.g. requests==2.31.0"),
    no_sandbox: bool = typer.Option(False, "--no-sandbox", help="static analysis only"),
    config: Path = ConfigOpt,
    model: Path = ModelOpt,
    image: str = ImageOpt,
) -> None:
    """Print the full trace, feature values and rule evaluations for one package (FR-7.3)."""
    from pipguard.rules import build_inputs, evaluate_all, load_rules

    setup_logging()
    new_correlation_id()
    try:
        parsed = PackageSpec.parse(spec)
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    opts = _options(config, model, sandbox=not no_sandbox, image=image, pr_candidate=True)
    with tempfile.TemporaryDirectory(prefix="pipguard-") as tmp:
        result = scan_spec(parsed, opts, Path(tmp))
    out: dict[str, object] = {"verdict": json.loads(result.verdict.model_dump_json())}
    if result.static is not None:
        feats, evidence = build_inputs(result.static, result.trace)
        out["features"] = feats
        out["rules"] = evaluate_all(load_rules(), feats, evidence)  # every rule, fired or not
        out["static"] = json.loads(result.static.model_dump_json())
    out["trace"] = json.loads(result.trace.model_dump_json()) if result.trace else None
    typer.echo(json.dumps(out, indent=2))
    raise typer.Exit(exit_code([result.verdict.level], fail_on_warn=False))


@app.command()
def version() -> None:
    """Print the scanner version."""
    typer.echo(SCANNER_VERSION)


def main() -> None:
    """Console entry point: any uncaught crash exits 3, never 0 or 1."""
    # standalone_mode=False so click usage errors (which exit 2 by default, colliding with
    # "block") are mapped to 3 here instead.
    try:
        rc = app(standalone_mode=False)
    except SystemExit:
        raise
    except BaseException as exc:
        # typer vendors click privately, so usage errors are recognised by their show().
        if callable(show := getattr(exc, "show", None)):
            show()
            raise SystemExit(EXIT_ERROR) from exc
        typer.echo(f"error: pipguard crashed ({type(exc).__name__}): failing closed", err=True)
        raise SystemExit(EXIT_ERROR) from exc
    raise SystemExit(rc if isinstance(rc, int) else 0)
