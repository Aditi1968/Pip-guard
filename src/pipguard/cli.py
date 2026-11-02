"""``pipguard`` CLI (FR-7). Thin shell: parse, call stages, print, exit."""

from __future__ import annotations

import typer

from pipguard.models import PackageSpec

app = typer.Typer(no_args_is_help=True, add_completion=False, help=__doc__)

EXIT_ERROR = 3


@app.command()
def scan(
    spec: str = typer.Argument(..., help="Exact pin, e.g. requests==2.31.0"),
) -> None:
    """Scan one exactly pinned package."""
    try:
        PackageSpec.parse(spec)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR) from exc
    # Fail closed until the pipeline is wired: an unexamined package never passes.
    typer.echo("error: pipeline not implemented yet", err=True)
    raise typer.Exit(EXIT_ERROR)


@app.command()
def version() -> None:
    """Print the scanner version."""
    from pipguard import SCANNER_VERSION

    typer.echo(SCANNER_VERSION)
