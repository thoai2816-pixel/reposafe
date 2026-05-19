import typer
from pathlib import Path
from typing import Optional
from .scanners.secrets_scanner import SecretsScanner
from .scanners.dependency_scanner import DependencyScanner
from .scanners.ci_scanner import CIConfigScanner
from .scanners.baseline_scanner import BaselineScanner
from .reporters.console_reporter import ConsoleReporter
from .reporters.json_reporter import JSONReporter
from .reporters.html_reporter import HTMLReporter
from .core import run_scanners

app = typer.Typer(help="RepoSafe — lightweight repo security scanner")
OUTPUT_FORMATS = {"console", "json", "html"}


def _dispatch(path: Path, scanners, out: Optional[str] = None, fmt: Optional[str] = None):
    if not path.exists() or not path.is_dir():
        raise typer.BadParameter(f"repository path does not exist or is not a directory: {path}")
    if fmt and fmt not in OUTPUT_FORMATS:
        raise typer.BadParameter(f"unsupported format {fmt}; choose one of console/json/html")
    findings, metadata = run_scanners(path, scanners)
    ConsoleReporter().report(findings, metadata)
    if fmt == "json" or (fmt is None and out and out.endswith(".json")):
        JSONReporter(out or "report.json").report(findings, metadata)
        typer.echo(f"JSON report written to {out or 'report.json'}")
    if fmt == "html" or (fmt is None and out and out.endswith(".html")):
        HTMLReporter(out or "report.html").report(findings, metadata)
        typer.echo(f"HTML report written to {out or 'report.html'}")


@app.command()
def secrets(path: Path = typer.Argument(..., help="path to repo")):
    _dispatch(path, [SecretsScanner(path)])


@app.command()
def deps(path: Path = typer.Argument(..., help="path to repo")):
    _dispatch(path, [DependencyScanner(path)])


@app.command()
def ci(path: Path = typer.Argument(..., help="path to repo")):
    _dispatch(path, [CIConfigScanner(path)])


@app.command()
def baseline(path: Path = typer.Argument(..., help="path to repo")):
    _dispatch(path, [BaselineScanner(path)])


@app.command()
def scan(path: Path = typer.Argument(..., help="path to repo"),
         format: str = typer.Option('console', '--format', '-f', help='output format: console/json/html'),
         out: Path = typer.Option(None, '--out', '-o', help='output file for JSON/HTML')):
    scanners = [
        SecretsScanner(path),
        DependencyScanner(path),
        CIConfigScanner(path),
        BaselineScanner(path),
    ]
    selected_format = format.lower()
    _dispatch(path, scanners, out=str(out) if out else None, fmt=selected_format if selected_format != 'console' else None)


def main():
    app()


if __name__ == '__main__':
    main()
