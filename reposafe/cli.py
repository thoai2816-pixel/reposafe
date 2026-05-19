import typer
from pathlib import Path
from .scanners.secrets_scanner import SecretsScanner
from .scanners.dependency_scanner import DependencyScanner
from .scanners.ci_scanner import CIConfigScanner
from .scanners.baseline_scanner import BaselineScanner
from .reporters.console_reporter import ConsoleReporter
from .reporters.json_reporter import JSONReporter
from .reporters.html_reporter import HTMLReporter
from .core import run_scanners

app = typer.Typer(help="RepoSafe — lightweight repo security scanner")


def _dispatch(path: Path, scanners, out=None, fmt=None):
    findings = run_scanners(path, scanners)
    ConsoleReporter().report(findings)
    if fmt == "json" or (fmt is None and out and out.endswith('.json')):
        JSONReporter(out).report(findings)
    if fmt == "html" or (fmt is None and out and out.endswith('.html')):
        HTMLReporter(out or 'report.html').report(findings)


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
    _dispatch(path, scanners, out=str(out) if out else None, fmt=format if format != 'console' else None)


def main():
    app()


if __name__ == '__main__':
    main()
