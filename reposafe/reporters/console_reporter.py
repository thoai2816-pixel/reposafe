from typing import List
from rich.console import Console
from rich.table import Table
from ..models import Finding


class ConsoleReporter:
    def __init__(self):
        self.console = Console()

    def report(self, findings: List[Finding]):
        if not findings:
            self.console.print("[green]No issues found.[/green]")
            return
        table = Table(title="RepoSafe Findings")
        table.add_column("Severity")
        table.add_column("Scanner")
        table.add_column("Message")
        table.add_column("File")
        table.add_column("Line")
        for f in findings:
            table.add_row(f.severity.value if hasattr(f.severity, 'value') else str(f.severity), f.scanner, f.message, f.file or '-', str(f.line or '-'))
        self.console.print(table)
