from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from ..models import Finding


SEVERITY_STYLE = {
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim cyan",
}


class ConsoleReporter:
    def __init__(self):
        self.console = Console()

    def report(self, findings: List[Finding], metadata: Dict[str, Any] = None):
        if not findings:
            self.console.print("[green]No issues found.[/green]")
            return
        if metadata:
            summary = metadata.get('summary', {})
            self.console.print(
                Panel(
                    f"Path: {metadata.get('scanned_path')}\n"
                    f"Total: {summary.get('total', 0)}  "
                    f"High: {summary.get('high', 0)}  Medium: {summary.get('medium', 0)}  "
                    f"Low: {summary.get('low', 0)}  Info: {summary.get('info', 0)}\n"
                    f"Duration: {metadata.get('duration_seconds', 0)}s  Time: {metadata.get('scan_time')}",
                    title="RepoSafe Summary",
                    border_style="cyan",
                )
            )
        table = Table(title="RepoSafe Findings", show_lines=False)
        table.add_column("严重等级")
        table.add_column("扫描器")
        table.add_column("详情")
        table.add_column("文件")
        table.add_column("行号")
        table.add_column("规则ID")
        table.add_column("修复建议")
        for f in findings:
            sev = getattr(f.severity, 'value', str(f.severity))
            table.add_row(
                f"[{SEVERITY_STYLE.get(sev, '')}]{sev}[/]",
                f.scanner,
                f.message,
                f.file or '-',
                str(f.line or '-'),
                f.rule_id or '-',
                f.recommendation or '-',
            )
        self.console.print(table)
