from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from ..models import Finding


class ConsoleReporter:
    def __init__(self):
        self.console = Console()

    def report(self, findings: List[Finding], metadata: Dict[str, Any] = None):
        if not findings:
            self.console.print("[green]No issues found.[/green]")
            return
        table = Table(title="RepoSafe Findings")
        table.add_column("严重等级")
        table.add_column("扫描器")
        table.add_column("详情")
        table.add_column("文件")
        table.add_column("行号")
        table.add_column("规则ID")
        table.add_column("修复建议")
        for f in findings:
            sev = getattr(f.severity, 'value', str(f.severity))
            table.add_row(sev, f.scanner, f.message, f.file or '-', str(f.line or '-'), f.rule_id or '-', f.recommendation or '-')
        self.console.print(table)
        if metadata:
            summary = metadata.get('summary', {})
            self.console.print(f"扫描路径: {metadata.get('scanned_path')}  扫描时间: {metadata.get('scan_time')}")
            self.console.print(f"总计: {summary.get('total',0)} 高:{summary.get('high',0)} 中:{summary.get('medium',0)} 低:{summary.get('low',0)} 信息:{summary.get('info',0)}")
