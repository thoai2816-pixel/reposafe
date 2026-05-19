from pathlib import Path
from typing import List
import json
from ..core import RepoScanner
from ..models import Finding, Severity


class DependencyScanner(RepoScanner):
    def __init__(self, root: Path):
        super().__init__(root)

    def _check_requirements(self, p: Path):
        findings = []
        for line_no, line in enumerate(p.read_text().splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '==' not in line and '>=' not in line and '<=' not in line and '~=' not in line:
                findings.append(Finding(scanner='deps', severity=Severity.MEDIUM, message=f'{line.split("#")[0].strip()} is not pinned to a fixed version', file=str(p), line=line_no, rule_id='D001', recommendation='Pin dependency to a specific version (==).'))
            if '*' in line:
                findings.append(Finding(scanner='deps', severity=Severity.HIGH, message=f'package uses wildcard version: {line}', file=str(p), line=line_no, rule_id='D002', recommendation='Avoid wildcard versions; pin to a stable release.'))
        return findings

    def _check_package_json(self, p: Path):
        findings = []
        try:
            data = json.loads(p.read_text())
        except Exception:
            return findings
        for section in ('dependencies', 'devDependencies'):
            deps = data.get(section, {})
            for name, ver in deps.items():
                if isinstance(ver, str) and ('*' in ver or ver.strip() == ''):
                    findings.append(Finding(scanner='deps', severity=Severity.HIGH, message=f'{name}@{ver} uses wildcard', file=str(p), rule_id='D002', recommendation='Avoid wildcard versions; pin to a stable release.'))
                if isinstance(ver, str) and ('>=' in ver or '<=' in ver or '^' in ver):
                    findings.append(Finding(scanner='deps', severity=Severity.MEDIUM, message=f'{name} has wide version spec: {ver}', file=str(p), rule_id='D001', recommendation='Consider pinning to a specific version for reproducible builds.'))
        return findings

    def run(self):
        findings = []
        for p in self.root.glob('**/requirements.txt'):
            findings.extend(self._check_requirements(p))
        for p in self.root.glob('**/pyproject.toml'):
            # simple heuristic: look for version markers
            text = p.read_text()
            if 'version' in text:
                pass
        for p in self.root.glob('**/package.json'):
            findings.extend(self._check_package_json(p))
        return findings
