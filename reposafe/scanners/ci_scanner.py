from pathlib import Path
from typing import List
import yaml
import re
from ..core import RepoScanner
from ..models import Finding, Severity


class CIConfigScanner(RepoScanner):
    def __init__(self, root: Path):
        super().__init__(root)

    def _check_workflow(self, p: Path) -> List[Finding]:
        findings = []
        try:
            data = yaml.safe_load(p.read_text()) or {}
        except Exception:
            return findings
        # robustly detect pull_request_target whether YAML parsed as list or other form
        text = p.read_text()
        if 'pull_request_target' in text or 'pull_request_target' in str(data.get('on')):
            findings.append(Finding(scanner='ci', severity=Severity.HIGH, message='workflow uses pull_request_target', file=str(p)))
        perms = data.get('permissions')
        if perms and perms == 'write-all':
            findings.append(Finding(scanner='ci', severity=Severity.HIGH, message='permissions set to write-all', file=str(p)))
        # find unpinned actions by searching for uses: owner/repo
        # text already read above
        for m in re.finditer(r"uses:\s*([\w\-/.]+)(@([\w\-:.]+))?", text):
            full = m.group(0)
            pin = m.group(3)
            if not pin or not re.match(r'[0-9a-f]{7,}|v[0-9]+', pin):
                findings.append(Finding(scanner='ci', severity=Severity.MEDIUM, message='action is not pinned by commit SHA or stable tag', file=str(p)))
        if re.search(r"curl\s*\|\s*bash", text):
            findings.append(Finding(scanner='ci', severity=Severity.HIGH, message='dangerous shell pattern: curl | bash', file=str(p)))
        if re.search(r"continue-on-error:\s*true", text, re.I):
            findings.append(Finding(scanner='ci', severity=Severity.MEDIUM, message='continue-on-error true in workflow', file=str(p)))
        return findings

    def run(self):
        findings = []
        for p in self.root.rglob('*.yml'):
            if '.github/workflows' in str(p):
                findings.extend(self._check_workflow(p))
        for p in self.root.rglob('*.yaml'):
            if '.github/workflows' in str(p):
                findings.extend(self._check_workflow(p))
        return findings
