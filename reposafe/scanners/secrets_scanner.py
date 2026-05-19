import re
from pathlib import Path
from typing import List
from ..core import RepoScanner
from ..models import Finding, Severity


SECRET_PATTERNS = [
    (r"-----BEGIN PRIVATE KEY-----.+?-----END PRIVATE KEY-----", Severity.HIGH),
    (r"ghp_[A-Za-z0-9_]{8,}", Severity.HIGH),
    (r"AKIA[0-9A-Z]{16}", Severity.HIGH),
    (r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", Severity.MEDIUM),
    (r"[A-Za-z0-9_/+=]{40,}", Severity.MEDIUM),
]


class SecretsScanner(RepoScanner):
    def __init__(self, root: Path):
        super().__init__(root)

    def _scan_file(self, p: Path) -> List[Finding]:
        findings = []
        try:
            text = p.read_text(errors='ignore')
        except Exception:
            return findings
        for pat, sev in SECRET_PATTERNS:
            for m in re.finditer(pat, text, re.DOTALL):
                line = text[:m.start()].count('\n') + 1
                findings.append(Finding(scanner='secrets', severity=sev, message=f'possible secret match: {m.group(0)[:80]}', file=str(p), line=line, rule_id='S001', recommendation='Remove secret from repo and rotate credentials'))
        return findings

    def run(self):
        findings = []
        for p in self.root.rglob('*'):
            if p.is_file() and p.suffix not in ['.png', '.jpg', '.jpeg', '.gif', '.bin']:
                findings.extend(self._scan_file(p))
        return findings
