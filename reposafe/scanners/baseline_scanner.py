from pathlib import Path
from typing import List
import fnmatch
from ..core import RepoScanner
from ..models import Finding, Severity


DEFAULT_FILES = [
    ('LICENSE', Severity.LOW),
    ('README.md', Severity.LOW),
    ('SECURITY.md', Severity.LOW),
    ('.gitignore', Severity.LOW),
    ('CODE_OF_CONDUCT.md', Severity.LOW),
]


class BaselineScanner(RepoScanner):
    def __init__(self, root: Path):
        super().__init__(root)

    def run(self):
        findings = []
        for name, sev in DEFAULT_FILES:
            p = self.root / name
            if not p.exists():
                findings.append(Finding(scanner='baseline', severity=Severity.LOW, message=f'{name} is missing', rule_id='B001', recommendation=f'Add {name} to the repository as appropriate.'))
            else:
                findings.append(Finding(scanner='baseline', severity=Severity.LOW, message=f'{name} found: {p.name}', file=str(p)))

        # check for risky files
        patterns = ['*.env', '*.pem', '*.key', '*.sql', '*.db', '*.sqlite', '*.zip', '*.tar.gz']
        for p in self.root.rglob('*'):
            if p.is_file():
                for pat in patterns:
                    if fnmatch.fnmatch(p.name.lower(), pat):
                        findings.append(Finding(scanner='baseline', severity=Severity.HIGH, message=f'risky file found: {p.name}', file=str(p), rule_id='B002', recommendation='Remove sensitive or large files and add them to .gitignore; rotate any secrets.'))
        return findings
