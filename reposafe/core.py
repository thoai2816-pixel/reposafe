from pathlib import Path
from typing import List
from .models import Finding


class RepoScanner:
    def __init__(self, root: Path):
        self.root = Path(root)

    def run(self) -> List[Finding]:
        raise NotImplementedError


def run_scanners(root: Path, scanners: List[RepoScanner]):
    findings = []
    for s in scanners:
        try:
            findings.extend(s.run())
        except Exception as e:
            findings.append(Finding(scanner=s.__class__.__name__, severity="LOW", message=f"scanner error: {e}"))
    return findings
