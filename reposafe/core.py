from pathlib import Path
from typing import List, Tuple, Dict, Any
from .models import Finding
from datetime import datetime


class RepoScanner:
    def __init__(self, root: Path):
        self.root = Path(root)

    def run(self) -> List[Finding]:
        raise NotImplementedError


def run_scanners(root: Path, scanners: List[RepoScanner]) -> Tuple[List[Finding], Dict[str, Any]]:
    findings: List[Finding] = []
    for s in scanners:
        try:
            findings.extend(s.run())
        except Exception as e:
            findings.append(Finding(scanner=s.__class__.__name__, severity='LOW', message=f'scanner error: {e}'))

    # build metadata summary
    summary = {"total": len(findings), "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(getattr(f, 'severity', 'LOW')).upper()
        if 'HIGH' in sev:
            summary['high'] += 1
        elif 'MEDIUM' in sev:
            summary['medium'] += 1
        elif 'INFO' in sev:
            summary['info'] += 1
        else:
            summary['low'] += 1

    metadata = {
        'scanned_path': str(Path(root)),
        'scan_time': datetime.utcnow().isoformat() + 'Z',
        'summary': summary,
    }
    return findings, metadata
