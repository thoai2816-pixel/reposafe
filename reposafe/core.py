from pathlib import Path
from typing import List, Tuple, Dict, Any
from .models import Finding
from datetime import datetime
from time import perf_counter


class RepoScanner:
    def __init__(self, root: Path):
        self.root = Path(root)

    def run(self) -> List[Finding]:
        raise NotImplementedError


def run_scanners(root: Path, scanners: List[RepoScanner]) -> Tuple[List[Finding], Dict[str, Any]]:
    root = Path(root)
    started = perf_counter()
    findings: List[Finding] = []
    scanner_stats: Dict[str, Any] = {}
    for s in scanners:
        scanner_started = perf_counter()
        try:
            scanner_findings = s.run()
            findings.extend(scanner_findings)
            scanner_stats[s.__class__.__name__] = {
                "findings": len(scanner_findings),
                "duration_seconds": round(perf_counter() - scanner_started, 4),
            }
        except Exception as e:
            findings.append(
                Finding(
                    scanner=s.__class__.__name__,
                    severity="LOW",
                    message=f"scanner error: {e}",
                    rule_id="CORE001",
                    recommendation="Check scanner input and report the unexpected error.",
                    category="scanner_error",
                    confidence=1.0,
                )
            )

    findings = sorted(findings, key=lambda item: item.sort_key())
    summary = {"total": len(findings), "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(getattr(f, "severity", "LOW")).upper()
        if "HIGH" in sev:
            summary["high"] += 1
        elif "MEDIUM" in sev:
            summary["medium"] += 1
        elif "INFO" in sev:
            summary["info"] += 1
        else:
            summary["low"] += 1

    metadata = {
        "scanned_path": str(root),
        "scan_time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "summary": summary,
        "scanner_stats": scanner_stats,
        "duration_seconds": round(perf_counter() - started, 4),
    }
    return findings, metadata
