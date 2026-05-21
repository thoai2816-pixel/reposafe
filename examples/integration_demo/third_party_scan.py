"""
Example third-party integration for RepoSafe.

This script simulates another Python application importing RepoSafe as a
library, running the scanners, and consuming structured scan results.
"""

from __future__ import annotations

import json
from pathlib import Path

from reposafe.core import run_scanners
from reposafe.scanners.baseline_scanner import BaselineScanner
from reposafe.scanners.ci_scanner import CIConfigScanner
from reposafe.scanners.dependency_scanner import DependencyScanner
from reposafe.scanners.secrets_scanner import SecretsScanner


def scan_repository(repo_path: Path):
    scanners = [
        SecretsScanner(repo_path),
        DependencyScanner(repo_path),
        CIConfigScanner(repo_path),
        BaselineScanner(repo_path),
    ]
    findings, metadata = run_scanners(repo_path, scanners)
    return findings, metadata


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    target_repo = project_root / "examples" / "vulnerable_repo"

    findings, metadata = scan_repository(target_repo)
    summary = {
        "integration_name": "third_party_scan_demo",
        "target_repo": str(target_repo.relative_to(project_root)),
        "summary": metadata["summary"],
        "top_findings": [
            {
                "severity": finding.severity.value,
                "scanner": finding.scanner,
                "rule_id": finding.rule_id,
                "message": finding.message,
                "file": finding.file,
                "line": finding.line,
            }
            for finding in findings[:8]
        ],
    }

    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
