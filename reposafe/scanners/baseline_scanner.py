import fnmatch
from pathlib import Path
from typing import List, Optional

from ..core import RepoScanner
from ..models import Finding, Severity
from ..utils import DEFAULT_EXCLUDED_DIRS, is_excluded, read_text, relative_path


REQUIRED_FILES = [
    ("LICENSE", "Add an open-source license so downstream users understand permitted use."),
    ("README.md", "Add a README with project purpose, installation, and basic usage."),
    ("SECURITY.md", "Add a SECURITY.md that explains how to report vulnerabilities responsibly."),
    (".gitignore", "Add .gitignore entries for credentials, build outputs, caches, and local files."),
    ("CODE_OF_CONDUCT.md", "Add a code of conduct for community participation if the project accepts contributions."),
]

HIGH_RISK_PATTERNS = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.kdbx",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
    "*.sql",
]
TEMP_PATTERNS = ["*.tmp", "*.temp", "*.bak", "*.swp", "*~", ".DS_Store"]
ARCHIVE_PATTERNS = ["*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.rar", "*.7z"]
LARGE_FILE_BYTES = 5 * 1024 * 1024


class BaselineScanner(RepoScanner):
    def _make_finding(
        self,
        severity: Severity,
        message: str,
        path: Optional[Path],
        rule_id: str,
        recommendation: str,
        category: str = "baseline",
        confidence: float = 0.85,
    ) -> Finding:
        return Finding(
            scanner="baseline",
            severity=severity,
            message=message,
            file=relative_path(self.root, path) if path else None,
            rule_id=rule_id,
            recommendation=recommendation,
            category=category,
            confidence=confidence,
        )

    def _check_required_files(self) -> List[Finding]:
        findings: List[Finding] = []
        for filename, recommendation in REQUIRED_FILES:
            path = self.root / filename
            if path.exists():
                findings.append(
                    self._make_finding(
                        Severity.INFO,
                        f"{filename} found{self._license_suffix(filename, path)}",
                        path,
                        "B000",
                        "No action required.",
                        category="baseline_present",
                        confidence=1.0,
                    )
                )
            else:
                findings.append(
                    self._make_finding(
                        Severity.LOW,
                        f"{filename} is missing",
                        None,
                        "B001",
                        recommendation,
                        category="missing_baseline_file",
                        confidence=1.0,
                    )
                )
        return findings

    def _license_suffix(self, filename: str, path: Path) -> str:
        if filename != "LICENSE":
            return ""
        text = (read_text(path) or "")[:1200].lower()
        if "mit license" in text:
            return ": MIT"
        if "apache license" in text:
            return ": Apache"
        if "gnu general public license" in text:
            return ": GPL"
        return ""

    def _check_repository_files(self) -> List[Finding]:
        findings: List[Finding] = []
        for path in self.root.rglob("*"):
            if is_excluded(path, DEFAULT_EXCLUDED_DIRS):
                continue
            if not path.is_file():
                continue
            findings.extend(self._check_risky_name(path))
            findings.extend(self._check_large_file(path))
        return findings

    def _check_risky_name(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        name = path.name
        lower_name = name.lower()
        if self._matches(lower_name, HIGH_RISK_PATTERNS):
            findings.append(
                self._make_finding(
                    Severity.HIGH,
                    f"high-risk file should not be committed: {name}",
                    path,
                    "B002",
                    "Remove secrets, database dumps, private keys, and local environment files from git; rotate exposed credentials.",
                    category="risky_file",
                    confidence=0.95,
                )
            )
        elif self._matches(lower_name, ARCHIVE_PATTERNS):
            findings.append(
                self._make_finding(
                    Severity.MEDIUM,
                    f"archive file committed: {name}",
                    path,
                    "B003",
                    "Avoid committing generated archives unless they are release assets with documented provenance.",
                    category="archive_file",
                    confidence=0.75,
                )
            )
        elif self._matches(lower_name, TEMP_PATTERNS):
            findings.append(
                self._make_finding(
                    Severity.LOW,
                    f"temporary or backup file committed: {name}",
                    path,
                    "B004",
                    "Remove temporary files and add matching patterns to .gitignore.",
                    category="temporary_file",
                    confidence=0.8,
                )
            )
        return findings

    def _check_large_file(self, path: Path) -> List[Finding]:
        try:
            size = path.stat().st_size
        except OSError:
            return []
        if size < LARGE_FILE_BYTES:
            return []
        return [
            self._make_finding(
                Severity.MEDIUM,
                f"large file committed: {path.name} ({round(size / 1024 / 1024, 2)} MiB)",
                path,
                "B005",
                "Move large generated artifacts to release storage or Git LFS and keep the repository lightweight.",
                category="large_file",
                confidence=0.9,
            )
        ]

    def _matches(self, name: str, patterns: List[str]) -> bool:
        return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._check_required_files())
        findings.extend(self._check_repository_files())
        return findings
