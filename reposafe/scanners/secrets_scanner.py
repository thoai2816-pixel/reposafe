import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

from ..core import RepoScanner
from ..models import Finding, Severity
from ..utils import (
    iter_files,
    line_at,
    line_number,
    looks_like_hash,
    parse_key_value,
    read_text,
    redact,
    relative_path,
    shannon_entropy,
)


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    name: str
    pattern: str
    severity: Severity
    recommendation: str
    flags: int = re.MULTILINE


SECRET_RULES = [
    SecretRule(
        "S001",
        "private-key",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----",
        Severity.HIGH,
        "Remove private keys from the repository, rotate affected credentials, and store keys in a secret manager.",
    ),
    SecretRule(
        "S002",
        "github-token",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b",
        Severity.HIGH,
        "Revoke the GitHub token and replace it with a short-lived secret injected by CI.",
    ),
    SecretRule(
        "S003",
        "aws-access-key",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        Severity.HIGH,
        "Disable the AWS access key, rotate the credential pair, and remove it from git history if exposed.",
    ),
    SecretRule(
        "S004",
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        Severity.MEDIUM,
        "Do not commit JWTs; use short-lived tokens and inject them through environment variables.",
    ),
    SecretRule(
        "S005",
        "slack-token",
        r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
        Severity.HIGH,
        "Revoke the Slack token and move bot credentials to a secret store.",
    ),
    SecretRule(
        "S006",
        "generic-assignment",
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[:=]\s*[\"'][^\"'\n]{12,}[\"']",
        Severity.MEDIUM,
        "Review this hard-coded credential-like value and move real secrets out of source control.",
    ),
]

SENSITIVE_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

SECRET_KEYWORDS = {
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "private_key",
    "access_key",
}


class SecretsScanner(RepoScanner):
    def _finding(
        self,
        rule: SecretRule,
        path: Path,
        text: str,
        offset: int,
        value: str,
    ) -> Finding:
        rel = relative_path(self.root, path)
        return Finding(
            scanner="secrets",
            severity=rule.severity,
            message=f"possible {rule.name} found",
            file=rel,
            line=line_number(text, offset),
            rule_id=rule.rule_id,
            recommendation=rule.recommendation,
            category="secret_leak",
            evidence=redact(value),
            confidence=0.9 if rule.severity == Severity.HIGH else 0.75,
        )

    def _scan_regex_rules(self, path: Path, text: str) -> List[Finding]:
        findings: List[Finding] = []
        for rule in SECRET_RULES:
            for match in re.finditer(rule.pattern, text, rule.flags):
                findings.append(self._finding(rule, path, text, match.start(), match.group(0)))
        return findings

    def _scan_high_entropy_assignments(self, path: Path, text: str) -> List[Finding]:
        findings: List[Finding] = []
        for offset, line in self._iter_lines_with_offsets(text):
            parsed = parse_key_value(line)
            if not parsed:
                continue
            key, value = parsed
            normalized_key = key.lower().replace("-", "_")
            if not any(keyword in normalized_key for keyword in SECRET_KEYWORDS):
                continue
            if len(value) < 20 or looks_like_hash(value):
                continue
            entropy = shannon_entropy(value)
            if entropy < 4.0:
                continue
            findings.append(
                Finding(
                    scanner="secrets",
                    severity=Severity.MEDIUM,
                    message=f"high entropy credential-like value assigned to {key}",
                    file=relative_path(self.root, path),
                    line=line_number(text, offset),
                    rule_id="S007",
                    recommendation="Confirm whether the value is a real secret, then move it to a secret manager and rotate it if exposed.",
                    category="high_entropy_secret",
                    evidence=redact(value),
                    confidence=min(0.95, 0.55 + (entropy / 10)),
                    metadata={"entropy": round(entropy, 2), "variable": key},
                )
            )
        return findings

    def _scan_sensitive_filename(self, path: Path) -> List[Finding]:
        lower_name = path.name.lower()
        if lower_name in SENSITIVE_FILENAMES or lower_name.endswith((".pem", ".key", ".p12", ".pfx")):
            return [
                Finding(
                    scanner="secrets",
                    severity=Severity.HIGH,
                    message=f"sensitive credential file committed: {path.name}",
                    file=relative_path(self.root, path),
                    rule_id="S008",
                    recommendation="Remove credential files from git, add them to .gitignore, and rotate any exposed material.",
                    category="secret_file",
                    confidence=0.95,
                )
            ]
        return []

    def _scan_file(self, path: Path) -> List[Finding]:
        findings = self._scan_sensitive_filename(path)
        text = read_text(path)
        if text is None:
            return findings
        findings.extend(self._scan_regex_rules(path, text))
        findings.extend(self._scan_high_entropy_assignments(path, text))
        return findings

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        for path in iter_files(self.root):
            findings.extend(self._scan_file(path))
        return self._deduplicate(findings)

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique: List[Finding] = []
        for finding in findings:
            key = (finding.rule_id, finding.file, finding.line, finding.evidence)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    def _iter_lines_with_offsets(self, text: str):
        offset = 0
        for line in text.splitlines(keepends=True):
            yield offset, line_at(text, offset)
            offset += len(line)
