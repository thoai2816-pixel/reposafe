import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import yaml

from ..core import RepoScanner
from ..models import Finding, Severity
from ..utils import read_text, relative_path


SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
SECURITY_JOB_WORDS = ("security", "sast", "scan", "audit", "secret", "dependency", "deps")
PLAINTEXT_SECRET_WORDS = ("token", "secret", "password", "passwd", "api_key", "apikey", "access_key")


class CIConfigScanner(RepoScanner):
    def _make_finding(
        self,
        severity: Severity,
        message: str,
        path: Path,
        line: Optional[int],
        rule_id: str,
        recommendation: str,
        category: str = "ci_risk",
        confidence: float = 0.85,
    ) -> Finding:
        return Finding(
            scanner="ci",
            severity=severity,
            message=message,
            file=relative_path(self.root, path),
            line=line,
            rule_id=rule_id,
            recommendation=recommendation,
            category=category,
            confidence=confidence,
        )

    def _check_workflow(self, path: Path) -> List[Finding]:
        text = read_text(path) or ""
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            data = {}

        findings: List[Finding] = []
        findings.extend(self._check_triggers(path, text, data))
        findings.extend(self._check_permissions(path, text, data))
        findings.extend(self._check_action_pins(path, text))
        findings.extend(self._check_shell_patterns(path, text))
        findings.extend(self._check_plaintext_env(path, text, data))
        findings.extend(self._check_continue_on_error(path, text, data))
        return findings

    def _check_triggers(self, path: Path, text: str, data: Dict) -> List[Finding]:
        if "pull_request_target" not in text and "pull_request_target" not in str(data.get("on", "")):
            return []
        return [
            self._make_finding(
                Severity.HIGH,
                "workflow uses pull_request_target",
                path,
                self._find_line(text, "pull_request_target"),
                "C001",
                "Use pull_request for untrusted contributions, or tightly restrict pull_request_target jobs and permissions.",
            )
        ]

    def _check_permissions(self, path: Path, text: str, data: Dict) -> List[Finding]:
        findings: List[Finding] = []
        permissions = data.get("permissions")
        if permissions == "write-all" or re.search(r"permissions:\s*write-all", text):
            findings.append(
                self._make_finding(
                    Severity.HIGH,
                    "workflow permissions are set to write-all",
                    path,
                    self._find_line(text, "write-all"),
                    "C002",
                    "Use least-privilege permissions and grant write scopes only to jobs that require them.",
                )
            )
        if isinstance(permissions, dict):
            for scope, value in permissions.items():
                if str(value).lower() == "write":
                    findings.append(
                        self._make_finding(
                            Severity.MEDIUM,
                            f"workflow grants write permission for {scope}",
                            path,
                            self._find_line(text, f"{scope}:"),
                            "C003",
                            "Review write permissions and limit them to the minimum required scope.",
                            confidence=0.7,
                        )
                    )
        return findings

    def _check_action_pins(self, path: Path, text: str) -> List[Finding]:
        findings: List[Finding] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            match = re.search(r"uses:\s*['\"]?([^'\"\s#]+)", line)
            if not match:
                continue
            action_ref = match.group(1)
            if action_ref.startswith("./") or action_ref.startswith("docker://"):
                continue
            if "@" not in action_ref:
                findings.append(
                    self._make_finding(
                        Severity.MEDIUM,
                        f"action is not pinned by commit SHA: {action_ref}",
                        path,
                        line_no,
                        "C004",
                        "Pin third-party actions to a full 40-character commit SHA.",
                        category="unpinned_action",
                    )
                )
                continue
            _, pin = action_ref.rsplit("@", 1)
            if not SHA_PATTERN.fullmatch(pin):
                findings.append(
                    self._make_finding(
                        Severity.MEDIUM,
                        f"action is not pinned by commit SHA: {action_ref}",
                        path,
                        line_no,
                        "C004",
                        "Tags and branches can move; pin third-party actions to a reviewed commit SHA.",
                        category="unpinned_action",
                    )
                )
        return findings

    def _check_shell_patterns(self, path: Path, text: str) -> List[Finding]:
        findings: List[Finding] = []
        patterns = [
            (r"(curl|wget)[^\n|]*\|\s*(bash|sh)", "dangerous shell pattern: curl/wget | shell"),
            (r"bash\s+-c\s+[\"']?\$\(curl", "dangerous shell pattern: bash -c $(curl ...)"),
            (r"chmod\s+\+x\s+.*\n\s*-\s*\./", "downloaded script appears to be made executable and run"),
        ]
        for pattern, message in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                findings.append(
                    self._make_finding(
                        Severity.HIGH,
                        message,
                        path,
                        self._line_from_offset(text, match.start()),
                        "C005",
                        "Avoid executing remote scripts directly; download, verify integrity, then run from a trusted location.",
                        category="dangerous_shell",
                        confidence=0.9,
                    )
                )
        return findings

    def _check_plaintext_env(self, path: Path, text: str, data: Dict) -> List[Finding]:
        findings: List[Finding] = []
        for env_map in self._iter_env_maps(data):
            for key, value in env_map.items():
                key_lower = str(key).lower()
                if not any(word in key_lower for word in PLAINTEXT_SECRET_WORDS):
                    continue
                value_text = str(value)
                if "secrets." in value_text or value_text.startswith("${{"):
                    continue
                findings.append(
                    self._make_finding(
                        Severity.HIGH,
                        f"plaintext sensitive environment variable: {key}",
                        path,
                        self._find_line(text, str(key)),
                        "C006",
                        "Store sensitive values in GitHub Actions secrets and reference them with the secrets context.",
                        category="plaintext_ci_secret",
                    )
                )
        return findings

    def _check_continue_on_error(self, path: Path, text: str, data: Dict) -> List[Finding]:
        findings: List[Finding] = []
        jobs = data.get("jobs", {}) if isinstance(data, dict) else {}
        if not isinstance(jobs, dict):
            if re.search(r"continue-on-error:\s*true", text, re.IGNORECASE):
                findings.append(
                    self._make_finding(
                        Severity.MEDIUM,
                        "continue-on-error true appears in workflow",
                        path,
                        self._find_line(text, "continue-on-error"),
                        "C007",
                        "Do not let security checks fail open.",
                        category="fail_open_security",
                    )
                )
            return findings
        for job_name, job in jobs.items():
            job_blob = str(job)
            job_is_security = any(word in str(job_name).lower() or word in job_blob.lower() for word in SECURITY_JOB_WORDS)
            if job_is_security and "continue-on-error" in job_blob and "True" in job_blob:
                findings.append(
                    self._make_finding(
                        Severity.MEDIUM,
                        f"security-related job {job_name} uses continue-on-error",
                        path,
                        self._find_line(text, "continue-on-error"),
                        "C007",
                        "Security checks should fail the workflow when they detect issues or crash.",
                        category="fail_open_security",
                    )
                )
        return findings

    def _iter_env_maps(self, data: Dict) -> Iterable[Dict]:
        if not isinstance(data, dict):
            return []
        env_maps = []
        if isinstance(data.get("env"), dict):
            env_maps.append(data["env"])
        jobs = data.get("jobs", {})
        if isinstance(jobs, dict):
            for job in jobs.values():
                if isinstance(job, dict) and isinstance(job.get("env"), dict):
                    env_maps.append(job["env"])
                for step in job.get("steps", []) if isinstance(job, dict) else []:
                    if isinstance(step, dict) and isinstance(step.get("env"), dict):
                        env_maps.append(step["env"])
        return env_maps

    def _find_line(self, text: str, needle: str) -> Optional[int]:
        for index, line in enumerate(text.splitlines(), start=1):
            if needle in line:
                return index
        return None

    def _line_from_offset(self, text: str, offset: int) -> int:
        return text[:offset].count("\n") + 1

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        workflow_dir = self.root / ".github" / "workflows"
        if not workflow_dir.exists():
            return findings
        for path in list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")):
            findings.extend(self._check_workflow(path))
        return findings
