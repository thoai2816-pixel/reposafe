import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import tomllib
except ImportError:  # pragma: no cover - Python 3.10 fallback path
    tomllib = None

from ..core import RepoScanner
from ..models import Finding, Severity
from ..utils import read_text, relative_path


PINNED_OPERATORS = ("==", "===")
WIDE_OPERATORS = (">=", "<=", ">", "<", "~=", "!=", "^")
SUSPICIOUS_NAMES = {
    "reqeusts": "requests",
    "requestes": "requests",
    "djagno": "django",
    "flaks": "flask",
    "pyyaml2": "pyyaml",
    "react-domm": "react-dom",
    "lodahs": "lodash",
    "expresss": "express",
}
RISKY_DEV_DEPENDENCIES = {
    "nodemon",
    "ts-node-dev",
    "webpack-dev-server",
    "vite",
    "pytest",
    "debugpy",
}
LOCKFILES = {
    "package.json": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock"),
    "requirements.txt": ("requirements.lock",),
}


class DependencyScanner(RepoScanner):
    def _make_finding(
        self,
        severity: Severity,
        message: str,
        path: Path,
        line: Optional[int],
        rule_id: str,
        recommendation: str,
        category: str = "dependency_risk",
        confidence: float = 0.8,
    ) -> Finding:
        return Finding(
            scanner="deps",
            severity=severity,
            message=message,
            file=relative_path(self.root, path),
            line=line,
            rule_id=rule_id,
            recommendation=recommendation,
            category=category,
            confidence=confidence,
        )

    def _check_requirements(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        text = read_text(path) or ""
        for line_no, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line or line.startswith(("-r ", "--requirement", "--index-url", "--extra-index-url")):
                continue
            if line.startswith(("-e ", "git+", "http://", "https://")):
                findings.append(
                    self._make_finding(
                        Severity.MEDIUM,
                        f"dependency is installed from an external URL or editable source: {line}",
                        path,
                        line_no,
                        "D005",
                        "Prefer registry releases pinned by version and hash for reproducible builds.",
                    )
                )
                continue
            name, spec = self._split_requirement(line)
            if not name:
                continue
            findings.extend(self._check_dependency_spec(path, line_no, name, spec, raw=line))
        findings.extend(self._check_lockfile(path))
        return findings

    def _split_requirement(self, line: str) -> Tuple[str, str]:
        line = line.split(";", 1)[0].strip()
        line = re.sub(r"\[.*?\]", "", line)
        match = re.match(r"([A-Za-z0-9_.-]+)\s*(.*)", line)
        if not match:
            return "", ""
        return match.group(1), match.group(2).strip()

    def _check_package_json(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        text = read_text(path) or "{}"
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return [
                self._make_finding(
                    Severity.LOW,
                    "package.json could not be parsed",
                    path,
                    None,
                    "D000",
                    "Fix JSON syntax so dependency configuration can be reviewed.",
                    confidence=1.0,
                )
            ]

        for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                line = self._find_line(text, name)
                findings.extend(self._check_dependency_spec(path, line, name, str(spec), raw=f"{name}@{spec}"))
                if section == "devDependencies" and name.lower() in RISKY_DEV_DEPENDENCIES:
                    findings.append(
                        self._make_finding(
                            Severity.LOW,
                            f"dev dependency may expose local debug or dev-server behavior: {name}",
                            path,
                            line,
                            "D006",
                            "Keep dev dependencies out of production images and verify build artifacts do not expose debug tooling.",
                            category="dev_dependency_exposure",
                            confidence=0.65,
                        )
                    )

        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for script_name, command in scripts.items():
                if re.search(r"(curl|wget).*\|\s*(bash|sh)", str(command)):
                    findings.append(
                        self._make_finding(
                            Severity.HIGH,
                            f"npm script {script_name} pipes remote content to shell",
                            path,
                            self._find_line(text, script_name),
                            "D007",
                            "Avoid curl/wget pipe-to-shell install scripts; verify downloaded content before execution.",
                            category="install_script_risk",
                            confidence=0.9,
                        )
                    )
        findings.extend(self._check_lockfile(path))
        return findings

    def _check_pyproject(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        text = read_text(path) or ""
        data = {}
        if tomllib is not None:
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                data = {}
        dependencies = self._pyproject_dependencies(data)
        if not dependencies and text:
            dependencies = re.findall(r"^[ \t]*[\"']([^\"']+)[\"'],?\s*$", text, flags=re.MULTILINE)
        for dep in dependencies:
            name, spec = self._split_requirement(dep)
            if name:
                findings.extend(self._check_dependency_spec(path, self._find_line(text, dep), name, spec, raw=dep))
        findings.extend(self._check_lockfile(path))
        return findings

    def _pyproject_dependencies(self, data: Dict) -> Iterable[str]:
        project = data.get("project", {}) if isinstance(data, dict) else {}
        deps = list(project.get("dependencies", []) or [])
        optional = project.get("optional-dependencies", {}) or {}
        for values in optional.values():
            deps.extend(values or [])
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) if isinstance(data, dict) else {}
        for name, spec in poetry_deps.items():
            if name.lower() != "python":
                deps.append(f"{name}{spec if isinstance(spec, str) else ''}")
        return deps

    def _check_dependency_spec(self, path: Path, line: Optional[int], name: str, spec: str, raw: str) -> List[Finding]:
        findings: List[Finding] = []
        normalized = name.lower().replace("_", "-")
        if normalized in SUSPICIOUS_NAMES:
            findings.append(
                self._make_finding(
                    Severity.MEDIUM,
                    f"suspicious dependency name {name}; did you mean {SUSPICIOUS_NAMES[normalized]}?",
                    path,
                    line,
                    "D004",
                    "Review dependency names carefully to reduce typosquatting risk.",
                    category="typosquatting",
                    confidence=0.75,
                )
            )
        if not spec:
            findings.append(
                self._make_finding(
                    Severity.MEDIUM,
                    f"{name} is not pinned to a fixed version",
                    path,
                    line,
                    "D001",
                    "Pin dependencies to exact versions for reproducible security review.",
                )
            )
            return findings
        if "*" in spec or spec.strip() in {"latest", ""}:
            findings.append(
                self._make_finding(
                    Severity.HIGH,
                    f"package uses wildcard version: {raw}",
                    path,
                    line,
                    "D002",
                    "Avoid wildcard or latest versions; pin to a stable release.",
                )
            )
        elif not spec.startswith(PINNED_OPERATORS):
            if spec.startswith(WIDE_OPERATORS) or any(op in spec for op in WIDE_OPERATORS):
                findings.append(
                    self._make_finding(
                        Severity.MEDIUM,
                        f"{name} has a broad version range: {spec}",
                        path,
                        line,
                        "D003",
                        "Use exact versions or a lockfile-backed workflow for deterministic builds.",
                    )
                )
            elif re.match(r"^[0-9]+(?:\.[0-9]+)*$", spec):
                return findings
            else:
                findings.append(
                    self._make_finding(
                        Severity.MEDIUM,
                        f"{name} is not pinned to a fixed version",
                        path,
                        line,
                        "D001",
                        "Pin dependencies to exact versions for reproducible security review.",
                    )
                )
        return findings

    def _check_lockfile(self, manifest: Path) -> List[Finding]:
        expected = LOCKFILES.get(manifest.name)
        if not expected:
            return []
        if any((manifest.parent / name).exists() for name in expected):
            return []
        return [
            self._make_finding(
                Severity.LOW,
                f"{manifest.name} has no recognized lockfile nearby",
                manifest,
                None,
                "D008",
                "Commit a lockfile when the package manager supports it so dependency resolution is reproducible.",
                category="missing_lockfile",
                confidence=0.7,
            )
        ]

    def _find_line(self, text: str, needle: str) -> Optional[int]:
        if not needle:
            return None
        for index, line in enumerate(text.splitlines(), start=1):
            if needle in line:
                return index
        return None

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        for path in self.root.glob("**/requirements.txt"):
            findings.extend(self._check_requirements(path))
        for path in self.root.glob("**/package.json"):
            findings.extend(self._check_package_json(path))
        for path in self.root.glob("**/pyproject.toml"):
            findings.extend(self._check_pyproject(path))
        return findings
