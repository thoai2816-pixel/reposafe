from pathlib import Path
from reposafe.scanners.dependency_scanner import DependencyScanner


def test_deps_detects_requirements(tmp_path: Path):
    p = tmp_path / "requirements.txt"
    p.write_text("requests\nflask>=1.0\npackage==1.2.3\n")
    s = DependencyScanner(tmp_path)
    findings = s.run()
    assert any('requests' in f.message or 'requests' in (f.file or '') for f in findings)
