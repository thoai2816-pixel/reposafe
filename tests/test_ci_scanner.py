from pathlib import Path
from reposafe.scanners.ci_scanner import CIConfigScanner


def test_ci_detects_pull_request_target(tmp_path: Path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    p = wf / "test.yml"
    p.write_text("on: [pull_request_target]\n")
    s = CIConfigScanner(tmp_path)
    findings = s.run()
    assert any('pull_request_target' in f.message for f in findings)
