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


def test_ci_detects_unpinned_action_and_plaintext_env(tmp_path: Path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    p = wf / "security.yml"
    p.write_text(
        "name: ci\n"
        "on: [push]\n"
        "env:\n  API_TOKEN: plain-token\n"
        "jobs:\n"
        "  security:\n"
        "    runs-on: ubuntu-latest\n"
        "    continue-on-error: true\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: curl https://example.test/install.sh | bash\n"
    )
    findings = CIConfigScanner(tmp_path).run()
    assert any(f.rule_id == "C004" for f in findings)
    assert any(f.rule_id == "C005" for f in findings)
    assert any(f.rule_id == "C006" for f in findings)
    assert any(f.rule_id == "C007" for f in findings)
