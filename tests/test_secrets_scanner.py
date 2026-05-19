from pathlib import Path
from reposafe.scanners.secrets_scanner import SecretsScanner


def test_secrets_finds_dummy(tmp_path: Path):
    p = tmp_path / "test.txt"
    p.write_text("some text\nghp_ABCDEFGHIJKLMNOPQRSTUVWX1234567890")
    s = SecretsScanner(tmp_path)
    findings = s.run()
    assert any(f.rule_id == "S002" for f in findings)
    assert all("ABCDEFGHIJKLMNOP" not in (f.evidence or "") for f in findings)


def test_secrets_finds_high_entropy_assignment(tmp_path: Path):
    p = tmp_path / "settings.py"
    p.write_text('API_TOKEN = "K8sDemoToken_7z1j9QxP4LmN8RvT2YbC5DfG"\n')
    findings = SecretsScanner(tmp_path).run()
    assert any(f.rule_id == "S006" or f.rule_id == "S007" for f in findings)
