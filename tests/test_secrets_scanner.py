from pathlib import Path
from reposafe.scanners.secrets_scanner import SecretsScanner


def test_secrets_finds_dummy(tmp_path: Path):
    p = tmp_path / "test.txt"
    p.write_text("some text\nghp_ABCDEFGHIJKLMNOPQRSTUVWX1234567890")
    s = SecretsScanner(tmp_path)
    findings = s.run()
    assert any('ghp_' in f.message or 'ghp_' in (f.file or '') for f in findings)
