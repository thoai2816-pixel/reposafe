from pathlib import Path
from reposafe.scanners.baseline_scanner import BaselineScanner


def test_baseline_missing(tmp_path: Path):
    s = BaselineScanner(tmp_path)
    findings = s.run()
    assert any('missing' in f.message for f in findings)


def test_baseline_detects_risky_and_temp_files(tmp_path: Path):
    (tmp_path / ".env").write_text("TOKEN=demo")
    (tmp_path / "data.sql").write_text("select 1;")
    (tmp_path / "notes.tmp").write_text("temp")
    findings = BaselineScanner(tmp_path).run()
    assert any(f.rule_id == "B002" and f.severity == "HIGH" for f in findings)
    assert any(f.rule_id == "B004" for f in findings)
