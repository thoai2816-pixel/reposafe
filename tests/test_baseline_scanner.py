from pathlib import Path
from reposafe.scanners.baseline_scanner import BaselineScanner


def test_baseline_missing(tmp_path: Path):
    s = BaselineScanner(tmp_path)
    findings = s.run()
    assert any('missing' in f.message for f in findings)
