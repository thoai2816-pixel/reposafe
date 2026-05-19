import json
from typing import List
from ..models import Finding


class JSONReporter:
    def __init__(self, out: str = 'report.json'):
        self.out = out

    def report(self, findings: List[Finding]):
        data = [f.dict() for f in findings]
        with open(self.out, 'w', encoding='utf8') as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
