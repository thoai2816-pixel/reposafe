from typing import List
from jinja2 import Template
from ..models import Finding

HTML_TMPL = """
<html>
<head><meta charset="utf-8"><title>RepoSafe Report</title></head>
<body>
  <h1>RepoSafe Report</h1>
  <table border="1" cellpadding="6">
    <thead><tr><th>Severity</th><th>Scanner</th><th>Message</th><th>File</th><th>Line</th></tr></thead>
    <tbody>
    {% for f in findings %}
      <tr>
        <td>{{f.severity}}</td>
        <td>{{f.scanner}}</td>
        <td>{{f.message}}</td>
        <td>{{f.file or ''}}</td>
        <td>{{f.line or ''}}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</body>
</html>
"""


class HTMLReporter:
    def __init__(self, out: str = 'report.html'):
        self.out = out

    def report(self, findings: List[Finding]):
        tpl = Template(HTML_TMPL)
        rows = [f.dict() for f in findings]
        with open(self.out, 'w', encoding='utf8') as fh:
            fh.write(tpl.render(findings=rows))
