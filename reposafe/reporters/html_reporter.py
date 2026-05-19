from typing import List
from jinja2 import Template
from ..models import Finding

HTML_TMPL = """
<html>
<head>
  <meta charset="utf-8">
  <title>RepoSafe 报告</title>
  <style>
    body{font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial;}
    table{border-collapse: collapse; width: 100%;}
    th, td{border: 1px solid #ddd; padding: 8px;}
    th{background: #f7f7f7;}
    .high{background:#ffe6e6}
    .medium{background:#fff4e6}
    .low{background:#eef7ff}
  </style>
</head>
<body>
  <h1>RepoSafe 安全扫描报告</h1>
  <p>扫描路径: {{scanned_path}} &nbsp; 扫描时间: {{scan_time}}</p>
  <p>总发现: {{summary.total}}；高: {{summary.high}}，中: {{summary.medium}}，低: {{summary.low}}，信息: {{summary.info}}</p>
  <table>
    <thead>
      <tr><th>严重等级</th><th>扫描器</th><th>详情</th><th>文件</th><th>行号</th></tr>
    </thead>
    <tbody>
    {% for f in findings %}
      <tr class="{{f.severity_class}}">
        <td>{{f.severity_cn}}</td>
        <td>{{f.scanner}}</td>
        <td>
          <div>{{f.message}}</div>
          <div><strong>规则：</strong>{{f.rule_id or ''}} &nbsp; <strong>修复建议：</strong>{{f.recommendation or ''}}</div>
        </td>
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

    def _map_severity(self, sev):
        # Accept either Severity enum or string
        s = str(sev)
        if s.upper().endswith('HIGH') or 'HIGH' in s.upper():
            return ('高', 'high')
        if s.upper().endswith('MEDIUM') or 'MEDIUM' in s.upper():
            return ('中', 'medium')
        return ('低', 'low')

    def report(self, findings: List[Finding]):
        rows = []
        summary = {'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0}
        for f in findings:
          sev_cn, sev_class = self._map_severity(getattr(f, 'severity', 'LOW'))
          rows.append({
            'severity': str(getattr(f, 'severity', 'LOW')),
            'severity_cn': sev_cn,
            'severity_class': sev_class,
            'scanner': f.scanner,
            'message': f.message,
            'file': f.file,
            'line': f.line,
            'rule_id': f.rule_id,
            'recommendation': f.recommendation,
          })
          summary[sev_class] += 1
          summary['total'] += 1

        tpl = Template(HTML_TMPL)
        with open(self.out, 'w', encoding='utf8') as fh:
          fh.write(tpl.render(findings=rows, summary=summary, scan_time=metadata.get('scan_time') if metadata else '', scanned_path=metadata.get('scanned_path') if metadata else ''))
