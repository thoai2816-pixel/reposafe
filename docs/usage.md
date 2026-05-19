# RepoSafe 使用说明

## 安装

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

## 基础命令

扫描单个功能：

```bash
reposafe secrets ./examples/vulnerable_repo
reposafe deps ./examples/vulnerable_repo
reposafe ci ./examples/vulnerable_repo
reposafe baseline ./examples/vulnerable_repo
```

统一扫描：

```bash
reposafe scan ./examples/vulnerable_repo
reposafe scan ./examples/vulnerable_repo --format json --out report.json
reposafe scan ./examples/vulnerable_repo --format html --out report.html
```

未执行 `pip install -e .` 时，也可以使用 Python 模块方式：

```bash
python -m reposafe.cli scan ./examples/vulnerable_repo --format html --out report.html
```

## 报告字段

每条风险包含：

- `scanner`：扫描器名称，如 `secrets`、`deps`、`ci`、`baseline`
- `severity`：风险等级，支持 `HIGH`、`MEDIUM`、`LOW`、`INFO`
- `rule_id`：规则编号，便于申报材料、截图和测试用例互相对应
- `file` / `line`：风险位置
- `evidence`：脱敏证据，避免报告二次泄露敏感信息
- `recommendation`：修复建议

## 推荐演示流程

1. 运行 `reposafe scan ./examples/vulnerable_repo`，展示彩色终端结果。
2. 运行 `reposafe scan ./examples/vulnerable_repo --format html --out report.html`，展示 HTML 总览和风险详情。
3. 运行 `reposafe scan ./examples/vulnerable_repo --format json --out report.json`，展示结构化报告字段。
4. 运行 `.venv/bin/python -m pytest -q`，展示单元测试全部通过。
