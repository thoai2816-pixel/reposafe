
# RepoSafe

RepoSafe：轻量级开源仓库安全体检工具。它面向开源项目维护者、课程实践和安全竞赛申报场景，提供本地化、无网络依赖的仓库安全基线扫描能力。

## 功能概览

- 敏感信息泄露检测（API Key/Token/JWT/私钥片段等）
- 依赖配置风险检测（未固定版本、通配符版本、宽泛版本范围）
- CI / GitHub Actions 风险检测（`pull_request_target`、`curl | bash` 等）
- 开源项目安全基线检测（关键文档缺失、风险文件存在）
- 统一扫描与多格式报告（Console / JSON / HTML）

## 检测能力

| 功能 | 命令 | 典型风险 |
| --- | --- | --- |
| 敏感信息泄露检测 | `reposafe secrets ./repo` | API Key、Token、JWT、私钥片段、云访问密钥、高熵字符串 |
| 依赖配置风险检测 | `reposafe deps ./repo` | 未固定版本、宽泛版本范围、通配符版本、可疑依赖名、dev 依赖暴露 |
| CI 配置风险检测 | `reposafe ci ./repo` | `pull_request_target`、`write-all`、Action 未固定 commit、`curl | bash`、明文环境变量 |
| 安全基线检查 | `reposafe baseline ./repo` | 缺少安全文档、提交 `.env/.pem/.key`、数据库文件、压缩包和临时文件 |
| 统一扫描报告 | `reposafe scan ./repo` | 终端彩色输出、JSON 报告、HTML 报告 |

## Quick Start

1. Create and activate a Python 3.10+ virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies from `requirements.txt`:

```bash
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

3. Run tests:

```bash
pytest -q
```

4. Run RepoSafe (examples):

```bash
python -m reposafe.cli scan ./examples/vulnerable_repo
python -m reposafe.cli scan ./examples/vulnerable_repo --format json --out report.json
python -m reposafe.cli scan ./examples/vulnerable_repo --format html --out report.html
python -m reposafe.cli secrets ./examples/vulnerable_repo
```

如果安装了 editable 包，也可以直接运行：

```bash
reposafe scan ./examples/vulnerable_repo --format html --out report.html
```

## 示例输出

```text
[HIGH] possible github-token found: .env:1
[MEDIUM] flask has a broad version range: >=1.0
[HIGH] workflow uses pull_request_target
[HIGH] high-risk file should not be committed: .env
```

## 演示说明

推荐用于答辩/申报演示的流程：

1. 运行统一扫描并展示终端输出（可看到严重等级、规则 ID、修复建议、路径、行号、统计总览）。
2. 生成 `report.json` 并展示结构化字段（`metadata` + `findings`）。
3. 生成 `report.html` 并展示报告首页（总风险、高中低危分布、扫描路径与时间）。
4. 展示风险详情行（规则 ID + 修复建议 + 文件路径 + 行号）。

常用演示命令：

```bash
python -m reposafe.cli scan ./examples/vulnerable_repo
python -m reposafe.cli scan ./examples/vulnerable_repo --format json --out report.json
python -m reposafe.cli scan ./examples/vulnerable_repo --format html --out report.html
open report.html
```

## 规则说明

RepoSafe 第一版聚焦“配置风险检测”和“开源项目安全体检”，不会联网查询 CVE 数据库，也不会上传代码内容。所有规则在本地执行，输出会保留文件路径、行号、规则 ID、风险等级、脱敏证据和修复建议，便于在申报书中展示“功能介绍、测试情况、使用文档、真实案例和社会价值”。

## 报告截图

> 当前仓库先放置了示意图，便于文档排版；可在你录制演示后用真实截图替换同名文件。

### HTML 报告首页（示意）

![HTML 报告首页示意](docs/images/report-overview.svg)

### 风险详情页（示意）

![HTML 风险详情示意](docs/images/report-detail.svg)

Notes:

- 详细使用说明见 [docs/usage.md](docs/usage.md)。
- 申报书辅助材料见 [docs/application_material.md](docs/application_material.md)。
