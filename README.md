
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

