# RepoSafe 申报书辅助材料

## 一、项目名称

RepoSafe：轻量级开源仓库安全体检工具

## 二、项目定位

RepoSafe 面向开源项目维护者和安全初学者，提供一套可在本地执行的仓库安全体检能力。项目不依赖外部云服务，不上传源代码，适合在教学、社团实践、开源项目发布前检查和安全奖励计划申报中展示。

## 三、核心功能

1. 敏感信息泄露检测：识别 GitHub Token、AWS Access Key、JWT、私钥片段、常见 secret 变量赋值和高熵字符串，并对证据脱敏。
2. 依赖配置风险检测：检查 `requirements.txt`、`package.json`、`pyproject.toml` 中未固定版本、宽泛版本、通配符版本、可疑依赖名、缺少 lockfile 和 dev 依赖暴露风险。
3. CI 配置风险检测：检查 GitHub Actions 中的 `pull_request_target`、`permissions: write-all`、未固定 commit SHA 的 action、`curl | bash`、明文环境变量和安全任务 fail-open 配置。
4. 开源项目安全基线检查：检查 `LICENSE`、`README.md`、`SECURITY.md`、`.gitignore`、`CODE_OF_CONDUCT.md`，并识别 `.env`、`.pem`、`.key`、数据库文件、压缩包、临时文件和大文件。
5. 统一扫描与报告生成：提供 `reposafe scan` 统一入口，支持彩色终端输出、JSON 报告和 HTML 报告。

## 四、创新点和实用价值

- 规则覆盖开源仓库最常见的真实风险，不只检查源码，也检查依赖和 CI 配置。
- 报告包含规则 ID、置信度、脱敏证据、文件路径、行号和修复建议，便于定位和整改。
- 完全本地运行，不需要联网查询漏洞库，适合对私有仓库或未公开课程项目进行预检查。
- 示例仓库内置多类可控风险，便于答辩截图、课堂演示和回归测试。

## 五、真实引用案例

项目已提供 `examples/integration_demo` 示例程序，用于演示第三方 Python 程序如何调用 RepoSafe 的扫描能力。该示例不通过命令行启动 RepoSafe，而是直接导入 `run_scanners`、`SecretsScanner`、`DependencyScanner`、`CIConfigScanner` 和 `BaselineScanner`，对 `examples/vulnerable_repo` 进行安全检查，并输出结构化扫描结果。

运行命令如下：

```bash
.venv/bin/python examples/integration_demo/third_party_scan.py
```

示例输出包含 `integration_name`、`target_repo`、`summary` 和 `top_findings` 等字段，能够被其他 Python 程序、教学评测系统、CI 质量门禁或安全平台继续读取和处理。该示例验证了 RepoSafe 不仅可以作为独立命令行工具使用，也具备被其他软件引用、依赖和集成的能力。

## 六、测试情况

当前测试覆盖四类核心扫描器：

- `test_secrets_scanner.py`：验证 GitHub Token 和高熵 secret 识别。
- `test_dependency_scanner.py`：验证未固定版本、宽泛版本、通配符版本和危险安装脚本识别。
- `test_ci_scanner.py`：验证 `pull_request_target`、未固定 action、明文 env、`curl | bash` 和 `continue-on-error` 识别。
- `test_baseline_scanner.py`：验证基线文件缺失、高风险文件和临时文件识别。

测试命令：

```bash
.venv/bin/python -m pytest -q
```

本次验证结果：`8 passed in 0.12s`。

## 七、代码规模

当前 `reposafe/*.py` 业务代码约 1500 行，主要集中在四类扫描器、统一调度、数据模型、报告生成和工具函数。若按申报模板中“不少于 2000 行且不含注释和空行”的版本提交，建议继续扩展规则库、SARIF 报告、配置文件支持和批量仓库扫描功能。

## 八、推荐截图清单

- 终端执行 `reposafe scan ./examples/vulnerable_repo` 的彩色输出。
- `report.html` 首页，展示总风险和高/中/低危统计。
- HTML 风险详情展开区域，展示规则 ID、类别、置信度、脱敏证据和修复建议。
- `report.json` 结构化报告字段。
- `examples/integration_demo/third_party_scan.py` 运行结果，展示第三方程序引用 RepoSafe 的真实案例。
- `tests/` 目录和 `.venv/bin/python -m pytest -q` 通过结果。
- GitHub 仓库目录结构，展示 `reposafe/`、`tests/`、`examples/`、`docs/`。

## 九、可写入申报书的简短描述

RepoSafe 是一款轻量级开源仓库安全体检工具，围绕敏感信息泄露、依赖配置、GitHub Actions/CI 配置和开源项目安全基线四类风险提供本地扫描能力。工具支持统一命令行入口和彩色终端、JSON、HTML 三种报告格式，能够输出风险等级、规则 ID、文件路径、行号、脱敏证据和修复建议。项目可帮助开源项目维护者在代码公开或版本发布前发现常见安全问题，降低密钥泄露、供应链配置缺陷和 CI 权限滥用风险。
