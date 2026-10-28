# 本地多模型免费额度调度器

纯本地运行：调度你在各平台**手动申请**的免费 API 额度，当前模型额度耗尽/限流时自动切换下一家。
**绝不超过免费额度付费**，密钥只保存在私密目录，不向任何第三方上传。
可选：让模型通过**本地安全工具**帮你读文件、列目录、写沙箱文件、运行白名单命令（危险操作需你批准）。

## 一、本地工具调用（可选，默认开启）

模型可以通过 function calling 执行有限的本机操作，**数据安全优先（deny-by-default）**。

### 可用工具（10个）
| 工具 | 行为 | 是否需要批准 |
|---|---|---|
| `list_directory` | 列出白名单目录内容 | 自动执行 |
| `read_file` | 读取白名单内文本文件（密钥自动脱敏） | 自动执行 |
| `search_local_text` | 白名单内按关键词检索文本行（默认最多30条） | 自动执行 |
| `preview_csv` | 预览CSV前N行（默认20行，截断长内容） | 自动执行 |
| `lint_code` | 静态检查 .py 语法（ast.parse，不运行）并提示危险调用 | 自动执行 |
| `scan_project` | 扫描项目文件树 + 函数/类/导入符号统计（轻量代码理解） | 自动执行 |
| `diff_preview` | 对比两个文本文件输出统一diff（审查代码变更） | 自动执行 |
| `write_file` | 在沙箱目录新建/覆盖写入（仅限白名单文本扩展名） | 自动执行 |
| `run_command` | 白名单命令：git status/log -5/diff、python --version、pip list、conda env list | 自动执行 |
| `run_script` | 在**隔离子进程**中运行沙箱目录内 .py 脚本 | **需你批准** |

### 安全模型（重要）
1. **目录白名单**：仅 `read_dirs` 可读、`write_dirs` 可写、`script_dirs` 可运行脚本（默认只允许 `F:\AI` 读取，写入/脚本仅限 `sandbox` 目录）
2. **私密目录硬排除**：`C:\Users\YourName\AI`（密钥所在）任何情况下拒绝访问；`secrets.json/.env/*.pem` 等敏感文件名拒绝
3. **文件类型黑白名单**：白名单文本扩展名（约31种）可读可写；`.exe/.dll/.zip/.docx/.mp4/.pdf` 等二进制/Office/媒体/压缩文件一律拒绝读取
4. **路径防穿越**：realpath 解析 `..` 与符号链接；越界即拒绝
5. **内容脱敏**：文件内容与命令输出中的 API Key/私钥自动替换为 `[已脱敏]` 后才给模型；文件内容视为不可信输入（防提示词注入）
6. **命令白名单 + 危险词拦截**：`curl`、`rm -rf`、`powershell`、`pip install` 等一律拒绝；subprocess 无 shell、带超时、隐藏控制台窗口
7. **人工审批（human-in-the-loop）**：策略为 `approval` 的工具未经批准绝不执行（GUI「本地工具」/「计划任务」页签批准/拒绝；对话输入 `批准执行 op-0001` / `拒绝 op-0001`）；批准操作默认10分钟过期，过期作废；批准后重新执行**全部**安全校验
8. **逐工具策略**：`tool_policies` 可对每个工具单独设为 `auto`（自动）/`approval`（需批准）/`deny`（禁用）
9. **脚本隔离执行**：`run_script` 在独立 Python 子进程（`-I` 隔离模式）中运行，引导代码**禁用网络/子进程/动态库/危险OS操作（`os.system`/`os.remove`/`exec*`/`spawn*` 等）/白名单外模块**，超时自动终止、输出截断（注：非 WASM 级强隔离，是本机场景下的务实安全方案）
10. **迭代上限**：单次对话最多5轮工具调用，防止模型失控循环
11. **全程审计**：安全拦截（越权/危险命令/敏感文件名等）单独写入 `logs\security_audit.log`；常规调用写 `usage.log`
12. **删除/移动/重命名未提供该能力**（故意不提供）

### 配置（config.json → tool_policy）
```json
"tool_policy": {
  "enabled": true,
  "read_dirs": ["F:\\AI"],
  "write_dirs": ["F:\\AI\\local-llm-router\\sandbox"],
  "script_dirs": ["F:\\AI\\local-llm-router\\sandbox"],
  "cwd": "F:\\AI",
  "read_file_max_bytes": 262144,
  "max_output_chars": 20000,
  "exec_timeout": 15,
  "script_timeout": 30,
  "approval_ttl_seconds": 600,
  "allowed_text_extensions": [".txt", ".md", ".py", ".json", ".csv", ".log", ...],
  "blocked_extensions": [".exe", ".dll", ".zip", ".docx", ".pdf", ".mp4", ...],
  "tool_policies": {
    "run_script": "approval",
    "write_file": "auto",
    "run_command": "auto",
    "search_local_text": "auto",
    "preview_csv": "auto",
    "lint_code": "auto"
  },
  "max_search_results": 30,
  "max_csv_preview_rows": 20,
  "max_tool_iterations": 5
}
```
> 建议不要随意扩大 `read_dirs`/`write_dirs`；扩大会放大模型误操作的风险面。

## 二、安全边界（重要）

- ✅ 只调度 `free_only: true` 的模型；`free_only: false` 的模型被硬性锁定，永远不会被调用
- ✅ 本地硬上限：每模型**每日 token、每日调用次数、累计总 token** 三重上限，超限即跳过该模型
- ✅ **软额度预警**：模型今日用量达到上限的80%（可配）时，GUI仪表盘与状态页显示 ⚠️ 提醒，提前留意
- ✅ 余额前置检查：DeepSeek/Kimi/硅基流动等按余额计费平台，余额 ≤ 0 时不调用（fail-closed）；余额查询强制 `https://`（仅本地回环调试放行），防 API Key 明文传输
- ✅ 上下文超窗时自动保留 system 与最近若干条消息截断发送；仍超限才直接拒绝，不发出请求
- ✅ **未配置 Key 硬跳过**：Key 为空、仍是模板占位（含"填入/your/xxxx/example"等字样）或混入非 ASCII 字符时，该平台直接移出候选，不构造请求、不计失败冷却、不联网查余额；状态页明确标注「未配置 Key」，避免把占位 Key 发出后报晦涩编码错误
- ✅ **错误子码保留与分类**：失败摘要完整保留服务端 `code`/`type`/`message`，不被整体截断丢失定性信息；429 区分两类——请求数/速率限流（`limit_requests`、`Throttling.RateQuota`、`rate_limit`）走短冷却约 1 分钟自动恢复，分钟 Token/免费额度类配额（`insufficient_quota`、`AllocationQuota.FreeTierOnly`、`Free allocated quota`）走长冷却；401 鉴权失败直接停用该平台
- ✅ 状态文件 `state.json` 损坏时自动隔离备份为 `state.json.corrupt.<时间戳>` 并以空状态启动，不会反复崩溃
- ✅ 全部免费额度不可用时明确提示，**不自动启用任何付费模型**
- ✅ 只读查询余额/免费额度；**不自动点击领取、不批量注册、不薅福利**（自动领取违反平台协议且有封号风险）
- ✅ 密钥（secrets.json）只放在 `C:\Users\YourName\AI\llm_dispatcher`，代码在 `F:\AI\local-llm-router`
- ✅ 本地工具 deny-by-default：白名单目录 + 私密目录硬排除 + 危险操作人工审批 + 全程审计

## 三、按任务类型选模型（config.json → task_routing）

```json
"task_routing": {
  "default_type": "chat",
  "types": ["chat", "summary", "code", "reasoning", "vision", "planning"],
  "provider_defaults": {
    "zhipu": ["chat", "summary", "code", "reasoning", "vision", "planning"],
    "dashscope": ["chat", "summary", "code", "vision", "planning"],
    "volc_ark": ["chat", "summary", "planning"],
    "siliconflow": ["chat", "summary", "code", "planning"],
    "kimi": ["chat", "summary", "code", "reasoning", "planning"],
    "deepseek": ["chat", "summary", "code", "reasoning", "planning"]
  }
}
```
- 每个模型可标注支持的任务类型（secrets.json 的 provider 条目加 `"task_types": [...]` 可覆盖默认）
- 调度时只从**支持该任务类型**的免费模型里选（加权/冷却/额度判断不变）
- 用法：GUI 对话页「任务类型」下拉；CLI `chat --task code`；Plan 拆解默认走 `planning` 类型
- 任务类型：`chat` 通用问答 / `summary` 摘要 / `code` 编程 / `reasoning` 强推理 / `vision` 视觉 / `planning` 任务规划

## 四、Plan 任务拆解（planner.py）

把复杂任务交给模型拆成步骤清单，**顺序执行本地工具步骤，可断点续跑**：
- 生成：输入任务描述 → 模型输出 JSON 步骤数组（容错解析，非法工具自动过滤）
- 执行：逐步执行；approval 策略的工具（如 run_script）停下等待批准（GUI「计划任务」页签批准/拒绝）
- 持久化：进度存 `C:\Users\YourName\AI\llm_dispatcher\plans.json`（最多20个），**重启后仍可继续**
- CLI：`/plan 任务描述`（生成并执行）、`/plans`（列表）、`/plan-run <id>`（继续）、`/plan-approve <id> [步骤号]`
- GUI：「计划任务」页签

## 五、MCP 协议支持（mcp_server.py）

本地 MCP 服务器（stdio JSON-RPC），让 Claude Desktop / CodeBuddy 等外部 MCP 客户端以标准协议调用本工具集：
```powershell
& C:\Users\YourName\miniconda3\envs\workenv\python.exe F:\AI\local-llm-router\mcp_server.py
```
- 所有工具调用**仍经过 ToolExecutor 安全层**（目录白名单/私密目录硬排除/脱敏/审批策略）
- 协议：newline-delimited JSON over stdio；支持 initialize / notifications/initialized / ping / tools/list / tools/call
- 在客户端里把启动命令注册为 MCP server 即可（如 Claude Desktop → Settings → MCP Servers）

## 六、调度策略（config.json → scheduler）

- `weighted`（默认）：剩余免费额度占比（越大越优先）− 历史延迟惩罚 − 连续失败惩罚；连续失败≥3次再乘 0.5 降权
- `balance_first`：剩余免费额度多的模型优先（等价于 weighted 只算额度）
- `order`：按配置 priority 顺序
- `round_robin`：轮询
- `fastest`：历史响应最快优先

```json
"scheduler": {
  "strategy": "weighted",
  "strict_free_only": true,
  "pre_check_balance": true,
  "balance_cache_ttl": 300,
  "max_attempts_per_request": 6,
  "default_cooldown_seconds": 300,
  "rate_cooldown_seconds": 60,
  "history_turns": 20,
  "warn_threshold_percent": 0.8,
  "weighted": {"quota_weight": 1.0, "latency_weight": 0.4, "error_weight": 1.0},
  "error_penalty": {"enabled": true, "consecutive_threshold": 3, "penalty": 0.5}
}
```

**失败类别与冷却规则**（按服务端 `status_code` + `code`/`type` 子码判定）：

| 类别 | 典型子码 / 状态码 | 处置与冷却 |
| --- | --- | --- |
| `rate` 速率限流 | 429 `limit_requests`、`Throttling.RateQuota`、`rate_limit`、`too many requests` | 短冷却 `rate_cooldown_seconds`（默认 60s），约 1 分钟自动恢复 |
| `quota` 额度/配额不足 | 429 `insufficient_quota`、`AllocationQuota.FreeTierOnly`、`Free allocated quota`；402；余额不足、欠费 | 长冷却 `default_cooldown_seconds`（默认 300s）并切换下一家 |
| `auth` 鉴权失败 | 401 `invalid_api_key`、`authentication_error`、鉴权失败 | 直接停用该平台，不再尝试 |
| `other` 网络/服务端异常 | 500、连接错误等 | 记录错误并切换下一家，不计入额度冷却 |

- `rate_cooldown_seconds`：纯 RPM/请求数限流的冷却时长，默认 60 秒，避免把"等一分钟即恢复"的速率限流误判成额度耗尽而冷却 5 分钟
- 健康状态持久化：失败次数/最近错误类型写入 `state.json`，用于加权排序与GUI展示
- 用量统计：`daily_log` 保留最近7天各模型 token 消耗，供仪表盘趋势图

## 七、响应缓存（可选，默认关闭）

```json
"cache": {"enabled": false, "ttl_seconds": 86400,
          "dir": "C:\\Users\\YourName\\AI\\llm_dispatcher\\cache", "max_entries": 5000}
```
- 完全相同的请求在TTL内命中缓存，**不消耗任何额度**；缓存文件存放在私密目录
- 关闭时缓存逻辑零开销；GUI「本地工具」页签可一键清空

## 八、日志（config.json → logging）

```json
"logging": {"max_bytes": 1048576, "backup_count": 3}
```
- `logs\usage.log`：常规运行日志（按大小轮转，默认1MB×3个备份）
- `logs\security_audit.log`：安全事件专档（越权访问、危险命令、敏感文件名、审批记录等）
- GUI「运行日志」页签实时查看两个日志；「本地工具」页签可导出审计到 sandbox

## 九、GUI（127.0.0.1:7860，仅本机）

| 页签 | 功能 |
|---|---|
| 对话 | 对话（任务类型下拉）+多会话管理（新建/切换/删除/导出）+ 图片输入（需 vision.enabled）+ 保存回复代码块到沙箱 |
| 计划任务 | Plan 任务拆解：生成计划、逐步骤执行、批准/拒绝审批步骤、断点续跑 |
| 本地工具 | 待批准操作审批（批准/拒绝）、安全策略总览、缓存状态/清空、审计导出 |
| 仪表盘 | 免费额度预警 + 未配置 Key 平台横幅、模型状态表（含任务类型、Key 状态）、近7日各模型token消耗趋势图 |
| 额度检查 | 余额/免费额度只读查询 + 主流AI网页免费入口（一键跳转，API收费平台已锁定） |
| 调度状态 | 各模型启用/Key 状态/冷却/停用/任务类型/今日用量/累计用量/失败次数 |
| 配置与自检 | 在线编辑并校验 config.json（保存前自动留 config.json.bak 备份，可回滚）+ 一键自检（Key 配置清单/密钥隔离/写入边界/命令拦截/日志/余额） |
| 运行日志 | usage.log + security_audit.log 实时查看 |

## 目录结构

```
F:\AI\local-llm-router\
├── config.json              # 公开配置：策略、任务路由、工具白名单、缓存、日志、网页免费入口
├── secrets.example.json     # 密钥模板（复制到私密目录后填写）
├── main.py                  # CLI 入口（check/status/chat/gui/selftest，chat 支持 --task）
├── scheduler.py             # 调度核心（任务路由+加权策略+硬上限+预警+缓存+工具调用循环）
├── planner.py               # Plan 任务拆解（生成步骤+顺序执行+断点续跑）
├── codebase.py              # 项目结构索引/符号解析/diff（轻量LSP替代）
├── local_tools.py           # 本地工具安全执行器（deny-by-default+审批+受限脚本沙箱）
├── mcp_server.py            # MCP 服务器（stdio JSON-RPC，复用安全工具层）
├── balance_checker.py       # 余额/免费额度只读检查（deepseek/moonshot/siliconflow）
├── token_counter.py         # 本地 token 估算
├── logger.py                # 分级日志+安全审计+轮转
├── gui.py                   # Gradio 本地界面（8个页签）
├── mock_server.py           # 本地 Mock 服务（测试用）
├── tests\test_scheduler.py  # 调度逻辑验证（9项）
├── tests\test_tools.py      # 工具安全验证（9项）
├── tests\test_extra.py      # 第一轮新增功能验证（13项）
├── tests\test_extra2.py     # 第二轮新增功能验证（13项）
├── tests\test_extra3.py     # 第三轮 Key 状态校验（9项）
├── sandbox\                 # 可写/可运行脚本目录
└── logs\                    # 运行日志（本地）
```

## 安装（conda workenv）

```powershell
& C:\Users\YourName\miniconda3\envs\workenv\python.exe -m pip install -r F:\AI\local-llm-router\requirements.txt
```

## 配置密钥

1. 复制 `secrets.example.json` → `C:\Users\YourName\AI\llm_dispatcher\secrets.json`
2. 填入各平台 API Key（各平台控制台自行申请；secrets.json 请勿放入公开目录）
3. 按需调整 `caps`（每日/累计 token、每日次数上限）与 `enabled`（默认开启的均为免费模型）

## 使用

```powershell
& C:\Users\YourName\miniconda3\envs\workenv\python.exe F:\AI\local-llm-router\main.py check          # 检查各平台余额/免费额度
& C:\Users\YourName\miniconda3\envs\workenv\python.exe F:\AI\local-llm-router\main.py status         # 查看调度状态（含任务类型）
& C:\Users\YourName\miniconda3\envs\workenv\python.exe F:\AI\local-llm-router\main.py chat           # 命令行对话（自动切换模型）
& C:\Users\YourName\miniconda3\envs\workenv\python.exe F:\AI\local-llm-router\main.py chat --task code  # 指定任务类型
& C:\Users\YourName\miniconda3\envs\workenv\python.exe F:\AI\local-llm-router\main.py gui            # 本地网页界面(127.0.0.1:7860)
& C:\Users\YourName\miniconda3\envs\workenv\python.exe F:\AI\local-llm-router\main.py selftest       # Mock 验证（55项测试）
& C:\Users\YourName\miniconda3\envs\workenv\python.exe F:\AI\local-llm-router\mcp_server.py          # 启动MCP服务器（供Claude Desktop等接入）
```

chat 内特殊命令：`/plan 任务描述` 生成并执行计划；`/plans` 列出计划；`/plan-run <id>` 继续执行；`/plan-approve <id> [步骤号]` 批准步骤。

## 各家免费额度现状（2026-10，配置内已附官方链接）

| 平台 | 免费情况 | 余额查询 | 默认 |
|---|---|---|---|
| 智谱 GLM | GLM-4.7-Flash 等 Flash 系列永久免费（限流） | 无API，控制台自查 | 开 |
| 通义千问(百炼) | 新人免费额度自动发放（华北2北京），用完即停 | 无API，控制台自查 | 开 |
| 火山方舟(豆包) | Doubao-Lite 等免费调用额度 | 无API，控制台自查 | 开 |
| 硅基流动 | 部分开源模型免费 | 官方接口 ✓ | 开 |
| Google Gemini | 官方免费tier（gemini-2.5-flash等，每日自动重置，无需绑卡） | 无API，AI Studio自查 | 开 |
| 腾讯混元 | 首次开通自动发放100万token免费资源包（混元-lite永久免费限流） | 无API，控制台自查 | 开 |
| Groq | 免费档每日自动重置限额（llama-3.3-70b等），长期有效 | 无API，控制台自查 | 开 |
| 百度千帆 ERNIE | ERNIE-Speed 系列永久免费（限流） | 无API，控制台自查 | 开 |
| Kimi | 新用户赠送代金券（非免费模型） | 官方接口 ✓ | 关 |
| DeepSeek | 无免费模型，按量付费 | 官方接口 ✓ | 关 |

> 免费 API 额度均为平台**自动按天重置 / 永久免费（限流）**，无需手动领取；超额只会报错限流、不会扣费。
> 说明：OpenAI GPT 与 Claude 的 API **无免费额度**（免费的是各自网页/App产品），调度器锁定不调用，仅提供网页跳转；混元请务必在腾讯云控制台关闭后付费，免费资源包用尽后报错而非扣费。

## 主流AI · 网页免费入口

**API 收费的平台（OpenAI GPT、Anthropic Claude 等）已被调度器硬性锁定、绝不调用**（`free_only: false` 双保险防扣费）；
如果平台提供免费网页版，GUI「额度检查」页签提供一键跳转（列表见 config.json → `web_free_entries`）：

| 平台 | 网页入口 | 说明 |
|---|---|---|
| ChatGPT | https://chatgpt.com/ | 免费账号可用 GPT 系列 |
| Claude | https://claude.ai/ | 免费可用 Claude 系列 |
| Gemini | https://gemini.google.com/ | 免费；另有免费 API 已接入调度器 |
| 腾讯元宝 | https://yuanbao.tencent.com/ | 免费；另有免费 API 已接入调度器 |
| 豆包 | https://www.doubao.com/ | 免费；另有免费 API 已接入调度器 |
| Kimi | https://www.kimi.com/ | 免费网页版 |
| DeepSeek | https://chat.deepseek.com/ | 免费网页版 |
| 通义千问 | https://tongyi.aliyun.com/ | 免费；另有免费 API 已接入调度器 |
| 智谱清言 | https://chatglm.cn/ | 免费；另有免费 API 已接入调度器 |

> 调度器可自动调用（免费 API）：智谱 / 通义 / 豆包(火山) / 硅基 / Gemini / 混元；
> 锁定仅展示（API 收费）：GPT / Claude；按余额启用（默认关）：Kimi / DeepSeek。

## 验证

`python main.py selftest` 启动本地 Mock 服务，共 **55 项测试**：
- 调度逻辑 9 项：正常调用、额度不足自动切换、限流冷却、全部耗尽明确失败、本地硬上限、free_only 硬锁、鉴权失败停用、上下文超窗拒绝、三类余额接口解析
- 工具安全 10 项：白名单读取+密钥脱敏、路径穿越拒绝、私密目录硬排除、敏感文件名拒绝、写入边界、命令白名单/危险命令拒绝、调度器工具流、审批流程、工具调用迭代上限、无扩展名文件默认拒绝
- 第一轮新增 13 项：文件类型黑名单、工具策略 deny/approval、本地文本检索、CSV预览、静态语法检查、软额度预警、累计token上限、加权策略+失败惩罚、响应缓存、用量日志、安全审计日志、命令审批
- 第二轮新增 14 项：任务类型路由、无匹配任务类型、ask单次调用、Plan生成/执行/断点续跑、项目扫描、diff预览、MCP initialize/tools/list、MCP tools/call安全层、受限脚本禁网络/正常执行/禁子进程/禁危险OS操作
- 第三轮 Key 校验 9 项：Key 状态分类、候选过滤未配置平台、全未配置明确提示且不计失败、仅已配置平台发起请求、状态行 Key 状态列展示、429子码分类、chat速率限流短冷却、ask额度不足长冷却、错误摘要保留子错误码

全部通过后再交付。GUI 页面验证：启动后访问 http://127.0.0.1:7860 返回 200。
