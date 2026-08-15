# ADR-0001: 失败分支触发机制与 LLM SQL 判定

- **状态**: 已接受（Accepted）
- **日期**: 2026-08-14
- **作者**: Agent 1 项目组（经 grilling 会话确认）

## 背景 Context

原系统中"失败分支"（`STORY_BRANCHES["failed"]`）的唯一入口是
`AgentOrchestrator._record_failure()`，其触发路径存在严重缺陷：

1. **仅 baseline 分支可触发**：`_record_failure` 只有两个调用点——`execute_task()`
   （死代码，无 handler 注册）和 `terminal_simulator._execute_fix_task()`（修复命令连错3次）。
   recovery / sqli 分支虽然声明了 `fail_next/max_failures`，但**没有任何代码会触发它们**。
2. **实践中几乎不可达**：只有"目标用户正确、权限词写错"的 REVOKE 等特定输入才会计数；
   语法错误、目标写错、恢复命令错误、编辑修复错误均不计数。
3. **计数语义混乱**：`failed_count` 全局累积、跨分支永不清零，阈值错乱；
   `_attempt_counts` 仅在成功时持久化，重启丢失。

目标：让三个分支都能真实、可验证地触发失败，并引入 LangGraph 大模型对终端 SQL
做语法与修复效果判定。

## 决策 Decision

| # | 决策项 | 结论 |
|---|--------|------|
| D1 | 触发范围 | baseline / recovery / sqli **三个分支均可触发失败** |
| D2 | 计数单位 | **1 次"能识别出意图的操作失误" = 1 次失败**；`max_failures` 即分支错误预算（baseline=3, recovery=2, sqli=2） |
| D3 | LLM 权威性 | **LLM 裁决为权威**，确定性 `validate()` 作为兜底降级 |
| D4 | 调用时机 | 仅当**当前分支存在未完成修复任务**时，对**变更类命令**（REVOKE/GRANT/ALTER USER/DROP USER/CREATE USER/SET PASSWORD/DELETE FROM mysql.user）调用 LLM；只读命令（SHOW/SELECT/USE/cat/ls）零成本、不计失败 |
| D5 | 分支机制 | baseline = LLM 判 SQL；recovery / sqli = **确定性规则**（命令失败或违反 SOP 顺序即 1 次失败） |
| D6 | 记账规则 | 见下表"LLM 裁决记账规则" |
| D7 | LLM 输入 | 当前分支全部待修复任务清单 + 当前权限快照 + 学员输入 SQL |
| D8 | 健壮性 | LLM 调用**超时 20s**；任何异常/解析失败 → 记日志后降级到确定性 `validate()`；单次尝试不重试 |
| D9 | LangGraph 形态 | 两节点图 `judge` + `reframe`（JSON 解析失败时重写 prompt 重试 ≤2 次），结构化 JSON 输出；图编译一次全局复用 |
| D10 | 计数生命周期 | **每分支独立计数**；推进下一分支时——若上一分支**未完全修复**则保留其计数（重进时累加），若**完全修复**则清零 |
| D11 | 审计报告 | 新增独立模块"各分支错误次数"，**其余模块保持不变** |

### LLM 裁决记账规则（D6）

| 裁决结果 | 行为 |
|---------|------|
| 语法错误 | **1 次失败** + 展示错误信息，不修改状态 |
| 命中错误点但未修复 | **1 次失败** + 展示反馈 |
| 未命中任何待修复错误点 | 良性操作 + 提示"未命中待修复项"，**不计失败** |
| SQL 本身是安全风险（注入特征等） | 仅安全告警，**不计失败**（攻防演练的"攻击方"路径） |
| 正确修复 | 完成任务，不计失败，重置该任务尝试计数 |

### LangGraph 模型配置（D9 依赖）

对齐 `C:\Users\31779\.claude\settings.json`：

- `base_url`: `https://raytoken.com.cn`
- `api_key`: `webray-key-0e88e21887e47fa8a5fbd9b343e52d5e`
- `model`: `deepseek-v4-flash`
- 接入方式：`langchain_anthropic.ChatAnthropic`（需补装 `langchain-anthropic`）

系统提示词（按需求原文）：「你是一个数据库安全专家，对于用户输入的sql代码进行判断
语法是否错误，是否会存在sql安全问题。」

## 结果 Consequences

**正面**
- 失败分支可被真实触发并验证（三个分支各按 D10 计数）。
- LLM 识别"意图"的能力使学员的常见错误（拼写、目标写错等）也能被正确归类为失败，而非漏计。
- 确定性兜底保证离线/API 抖动时平台不瘫痪。

**代价/风险**
- 新增运行时依赖 `langchain-anthropic`（含 `anthropic` SDK），需 `pip install`。
- 每次修复尝试有最多 20s 的 LLM 往返延迟（降级路径无延迟）。
- 需数据库迁移：`student_state` 增加 `branch_failed_counts`（TEXT JSON）列，兼容旧库。
- LLM 判定存在非确定性，兜底逻辑须与之保持一致（失败按 D2 单次计数，而非旧的"3次=1失败"）。
- `_execute_sql` 的变更类命令路径需重构：LLM 裁决决定"完成哪个任务"，确定性代码决定"如何改权限状态"。

## 关联

- 术语表: [glossary](../../docs/glossary.md)
- 涉及文件: `core/agent_orchestrator.py`, `modules/scenario/terminal_simulator.py`,
  `modules/report/report_generator.py`, `core/database_connector.py`,
  新增 `modules/toolkit/sql_judge.py`, `requirements.txt`
