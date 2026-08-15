# 术语表 Glossary

本项目（Agent 1 数据库安全运维智能体）涉及的核心术语定义，供文档与代码对照。

## 故事线 / 分支

| 术语 | 英文 | 定义 |
|------|------|------|
| 故事线 | Storyline | 学员从决策到完成审计报告的整体任务流程，由 `STORY_BRANCHES` 状态机驱动。 |
| 分支 | Branch | 故事线中的一条任务线。含 `start`、`baseline`（安全基线）、`recovery`（备份恢复）、`sqli`（SQL注入攻防）、`final_report`、`failed`。 |
| 失败分支 | Failed branch | 分支 `failed`（"运维事故升级"）。当某分支累计操作失误达到其 `max_failures` 阈值时进入，`story_phase = "failed"`。 |
| 错误预算 | Max failures | 分支属性 `max_failures`：该分支允许的最大操作失误次数（baseline=3, recovery=2, sqli=2）。达到即触发失败分支。 |
| 分支推进 | Advance | 完成当前分支全部任务后自动进入 `success_next` 分支，或通过决策按钮跳转到其他分支。 |

## 任务与错误点

| 术语 | 英文 | 定义 |
|------|------|------|
| 修复任务 | Fix task | 终端中可完成的实操任务，如 `fix_testuser_revoke`（撤销测试账号过度授权）、`restore_full_backup`（全量备份恢复）。 |
| 错误点 | Error point | 修复任务对应的待修复安全/运维问题，例如"test_user 拥有全局 DELETE/DROP 权限"。LLM 判定时的判定目标。 |
| 修复点未完全修复 | Partial repair | 离开某分支时该分支仍有未完成的修复任务。此时该分支的错误计数被保留。 |
| 操作失误 | Operation mistake | 一次"能识别出意图但未正确执行"的操作。**1 次操作失误 = 1 次失败**（ADR-0001 D2）。 |

## 失败计数

| 术语 | 英文 | 定义 |
|------|------|------|
| 分支错误次数 | Branch failed count | 按分支独立记录的操作失误次数，存于 `student_state.branch_failed_counts`（JSON）。 |
| 失败总数 | Failed count | `failed_count` 字段，等于各分支错误次数之和（用于评分扣分与状态显示）。 |
| 失败记账规则 | Accounting rule | LLM 裁决的五种结果对应的计分行为，见 ADR-0001 D6。 |

## LLM 判定

| 术语 | 英文 | 定义 |
|------|------|------|
| LLM 裁决 | Verdict | LangGraph 图对学员 SQL 的结构化判定输出：`syntax_valid` / `targets_error_point` / `fixes_error_point` / `security_issue` / `explanation`。 |
| 兜底降级 | Fallback | LLM 超时（20s）或异常时，回退到确定性 `validate()` 判定，保证离线可用。 |
| 变更类命令 | Mutation command | REVOKE / GRANT / ALTER USER / DROP USER / CREATE USER / SET PASSWORD / DELETE FROM mysql.user。LLM 只对这类命令判定。 |
| 确定性校验 | Deterministic validate | 基于正则/关键字匹配的修复任务校验函数，作为 LLM 的兜底。 |
| 分析提示 | Analysis hint | 终端在调用大模型前显示的瞬态提示"正在分析中..."。由服务端以 `hint` 事件流式推送，收到 `result` 后被替换。只在真的会调 LLM 时出现，避免假提示。 |
| LLM 提示事件 | Hint event | NDJSON 流事件之一（`{"type":"hint","message":"正在分析中..."}`）。由路由按 ADR-0001 D4 门槛预检（`terminal_sim.will_trigger_llm`），在调用 `execute` **之前**推送，见 ADR-0003。 |

## 其他

| 术语 | 英文 | 定义 |
|------|------|------|
| PITR | Point-in-Time Recovery | 时间点恢复，使用全量备份 + Binlog 恢复到误操作前的时间点。 |
| SOP | Standard Operating Procedure | 标准恢复操作流程，recovery 分支的步骤顺序（prepare → copy-back → binlog → verify）。违反顺序即失败。 |
| 终端模拟器 | Terminal Simulator | 模拟 mysql/bash 命令行的组件，学员在此输入 SQL 与运维命令。 |
| 权限快照 | Permissions snapshot | 终端当前 `_permissions` 状态（各用户剩余全局权限），作为 LLM 判定上下文的一部分。 |
| 按钮可用性矩阵 | Button availability matrix | 由故事阶段派生的各按钮组可用性映射，纯函数 `ui_button_states(phase)` 输出，`/api/story/status` 以 `buttons` 字段下发。**仅 failed 阶段有特殊矩阵**，其余阶段全可用。 |
| 按钮组 | Button group | 前端 `data-ui` 分组的受控按钮集合：`decision`（故事线决策×3）、`reset`（重置故事线）、`perm_analyze`（权限分析）、`report`（生成审计报告）。未分组的按钮（题目解析/教学指南）任何阶段始终可用。 |
| 恢复路径 | Recovery path | 失败分支后学员重新开始挑战的唯一出口：点击「重置故事线」（`/api/system/reset`）。failed 态下该按钮必须保持可用。 |

## 关联

- 设计决策: [ADR-0001](adr/0001-failure-branch-and-llm-sql-judge.md)、[ADR-0002](adr/0002-button-state-matrix.md)、[ADR-0003](adr/0003-llm-analysis-hint-stream.md)
