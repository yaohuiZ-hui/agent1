# ADR-0002: 前端按钮可用性由后端按故事阶段派生矩阵

- **状态**: 已接受（Accepted）
- **日期**: 2026-08-14
- **作者**: Agent 1 项目组（经 grilling 会话确认）

## 背景 Context

用户报告：发生重大事故（`failed` 分支）后，**重置按钮无法点击**，而**权限分析按钮可正常点击**，
怀疑二者可用状态倒置。

根因定位（在 [app.py](../../agent_1/app.py) 前端脚本）：

1. `setDecisionButtons(on)` 用 CSS 颜色类选择器
   `.menu-btn-primary,.menu-btn-warning,.menu-btn-danger` 批量设置 `disabled = !on`，
   并在 `updateUI` 中调用 `setDecisionButtons(d.phase !== 'failed')`。
2. 按钮类名复用导致误伤/漏网：
   - **重置故事线** 用 `menu-btn-danger` → 被错误扫进禁用区（它恰是失败后唯一恢复路径，
     失败提示语还写着"点击「重置故事线」可重新开始挑战"）。
   - **权限分析** 用 `menu-btn-info` → 不在选择器内 → 事故后仍可点。
   - **生成审计报告** 用 `menu-btn-warning` → 被副作用禁用。
3. 这段代码是"失败分支待验证"里程碑的**未提交新增代码**，尚未经过失败态验证。

结论：问题不是字面上的"两按钮状态互换"，而是**按颜色类批量禁用**的机制无法表达
"决策禁用、重置可用、权限分析禁用、报告可用"这种逐按钮语义。

## 决策 Decision

| # | 决策项 | 结论 |
|---|--------|------|
| D1 | failed 态按钮矩阵 | 决策×3 **禁用**；重置故事线 **可用**（恢复路径）；权限分析 **禁用**；生成审计报告 **可用** |
| D2 | 状态来源 | 按钮可用性由**后端纯函数 `ui_button_states(phase)`** 按故事阶段派生，`/api/story/status` 附 `buttons` 字段下发 |
| D3 | 模块位置 | 新建**零依赖纯模块 `core/ui_state.py`**（不碰 db），常量表 + 纯函数，可直接单测 |
| D4 | 前端渲染 | 前端按钮加 `data-ui` 分组（`decision` / `reset` / `perm_analyze` / `report`），`applyButtonStates(d.buttons)` 按分组逐组设置禁用样式；废弃按颜色类批量禁用的 `setDecisionButtons` |
| D5 | 兜底阶段 | 非 failed 阶段（intro / in_progress / completed）及**未知阶段一律全可用**（安全默认） |
| D6 | 后端拦截范围 | **仅 UI 层**。决策接口 `makeDecision` 已自带 failed 拦截；权限分析/报告为只读，无需接口拦截 |
| D7 | 测试接缝 | Python 标准库 `unittest`（零安装），测试 `core/ui_state.py` 的矩阵行为 |
| D8 | 其余阶段 | intro / in_progress / completed 保持现状（全部按钮可用），本次不改 |

### failed 态按钮矩阵（D1）

| 按钮组 | 是否可用 | 理由 |
|--------|---------|------|
| 故事线决策 ×3 | 否 | 故事已死，不可继续选择决策；`makeDecision` 后端亦有拦截 |
| 重置故事线 | 是 | 事故后唯一恢复路径，提示语指引用户点击重置重来 |
| 权限分析 | 否 | 对已结束的故事做权限分析无意义 |
| 生成审计报告 | 是 | 事故后仍可出具报告 |

## 结果 Consequences

**正面**
- 修复"事故后重置按钮禁用、权限分析可用"的倒置现象，恢复失败后的唯一出路。
- 按钮可用性语义从"按 CSS 颜色类"改为"后端单一来源"，前端只做哑渲染，
  未来新增按钮组只改 `core/ui_state.py` 一处。
- 纯函数可单测，覆盖 failed / 非 failed / 未知阶段 / 矩阵键集与前端绑定一致性 / 返回不可变副本。

**代价/风险**
- 按钮状态依赖 `/api/story/status` 返回，前端首次渲染需等待该接口（原有流程不变）。
- `data-ui` 分组与矩阵键集需保持一一对应，已用单测（`test_exposed_groups_match_frontend_bindings`）锁定。
- 本次为 UI 层修复；若未来要求"事故后分析接口也不可用"，需另增接口层拦截（D6 明确暂不做）。

## 关联

- 术语表: [glossary](../../docs/glossary.md)（新增"按钮可用性矩阵/按钮组"条目）
- 前置决策: [ADR-0001](0001-failure-branch-and-llm-sql-judge.md)（失败分支触发机制）
- 涉及文件: 新增 `core/ui_state.py`、`tests/test_ui_state.py`；修改 `app.py`
- 相关记忆: [[button-state-matrix]]
