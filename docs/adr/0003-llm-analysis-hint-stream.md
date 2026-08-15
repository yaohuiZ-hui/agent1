# ADR-0003: LLM 判定前在终端流式推送"正在分析中..."提示

- **状态**: 已接受（Accepted）— 2026-08-14 rev.2 修订
- **日期**: 2026-08-14
- **作者**: Agent 1 项目组（经 grilling 会话确认）

## 背景 Context

LLM SQL 判定（[ADR-0001](0001-failure-branch-and-llm-sql-judge.md) D8：单次超时 20s，JSON 解析失败重试 ≤2 次）
发生在**同步的后端请求**里：`/api/terminal/execute` → `terminal_sim.execute` → `_llm_judge_and_handle`
→ `judge_sql` → `graph.invoke()`。在最长可达几十秒的等待窗口内：

- 前端 `executeCmd` 是单个 `fetch().then(r=>r.json())`，只有响应返回后才渲染输出，
  期间终端只显示 `$ <cmd>`，学员无法判断是"正在分析"还是"卡死"。
- `sql_judge._judge_node` 里曾有 `print("正在分析中...")`，但只打到 **Flask 服务端控制台**，不到达网页终端。

用户需求：**在调用大模型前，在终端里显示"正在分析中..."提示**。
难点：前端无法预先得知某条命令会不会触发 LLM（取决于"变更类命令 + 存在待修复项 + LLM 可用"，
见 ADR-0001 D4），所以"在调用大模型前"这一时机只有服务端知道。

### rev.1 的缺陷（本修订的原因）

初版（rev.1）用 `judge_sql(..., on_start=回调)` 钩子在 LLM 调用瞬间触发提示，
但回调只能把 hint 追加进**局部列表**，而路由 generator 的 `yield` 在 `execute()` 返回之后才执行
（`for ev in events: yield`）。结果：**hint 与 result 在 execute 返回后同批刷出**，
前端收到两行后在同一次同步 `pump()` 里"加 hint → 立即删 hint"，浏览器从未绘制 → 瞬态提示不可见。
rev.1 的测试只断言最终 body 里事件顺序（`[hint, result]`），未断言**刷出时机**，因此测试通过但功能坏着。

## 决策 Decision（rev.2）

| # | 决策项 | 结论 |
|---|--------|------|
| D1 | 送达方式 | **服务端流式推送（NDJSON）**：`/api/terminal/execute` 改为 generator，先推 `hint` 事件，再推 `result`/`error`；前端 fetch reader 逐行渲染 |
| D2 | 触发时机 | **确定性预检**：抽出 `terminal_sim.will_trigger_llm(command)`（= `_is_mutation_sql(_normalize_sql(cmd))` 且 `_pending_fix_tasks()` 非空，即 ADR-0001 D4 门槛）。generator **在调用 `execute` 之前**先 `yield` hint → 保证 hint 先于 LLM 调用刷到客户端 |
| D3 | 单一来源 | D4 门槛提炼为模块级纯函数 `_normalize_sql` + `_is_mutation_sql`，`_execute_sql` 内部门槛与路由预检共用，不漂移 |
| D4 | 前端呈现 | `executeCmd` 流式读取：`hint` 插入瞬态行 `⏳ 正在分析中...`（琥珀色），`result` 到达时**替换**该行并渲染输出、刷新状态；`error` 显示错误 |
| D5 | 测试接缝 | Seam A'：`will_trigger_llm` 门槛单测（无 db，`__new__` 构造）；Seam B'：路由流式测试，**含 B2 时序回归**（`buffered=False` 下首块即 hint 且 `execute` 尚未被调用） |
| D6 | 废弃机制 | 移除 rev.1 的 `judge_sql.on_start` 参数、terminal_sim 的 `on_llm_start` 透传、`_judge_node` 的 `print("正在分析中...")`（其职责已由终端 hint 承担） |
| D7 | 事件格式 | NDJSON（`application/x-ndjson`），每行一个 JSON 事件：`hint` / `result` / `error` |
| D8 | 换行处理 | 前端 JS 新行用 `String.fromCharCode(10)`，规避 Jinja 模板里 Python 字符串对 `\n` 的转义 |

### NDJSON 事件契约（D1/D7）

| 事件 | 字段 | 说明 |
|------|------|------|
| `hint` | `message` | 预检命中门槛、即将调 LLM 时推送（先于 execute），消息为"正在分析中..." |
| `result` | `output` / `prompt` | 命令执行最终输出 + 终端提示符 |
| `error` | `message` | 执行异常时推送 |

## 结果 Consequences

**正面**
- 提示时机由服务端预检保证：只读命令/无待修复项不推送，无假提示；命中门槛则**先于 LLM 调用**刷出。
- rev.1 的"同批到达不可见"缺陷由 **B2 时序回归测试**兜住：断言首块即 hint 且 execute 尚未被调用。
- D4 门槛单一来源（`_is_mutation_sql` + `_pending_fix_tasks`），路由与 `_execute_sql` 不漂移。
- 无线程，无僵尸线程风险；`will_trigger_llm` 纯确定性，单测零依赖。

**代价/风险**
- 传输协议为 NDJSON 流，前端 `executeCmd` 依赖 fetch reader；若服务端/代理对生成器做缓冲，
  提示可能延迟刷出（本应用为 Flask dev server，按 chunk 刷出，无此问题）。
- `hint` 在请求开始即出（略早于 `graph.invoke`），对"即将分析"的语义足够。
- 测试注意：werkzeug test client 对流式响应**惰性消费**，必须在 mock 作用域内访问 `resp.data`/迭代，
  否则 generator 在 patch 还原后才运行（B1 曾因此误判）。

## 关联

- 术语表: [glossary](../../docs/glossary.md)（"分析提示/LLM 提示事件"）
- 前置决策: [ADR-0001](0001-failure-branch-and-llm-sql-judge.md)（LLM 判定与记账规则 D4/D8/D9）
- 涉及文件: `modules/scenario/terminal_simulator.py`, `app.py`,
  新增/改写 `tests/test_llm_hint_judge.py`, `tests/test_llm_hint_route.py`
- 相关记忆: [[llm-analysis-hint-stream]]
