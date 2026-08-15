"""Seam A': LLM 判定触发门槛 will_trigger_llm 单测（无 db，__new__ 构造）

对应用户需求："正在分析中..."提示必须在 LLM 调用前出现。
门槛即 ADR-0001 D4：**变更类命令 + 存在待修复项**。路由据此预检，在调用 execute 之前
先推送 hint 事件，从而保证 hint 先于 LLM 调用刷到客户端。

之前用 judge_sql.on_start 钩子（LLM 前瞬间触发）的方案被废弃：它在同步请求里无法
把提示提前刷出（只能等 execute 返回后才 yield），导致 hint 与 result 同批到达、
前端同帧加删不渲染。改为确定性预检（本测试验证的门槛）。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.scenario.terminal_simulator import (
    FIX_TASKS,
    TerminalSimulator,
    _is_mutation_sql,
    _normalize_sql,
)


def _inst(completed):
    """绕过 __init__ 构造（无需 db），仅设置 will_trigger_llm 依赖的 _completed_tasks。"""
    obj = TerminalSimulator.__new__(TerminalSimulator)
    obj._completed_tasks = set(completed)
    return obj


_MUTATION = "REVOKE ALL PRIVILEGES ON *.* FROM 'test_user'@'%';"
_READONLY = "SHOW GRANTS FOR 'test_user'@'%';"


class TestNormalizeSql(unittest.TestCase):
    def test_trims_and_uppercases_and_strips_semicolon(self):
        self.assertEqual(_normalize_sql("  revoke all; "), "REVOKE ALL")

    def test_lowercase_input_normalizes_to_upper(self):
        self.assertEqual(_normalize_sql("grant select on *.* to 'a'@'%'").startswith("GRANT"), True)


class TestIsMutationSql(unittest.TestCase):
    def test_mutation_keywords_are_detected(self):
        for sql in ("REVOKE ALL", "GRANT SELECT", "ALTER USER 'a'@'%'",
                    "CREATE USER 'a'@'%'", "DROP USER 'a'@'%'",
                    "SET PASSWORD FOR 'a'@'%'", "DELETE FROM MYSQL.USER WHERE ..."):
            self.assertTrue(_is_mutation_sql(sql), f"应为变更类: {sql}")

    def test_readonly_is_not_mutation(self):
        for sql in ("SHOW GRANTS FOR 'a'@'%'", "SELECT * FROM mysql.user",
                    "USE mysql", "FLUSH PRIVILEGES"):
            self.assertFalse(_is_mutation_sql(sql), f"不应为变更类: {sql}")


class TestWillTriggerLlm(unittest.TestCase):

    def test_mutation_with_pending_tasks(self):
        self.assertTrue(_inst([]).will_trigger_llm(_MUTATION))

    def test_lowercase_with_trailing_semicolon(self):
        self.assertTrue(_inst([]).will_trigger_llm("  revoke all privileges ...;"))

    def test_mutation_but_no_pending_tasks(self):
        obj = _inst(t["id"] for t in FIX_TASKS)  # 所有修复任务已完成 → 无待修复项
        self.assertFalse(obj.will_trigger_llm(_MUTATION))

    def test_readonly_never_triggers(self):
        self.assertFalse(_inst([]).will_trigger_llm(_READONLY))


if __name__ == "__main__":
    unittest.main()
