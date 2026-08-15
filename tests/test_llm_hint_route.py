"""Seam B': /api/terminal/execute 流式响应的事件顺序与刷出时机（集成测试）

对应用户需求："正在分析中..."提示必须在调用大模型前出现在终端里。
契约：
- 变更类命令（会触发 LLM 判定）→ 流为 [hint, result]，hint 消息为"正在分析中..."
- **hint 必须先于 execute 被刷出**（回归：曾因在 execute 返回后才 yield hint，
  导致 hint 与 result 同批到达、前端同帧加删不渲染）
- 只读命令（不会触发 LLM）→ 流只有 [result]，无 hint 假提示

使用临时 sqlite（SQLITE_DB_PATH 环境变量）隔离，mock 掉 judge_sql 不发真实请求。
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _BASE)

# 必须在 import app 之前设置环境变量，使 Config 指向临时 db/日志
_TMPDIR = tempfile.mkdtemp(prefix="agent1_test_hint_")
os.environ["SQLITE_DB_PATH"] = os.path.join(_TMPDIR, "test.db")
os.environ["LOG_FILE"] = os.path.join(_TMPDIR, "test.log")

import app  # noqa: E402


def _parse_stream(resp):
    """把流式响应体按行解析成事件列表（用于 buffered=True 的完整响应）。"""
    return [json.loads(line) for line in resp.data.decode("utf-8").splitlines() if line.strip()]


def _fake_judge(sql, error_points, perms_snapshot):
    """模拟 LLM 裁决成功修复 fix_testuser_revoke。"""
    return {"syntax_valid": True, "syntax_error": "",
            "targets_error_point": "fix_testuser_revoke",
            "fixes_error_point": True, "security_issue": False,
            "explanation": "test"}


class TestTerminalExecuteStream(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = app.app.test_client()
        # 空临时库里没有学员记录; command_history 有外键约束, 需先初始化学员 1
        app.orch.get_story_state(1)

    def test_mutation_command_streams_hint_before_result(self):
        """变更类命令 → 先 hint("正在分析中...") 后 result"""
        # 注意: werkzeug test client 对流式响应是惰性消费的——generator 在访问
        # resp.data 时才运行。必须在 mock 作用域内消费 body, 否则 patch 已被还原,
        # judge_sql 会走真实 LLM。
        calls = []
        with mock.patch("modules.toolkit.sql_judge.judge_sql",
                        side_effect=lambda *a, **k: (calls.append("judge_called") or _fake_judge(*a, **k))):
            resp = self.client.post("/api/terminal/execute", json={
                "command": "REVOKE ALL PRIVILEGES ON *.* FROM 'test_user'@'%';",
                "student_id": 1})
            self.assertEqual(resp.status_code, 200)
            events = _parse_stream(resp)
        self.assertEqual([e["type"] for e in events], ["hint", "result"])
        self.assertEqual(events[0]["message"], "正在分析中...")
        self.assertIn("judge_called", calls, "变更类命令应走到 LLM 判定")

    def test_hint_is_flushed_before_execute_runs(self):
        """回归：hint 必须早于 execute 被刷出（而非等 execute 返回后同批到达）"""
        calls = []
        real_execute = app.terminal_sim.execute

        def spy_execute(command_line, student_id=1, *args, **kwargs):
            calls.append(command_line)
            return real_execute(command_line, student_id, *args, **kwargs)

        with mock.patch.object(app.terminal_sim, "execute", side_effect=spy_execute), \
             mock.patch("modules.toolkit.sql_judge.judge_sql", side_effect=_fake_judge):
            resp = self.client.post("/api/terminal/execute", json={
                "command": "REVOKE ALL PRIVILEGES ON *.* FROM 'test_user'@'%';",
                "student_id": 1}, buffered=False)
            first = next(iter(resp.response))
            self.assertEqual(calls, [], "取到 hint 时 execute 尚未被调用")
            self.assertEqual(json.loads(first.decode("utf-8").strip())["type"], "hint")
            rest = b"".join(resp.response)
        self.assertIn(b'"type": "result"', rest)

    def test_readonly_command_has_no_hint(self):
        """只读命令 → 只有 result，无 hint 假提示"""
        with mock.patch("modules.toolkit.sql_judge.judge_sql", side_effect=_fake_judge):
            resp = self.client.post("/api/terminal/execute", json={
                "command": "SHOW GRANTS FOR 'test_user'@'%';",
                "student_id": 1})
            events = _parse_stream(resp)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual([e["type"] for e in events], ["result"])


if __name__ == "__main__":
    unittest.main()
