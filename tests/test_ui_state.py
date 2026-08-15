"""测试 ui_button_states 按钮可用性矩阵

对应用户报告: 重大事故(failed)后重置按钮不可点、权限分析可点 —— 按钮状态倒置。
矩阵应保证: failed 时 决策/权限分析 禁用, 重置/生成报告 可用; 其余阶段全可用。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ui_state import ui_button_states


class TestUiButtonStates(unittest.TestCase):
    """按钮组可用性矩阵的纯函数测试"""

    def test_failed_disables_decision_and_perm_analyze(self):
        s = ui_button_states("failed")
        self.assertFalse(s["decision"], "事故后决策按钮应禁用")
        self.assertFalse(s["perm_analyze"], "事故后权限分析按钮应禁用")
        self.assertTrue(s["reset"], "事故后重置故事线按钮应可用(唯一恢复路径)")
        self.assertTrue(s["report"], "事故后生成审计报告按钮应可用")

    def test_non_failed_phases_all_enabled(self):
        for phase in ("intro", "in_progress", "completed"):
            s = ui_button_states(phase)
            self.assertTrue(all(s.values()), f"阶段 {phase} 的按钮应全部可用: {s}")

    def test_unknown_phase_defaults_to_all_enabled(self):
        s = ui_button_states("some_unknown_phase")
        self.assertTrue(all(s.values()))

    def test_exposed_groups_match_frontend_bindings(self):
        """矩阵键集必须与前端 data-ui 分组的按钮组一一对应"""
        self.assertEqual(
            set(ui_button_states("failed").keys()),
            {"decision", "reset", "perm_analyze", "report"},
        )

    def test_matrix_is_immutable_copy(self):
        """调用方修改返回结果不应污染模块内部常量"""
        s1 = ui_button_states("failed")
        s1["reset"] = False
        s2 = ui_button_states("failed")
        self.assertTrue(s2["reset"], "返回副本应相互独立")


if __name__ == "__main__":
    unittest.main()
