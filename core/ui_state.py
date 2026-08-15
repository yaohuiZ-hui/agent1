"""按钮可用性状态矩阵 (UI 只读状态派生)

纯函数模块, 不依赖数据库。前端各按钮的可用性由 `/api/story/status`
依据故事阶段在此派生, 保证 UI 状态与后端语义单一来源。

背景: 曾出现"重大事故(failed)后重置按钮被禁用、权限分析可点"的倒置问题,
根因是前端 `setDecisionButtons` 按 CSS 颜色类(.menu-btn-danger 等)批量禁用,
把非决策按钮(重置故事线)一并扫进禁用区, 而权限分析(.menu-btn-info)漏网。
修复方式: 按钮可用性改由后端按阶段派生矩阵, 前端只按 `data-ui` 分组渲染。
"""
from typing import Dict

# 受控按钮组: 与前端各按钮的 data-ui 分组一一对应
#   decision     → 故事线决策×3 (基线扫描/备份恢复/SQL注入攻防)
#   reset        → 重置故事线
#   perm_analyze → 权限分析
#   report       → 生成审计报告
# 未列入的按钮(题目解析/教学指南)在任何阶段始终可用, 无需受控。
_BUTTON_GROUPS: tuple = ("decision", "reset", "perm_analyze", "report")

# failed(重大事故) 阶段矩阵
#   decision    禁用: 故事已死, 不可继续选择决策 (makeDecision 后端亦有拦截)
#   reset       可用: 事故后唯一恢复路径, 提示语要求"点击「重置故事线」重新开始"
#   perm_analyze 禁用: 事故后对已结束的故事做权限分析无意义
#   report      可用: 事故后仍可生成审计报告
_FAILED_STATE: Dict[str, bool] = {
    "decision": False,
    "reset": True,
    "perm_analyze": False,
    "report": True,
}

_ALL_ENABLED: Dict[str, bool] = {g: True for g in _BUTTON_GROUPS}


def ui_button_states(phase: str) -> Dict[str, bool]:
    """根据故事阶段返回各按钮组可用状态。

    Args:
        phase: 故事阶段 (intro / in_progress / completed / failed)。

    Returns:
        各按钮组的可用性字典; 仅 failed 有特殊矩阵,
        其余(含未知)阶段一律全部可用(安全默认)。
    """
    if phase == "failed":
        return dict(_FAILED_STATE)
    return dict(_ALL_ENABLED)
