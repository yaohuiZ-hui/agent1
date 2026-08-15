"""
场景模拟引导模块 - 故事引擎

管理故事状态机（State Machine）：
- 决策点分发（3个分支）
- 分支推进与解锁逻辑
- 故事文本管理和多分支剧情渲染
"""
import json
from typing import Optional, Dict, Any, List
from datetime import datetime

from core.agent_orchestrator import STORY_BRANCHES, StoryState
from core.database_connector import DatabaseConnector


# 告警弹窗模拟数据
ALERT_POPUPS = {
    "baseline": {
        "title": "安全告警",
        "message": "审计系统检测到多个安全风险：发现2个弱口令账号、3个过度授权测试账号，以及1个允许远程root登录的配置。",
        "severity": "high",
        "suggestions": ["执行基线检查脚本", "审核用户权限"],
    },
    "sqli": {
        "title": "入侵检测告警",
        "message": "WAF检测到来自192.168.1.105的异常请求，疑似SQL注入攻击（Union注入特征）。攻击路径：/api/user/profile。",
        "severity": "critical",
        "suggestions": ["分析慢查询日志", "检查老旧接口"],
    },
    "recovery": {
        "title": "数据完整性告警",
        "message": "交易流水表(trade_flow)出现数据异常，比对发现2024-01-15至2024-01-17期间存在约1500条记录丢失。",
        "severity": "critical",
        "suggestions": ["检查全量备份文件", "解析Binlog日志"],
    },
    "post_recovery": {
        "title": "数据校验告警",
        "message": "恢复后的数据校验发现：trade_flow表中部分字段（account_no, amount）存在恶意篡改痕迹，怀疑存在SQL注入漏洞。",
        "severity": "high",
        "suggestions": ["排查注入漏洞", "检查应用层代码"],
    },
    "waf_blocked": {
        "title": "WAF拦截记录",
        "message": "ModSecurity成功拦截来自外部IP的SQL注入攻击（规则ID: 942100）。攻击类型：SQL Injection Union Attack。",
        "severity": "medium",
        "suggestions": ["查看WAF日志", "加固老旧接口"],
    },
}


class StoryEngine:
    """
    故事引擎

    负责：
    - 故事状态机的初始化与推进
    - 决策点呈现与分支解锁
    - 告警弹窗的生成与触发
    - 剧情文本的渲染与返回
    """

    def __init__(self, db: DatabaseConnector):
        self._db = db

    # ──────────────────────────────────────────
    # 故事初始化
    # ──────────────────────────────────────────

    def get_story_intro(self) -> Dict[str, Any]:
        """获取故事开场介绍"""
        return {
            "title": "数据库安全运维应急响应",
            "background": STORY_BRANCHES["start"]["description"],
            "roles": [
                {"name": "核心数据库 DBA", "responsibility": "负责数据库安全运维、漏洞修复与数据恢复"},
                {"name": "数据安全审计员", "responsibility": "负责安全基线检查、权限审计与合规报告"},
            ],
            "decisions": STORY_BRANCHES["start"]["decisions"],
            "mission": "在30分钟内完成安全体检、漏洞修复和数据恢复，避免运维事故升级。",
        }

    def get_story_phase(self, branch: str) -> Dict[str, Any]:
        """获取指定分支的剧情信息"""
        branch_info = STORY_BRANCHES.get(branch, STORY_BRANCHES["start"])
        alert = ALERT_POPUPS.get(branch)

        result = {
            "branch": branch,
            "title": branch_info["title"],
            "description": branch_info["description"],
            "phase": branch_info["phase"],
            "tasks": branch_info.get("tasks", []),
            "alert": alert,
        }

        # 如果是终局分支，添加结局信息
        if branch == "final_report":
            result["conclusion"] = "恭喜！您已完成所有运维任务。系统安全评分已达标准，可生成最终审计报告。"
        elif branch == "failed":
            result["conclusion"] = "运维事故升级！核心交易系统停机超过30分钟。请回滚操作并重新培训。"

        return result

    # ──────────────────────────────────────────
    # 决策处理
    # ──────────────────────────────────────────

    def process_decision(self, decision_id: int, student_id: int = 1) -> Dict[str, Any]:
        """
        处理学员决策并返回分支剧情

        Args:
            decision_id: 决策ID (1, 2, 3)
            student_id: 学员ID

        Returns:
            分支剧情信息，包括告警弹窗、任务列表等
        """
        from core.agent_orchestrator import get_orchestrator
        orchestrator = get_orchestrator(self._db)
        result = orchestrator.make_decision(decision_id, student_id)

        if "error" in result:
            return result

        branch = result["branch"]
        branch_info = self.get_story_phase(result["decision"]["next_branch"])

        # 根据决策添加特定剧情推进文本
        decision_id = result["decision"]["id"]
        if decision_id == 1:
            branch_info["story_progress"] = (
                "你选择先进行安全基线扫描。登录数据库审计系统后，发现存在弱口令账号及过度授权的测试账号。"
                "完成加固后，你将解锁SQL注入攻防分支。"
            )
        elif decision_id == 2:
            branch_info["story_progress"] = (
                "你选择直接处理数据丢失问题。面对报错的命令行界面，你需要使用Binlog和全量备份文件"
                "进行时间点恢复（PITR）。"
            )
        elif decision_id == 3:
            branch_info["story_progress"] = (
                "你选择优先分析异常流量日志。通过分析慢查询日志和错误日志，定位到一段未过滤特殊字符的SQL语句。"
            )

        return branch_info

    # ──────────────────────────────────────────
    # 分支推进
    # ──────────────────────────────────────────

    def advance_branch(self, student_id: int = 1) -> Dict[str, Any]:
        """
        推进当前分支到下一阶段

        当学员完成当前分支所有任务后，推进到下一个分支
        """
        from core.agent_orchestrator import get_orchestrator
        orchestrator = get_orchestrator(self._db)
        state = orchestrator.get_story_state(student_id)

        # 当前分支信息
        current_branch = STORY_BRANCHES.get(state.current_branch)
        if not current_branch or "success_next" not in current_branch:
            return {"error": "当前分支无法推进", "branch": state.current_branch}

        # 检查任务是否全部完成
        all_tasks = current_branch.get("tasks", [])
        completed = state.completed_tasks
        if not all(t in completed for t in all_tasks):
            pending = [t for t in all_tasks if t not in completed]
            return {
                "error": "尚有未完成的任务",
                "pending_tasks": pending,
                "branch": state.current_branch,
            }

        # 推进到下一分支
        next_branch = current_branch["success_next"]
        story_text = current_branch.get("success_story", "")
        next_branch_info = STORY_BRANCHES.get(next_branch, {})

        # D10：完全修复 → 清零该分支错误计数
        branch_counts = dict(state.branch_failed_counts)
        branch_counts.pop(state.current_branch, None)

        # 更新状态
        orchestrator.update_story_state(
            student_id,
            current_branch=next_branch,
            story_phase=next_branch_info.get("phase", "in_progress"),
            failed_count=sum(branch_counts.values()),
            branch_failed_counts=json.dumps(branch_counts, ensure_ascii=False),
        )

        # 记录审计日志
        self._db.execute_sqlite_insert(
            "INSERT INTO audit_logs (student_id, action, detail) VALUES (?, ?, ?)",
            (student_id, "advance_branch", f"从 {state.current_branch} 推进到 {next_branch}"),
        )

        # 获取下一分支的告警弹窗
        next_alert = ALERT_POPUPS.get(next_branch)

        return {
            "success": True,
            "previous_branch": state.current_branch,
            "current_branch": next_branch,
            "story_text": story_text,
            "branch_info": next_branch_info,
            "alert": next_alert,
        }

    # ──────────────────────────────────────────
    # 失败分支处理
    # ──────────────────────────────────────────

    def handle_failure(self, student_id: int = 1) -> Dict[str, Any]:
        """处理失败分支"""
        from core.agent_orchestrator import get_orchestrator
        orchestrator = get_orchestrator(self._db)

        orchestrator.update_story_state(
            student_id,
            current_branch="failed",
            story_phase="failed",
        )

        self._db.execute_sqlite_insert(
            "INSERT INTO audit_logs (student_id, action, detail) VALUES (?, ?, ?)",
            (student_id, "story_failed", "运维事故升级，进入失败分支"),
        )

        return {
            "success": True,
            "branch": "failed",
            "title": STORY_BRANCHES["failed"]["title"],
            "description": STORY_BRANCHES["failed"]["description"],
            "message": "运维事故升级！核心交易系统停机超过30分钟，造成重大声誉损失。学员需回滚操作并重新接受培训。",
        }

    # ──────────────────────────────────────────
    # 业务工单生成
    # ──────────────────────────────────────────

    def generate_ticket(self, branch: str) -> Dict[str, Any]:
        """生成模拟业务工单"""
        tickets = {
            "baseline": {
                "ticket_id": "INC-2024-001",
                "title": "紧急安全基线检查与加固",
                "priority": "P1 紧急",
                "requester": "安全审计部",
                "deadline": "2024-01-20 18:00",
                "description": "季度审计发现多个安全配置不合规项，需立即完成基线检查和加固。",
                "checklist": [
                    "删除匿名用户",
                    "修改弱密码",
                    "撤销过度授权",
                    "关闭root远程登录",
                    "启用SSL",
                ],
            },
            "recovery": {
                "ticket_id": "INC-2024-002",
                "title": "交易流水数据丢失恢复",
                "priority": "P0 严重",
                "requester": "业务运营部",
                "deadline": "2024-01-18 12:00",
                "description": "核心交易系统误操作导致1500条交易流水丢失，需立即使用备份恢复。",
                "checklist": [
                    "确认全量备份文件",
                    "定位Binlog位置",
                    "执行PITR恢复",
                    "校验数据完整性",
                ],
            },
            "sqli": {
                "ticket_id": "INC-2024-003",
                "title": "SQL注入漏洞应急修复",
                "priority": "P0 严重",
                "requester": "安全运营中心(SOC)",
                "deadline": "2024-01-18 14:00",
                "description": "WAF检测到针对老旧接口的SQL注入攻击，需立即修复漏洞并配置WAF规则。",
                "checklist": [
                    "定位漏洞接口",
                    "修复代码（参数化查询）",
                    "配置WAF规则",
                    "验证修复效果",
                ],
            },
        }
        return tickets.get(branch, {"ticket_id": "N/A", "title": "未知工单"})

    # ──────────────────────────────────────────
    # 审计报表（场景内预览）
    # ──────────────────────────────────────────

    def generate_audit_snapshot(self, student_id: int = 1) -> Dict[str, Any]:
        """生成当前审计快照（场景内预览用）"""
        from core.agent_orchestrator import get_orchestrator
        orchestrator = get_orchestrator(self._db)
        state = orchestrator.get_story_state(student_id)

        vuln_count = self._db.execute_sqlite(
            "SELECT COUNT(*) as cnt FROM vulnerability_records WHERE student_id = ?", (student_id,)
        )
        fixed_count = self._db.execute_sqlite(
            "SELECT COUNT(*) as cnt FROM vulnerability_records WHERE student_id = ? AND is_fixed = 1", (student_id,)
        )
        cmd_count = self._db.execute_sqlite(
            "SELECT COUNT(*) as cnt FROM command_history WHERE student_id = ?", (student_id,)
        )

        return {
            "student": state.student_name,
            "current_branch": state.current_branch,
            "phase": state.story_phase,
            "score": state.score,
            "vulnerabilities_found": vuln_count[0]["cnt"] if vuln_count else 0,
            "vulnerabilities_fixed": fixed_count[0]["cnt"] if fixed_count else 0,
            "commands_executed": cmd_count[0]["cnt"] if cmd_count else 0,
            "failed_count": state.failed_count,
            "timestamp": datetime.now().isoformat(),
        }