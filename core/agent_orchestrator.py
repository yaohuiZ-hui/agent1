"""
数据库安全运维智能体 - 智能体编排器

核心调度模块，负责：
- 故事状态机管理（决策点跳转、分支推进）
- 学员进度追踪与评分
- 各模块间的协调调度
- 全流程合规性校验
"""
import json
import time
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field, asdict

from config.settings import get_config, Config
from core.database_connector import DatabaseConnector


# ──────────────────────────────────────────
# 数据模型
# ──────────────────────────────────────────

@dataclass
class StoryState:
    """故事线状态数据模型"""
    student_name: str = "默认学员"
    current_decision: int = 0       # 当前决策点 (0=未开始, 1/2/3)
    current_branch: str = "start"   # 当前分支
    completed_tasks: List[str] = field(default_factory=list)
    failed_count: int = 0
    retry_count: int = 0
    score: int = 0
    story_phase: str = "intro"      # intro, decision, in_progress, completed, failed
    unlocked_branches: List[str] = field(default_factory=lambda: ["baseline"])
    branch_failed_counts: Dict[str, int] = field(default_factory=dict)  # 各分支独立错误计数
    last_alert: str = ""


# 故事线分支定义
STORY_BRANCHES = {
    "start": {
        "title": "故事开始",
        "description": "某商业银行核心业务系统在进行季度审计时，发现部分敏感客户数据存在泄露风险，且由于一次误操作导致部分交易流水丢失。",
        "phase": "intro",
        "decisions": [
            {"id": 1, "title": "安全基线扫描与权限管控",
             "description": "先进行安全基线扫描与权限梳理，登录数据库审计系统...",
             "next_branch": "baseline"},
            {"id": 2, "title": "数据库备份恢复",
             "description": "直接处理数据丢失问题，面对报错的命令行界面...",
             "next_branch": "recovery"},
            {"id": 3, "title": "SQL注入攻防",
             "description": "优先分析异常流量日志，通过慢查询和错误日志定位问题...",
             "next_branch": "sqli"},
        ],
    },
    "baseline": {
        "title": "安全基线检查与权限管控",
        "description": "学员登录数据库审计系统，发现存在弱口令账号及过度授权的测试账号。",
        "phase": "in_progress",
        "tasks": ["fix_root_remote", "fix_anonymous", "fix_testuser_revoke", "fix_devuser_revoke", "fix_appuser_revoke"],
        "success_next": "sqli",
        "fail_next": "failed",
        "max_failures": 3,
        "success_story": "成功阻断了外部黑客利用老旧接口进行的SQL注入尝试，但发现内部仍有异常查询日志。",
        "fail_story": "权限配置错误导致业务中断，核心交易系统停机超过30分钟，造成重大声誉损失。",
    },
    "recovery": {
        "title": "数据库备份恢复",
        "description": "学员面对报错的命令行界面，使用Binlog和全量备份文件进行时间点恢复（PITR）。",
        "phase": "in_progress",
        "tasks": ["restore_full_backup", "apply_binlog_pitr", "verify_data_integrity"],
        "success_next": "sqli",
        "fail_next": "failed",
        "max_failures": 2,
        "success_story": "成功恢复了丢失的交易流水，但发现部分字段被恶意篡改，需进一步排查注入漏洞。",
        "fail_story": "恢复数据超时，核心交易系统停机超过30分钟，造成重大声誉损失。",
    },
    "sqli": {
        "title": "SQL注入攻防",
        "description": "通过分析慢查询日志和错误日志，定位到一段未过滤特殊字符的SQL语句。",
        "phase": "in_progress",
        "tasks": ["analyze_slow_query_log", "fix_vulnerable_code", "configure_waf"],
        "success_next": "final_report",
        "fail_next": "failed",
        "max_failures": 2,
        "success_story": "修复了注入漏洞，防止了数据进一步泄露，但系统整体安全评分依然不及格，需进行底层配置加固。",
        "fail_story": "未修复注入漏洞，数据持续泄露，运维事故升级。",
    },
    "final_report": {
        "title": "生成审计报告",
        "description": "完成所有实操任务，自动生成《数据库安全运维与加固报告》。",
        "phase": "completed",
        "tasks": ["generate_report"],
    },
    "failed": {
        "title": "运维事故升级",
        "description": "学员需回滚操作并重新接受培训。",
        "phase": "failed",
    },
}


class AgentOrchestrator:
    """
    智能体编排器

    负责故事线状态管理、任务调度、评分计算和模块间协调。
    """

    def __init__(self, db: DatabaseConnector, config: Optional[Config] = None):
        self._db = db
        self._config = config or get_config()
        self._task_handlers: Dict[str, Callable] = {}

    # ──────────────────────────────────────────
    # 故事状态管理
    # ──────────────────────────────────────────

    def get_story_state(self, student_id: int = 1) -> StoryState:
        """获取学员当前故事状态"""
        rows = self._db.execute_sqlite(
            "SELECT * FROM student_state WHERE id = ?", (student_id,)
        )
        if not rows:
            return self._init_student(student_id)
        row = rows[0]

        def _load_json(raw, default):
            try:
                return json.loads(raw) if raw else default
            except Exception:
                return default

        def _safe(key, default):
            try:
                return row[key]
            except Exception:
                return default

        return StoryState(
            student_name=row["student_name"],
            current_decision=row["current_decision"],
            current_branch=row["current_branch"],
            completed_tasks=json.loads(row["completed_tasks"]),
            failed_count=row["failed_count"],
            retry_count=row["retry_count"],
            score=row["score"],
            story_phase=row["story_phase"],
            unlocked_branches=_load_json(_safe("unlocked_branches", None), ["baseline"]),
            branch_failed_counts=_load_json(_safe("branch_failed_counts", None), {}),
        )

    def _init_student(self, student_id: int = 1) -> StoryState:
        """初始化新学员状态"""
        self._db.execute_sqlite_insert(
            "INSERT INTO student_state (id, student_name, story_phase) VALUES (?, ?, ?)",
            (student_id, f"学员{student_id}", "intro"),
        )
        return StoryState()

    def update_story_state(self, student_id: int, **kwargs):
        """更新学员故事状态"""
        fields = ", ".join(f"{k}=?" for k in kwargs.keys())
        values = list(kwargs.values()) + [student_id]
        self._db.execute_sqlite(
            f"UPDATE student_state SET {fields}, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            tuple(values),
        )

    def make_decision(self, decision_id: int, student_id: int = 1) -> Dict[str, Any]:
        """
        处理学员决策选择

        Args:
            decision_id: 决策ID (1, 2, 3)
            student_id: 学员ID

        Returns:
            决策后的分支信息
        """
        decision_map = {d["id"]: d for d in STORY_BRANCHES["start"]["decisions"]}
        if decision_id not in decision_map:
            return {"error": "无效的决策ID", "valid_decisions": [1, 2, 3]}

        # 失败状态下禁止再次选择决策（防止从失败分支逃逸回 in_progress）
        state = self.get_story_state(student_id)
        if state.story_phase == "failed":
            return {
                "error": "运维事故已升级，系统处于失败状态。请点击「重置故事线」重新开始挑战。",
                "phase": "failed",
            }

        decision = decision_map[decision_id]
        branch = STORY_BRANCHES[decision["next_branch"]]

        self.update_story_state(
            student_id,
            current_decision=decision_id,
            current_branch=decision["next_branch"],
            story_phase="in_progress",
        )

        # 记录审计日志
        self._db.execute_sqlite_insert(
            "INSERT INTO audit_logs (student_id, action, detail) VALUES (?, ?, ?)",
            (student_id, "make_decision", f"选择了决策{decision_id}: {decision['title']}"),
        )

        return {
            "decision": decision,
            "branch": branch,
            "story_text": branch["description"],
        }

    def get_current_branch_info(self, student_id: int = 1) -> Dict[str, Any]:
        """获取当前分支的详细信息"""
        state = self.get_story_state(student_id)
        branch = STORY_BRANCHES.get(state.current_branch, STORY_BRANCHES["start"])

        info = {
            "student_name": state.student_name,
            "phase": state.story_phase,
            "branch": state.current_branch,
            "branch_info": branch,
            "completed_tasks": state.completed_tasks,
            "pending_tasks": [t for t in branch.get("tasks", []) if t not in state.completed_tasks],
            "score": state.score,
            "failed_count": state.failed_count,
            "retry_count": state.retry_count,
        }

        # 如果处于决策点，提供可选决策
        if state.story_phase == "intro":
            info["available_decisions"] = STORY_BRANCHES["start"]["decisions"]

        return info

    # ──────────────────────────────────────────
    # 任务管理
    # ──────────────────────────────────────────

    def register_task_handler(self, task_id: str, handler: Callable):
        """注册任务处理器"""
        self._task_handlers[task_id] = handler

    def execute_task(self, task_id: str, student_id: int = 1, **kwargs) -> Dict[str, Any]:
        """
        执行指定任务

        Args:
            task_id: 任务ID
            student_id: 学员ID
            **kwargs: 任务参数

        Returns:
            任务执行结果
        """
        state = self.get_story_state(student_id)

        # 检查是否已经完成
        if task_id in state.completed_tasks:
            return {"success": True, "message": "该任务已完成", "task_id": task_id}

        # 找处理器
        handler = self._task_handlers.get(task_id)
        if handler:
            try:
                result = handler(student_id=student_id, **kwargs)
                if result.get("success"):
                    self._complete_task(student_id, task_id)
                return result
            except Exception as e:
                self._record_failure(student_id, task_id, str(e))
                return {"success": False, "error": str(e), "task_id": task_id}
        else:
            # 没有处理器时标记为模拟完成（用于测试）
            return {"success": False, "error": f"未注册任务处理器: {task_id}", "task_id": task_id}

    def _complete_task(self, student_id: int, task_id: str):
        """完成任务并更新状态"""
        state = self.get_story_state(student_id)
        completed = state.completed_tasks + [task_id]
        new_score = min(state.score + 20, 100)

        self.update_story_state(
            student_id,
            completed_tasks=json.dumps(completed),
            score=new_score,
        )

        # 记录任务完成
        self._db.execute_sqlite_insert(
            "INSERT INTO task_records (student_id, task_id, task_name, task_type, status) VALUES (?, ?, ?, ?, ?)",
            (student_id, task_id, task_id, "practical", "completed"),
        )

        # 检查分支是否全部完成
        branch = STORY_BRANCHES.get(state.current_branch)
        if branch and "tasks" in branch:
            all_done = all(t in completed for t in branch["tasks"])
            if all_done and "success_next" in branch:
                # D10：完全修复 → 清零该分支错误计数，再推进
                branch_counts = dict(state.branch_failed_counts)
                branch_counts.pop(state.current_branch, None)
                self.update_story_state(
                    student_id,
                    current_branch=branch["success_next"],
                    story_phase="in_progress" if branch["success_next"] != "final_report" else "completed",
                    failed_count=sum(branch_counts.values()),
                    branch_failed_counts=json.dumps(branch_counts, ensure_ascii=False),
                )

    def _record_failure(self, student_id: int, task_id: str, error: str):
        """记录任务失败（按分支独立计数），并检查是否达到分支失败阈值"""
        state = self.get_story_state(student_id)
        branch = state.current_branch
        branch_counts = dict(state.branch_failed_counts)
        new_branch_count = branch_counts.get(branch, 0) + 1
        branch_counts[branch] = new_branch_count
        total_failed = sum(branch_counts.values())

        self.update_story_state(
            student_id,
            failed_count=total_failed,
            branch_failed_counts=json.dumps(branch_counts, ensure_ascii=False),
        )

        self._db.execute_sqlite_insert(
            "INSERT INTO task_records (student_id, task_id, task_name, task_type, status, result) VALUES (?, ?, ?, ?, ?, ?)",
            (student_id, task_id, task_id, "practical", "failed", json.dumps({"error": error})),
        )

        # 检查当前分支是否达到失败阈值 → 自动推进到失败分支
        branch_info = STORY_BRANCHES.get(branch)
        if branch_info and "fail_next" in branch_info and "max_failures" in branch_info:
            if new_branch_count >= branch_info["max_failures"]:
                fail_branch = branch_info["fail_next"]
                fail_branch_info = STORY_BRANCHES.get(fail_branch, {})
                self.update_story_state(
                    student_id,
                    current_branch=fail_branch,
                    story_phase=fail_branch_info.get("phase", "failed"),
                )
                fail_story = branch_info.get("fail_story", "运维事故升级！")
                self._db.execute_sqlite_insert(
                    "INSERT INTO audit_logs (student_id, action, detail) VALUES (?, ?, ?)",
                    (student_id, "story_failed",
                     f"分支 '{branch}' 失败次数({new_branch_count})达到阈值，推进到失败分支: {fail_story}"),
                )

    # ──────────────────────────────────────────
    # 命令记录与合规校验
    # ──────────────────────────────────────────

    def record_command(self, student_id: int, command: str, output: str = "", is_valid: bool = False):
        """记录学员执行的命令"""
        self._db.execute_sqlite_insert(
            "INSERT INTO command_history (student_id, command, output, is_valid) VALUES (?, ?, ?, ?)",
            (student_id, command, output[:500], int(is_valid)),
        )

    def validate_command_sequence(self, student_id: int, expected_commands: List[str]) -> Dict[str, Any]:
        """
        校验学员命令执行顺序是否符合SOP

        Args:
            student_id: 学员ID
            expected_commands: 期望的命令序列

        Returns:
            校验结果，包含遗漏步骤和顺序错误
        """
        rows = self._db.execute_sqlite(
            "SELECT command FROM command_history WHERE student_id = ? ORDER BY executed_at ASC",
            (student_id,),
        )
        actual_commands = [row["command"].strip() for row in rows]

        missing = []
        for cmd in expected_commands:
            if not any(cmd in ac for ac in actual_commands):
                missing.append(cmd)

        return {
            "is_compliant": len(missing) == 0,
            "missing_steps": missing,
            "total_expected": len(expected_commands),
            "total_executed": len(actual_commands),
        }

    # ──────────────────────────────────────────
    # 评分系统
    # ──────────────────────────────────────────

    def calculate_final_score(self, student_id: int = 1) -> Dict[str, Any]:
        """计算最终评分"""
        state = self.get_story_state(student_id)

        # 基础分来自完成任务
        base_score = state.score

        # 失败扣分
        fail_penalty = state.failed_count * 10

        # 重试扣分
        retry_penalty = state.retry_count * 5

        # 漏洞发现加分
        vuln_rows = self._db.execute_sqlite(
            "SELECT COUNT(*) as cnt FROM vulnerability_records WHERE student_id = ? AND is_fixed = 1",
            (student_id,),
        )
        vuln_bonus = vuln_rows[0]["cnt"] * 10 if vuln_rows else 0

        final_score = max(0, min(100, base_score - fail_penalty - retry_penalty + vuln_bonus))

        # 等级评定
        if final_score >= 90:
            grade = "A (优秀)"
        elif final_score >= 80:
            grade = "B (良好)"
        elif final_score >= 70:
            grade = "C (合格)"
        elif final_score >= 60:
            grade = "D (需改进)"
        else:
            grade = "F (不合格，需重新培训)"

        return {
            "student_id": student_id,
            "student_name": state.student_name,
            "base_score": base_score,
            "fail_penalty": fail_penalty,
            "retry_penalty": retry_penalty,
            "vuln_bonus": vuln_bonus,
            "final_score": final_score,
            "grade": grade,
            "completed_tasks": len(state.completed_tasks),
            "failed_count": state.failed_count,
            "story_phase": state.story_phase,
        }

    # ──────────────────────────────────────────
    # 操作日志
    # ──────────────────────────────────────────

    def get_audit_trail(self, student_id: int = 1) -> List[Dict[str, Any]]:
        """获取学员的完整审计轨迹"""
        rows = self._db.execute_sqlite(
            "SELECT * FROM audit_logs WHERE student_id = ? ORDER BY logged_at ASC",
            (student_id,),
        )
        return [dict(r) for r in rows]

    def get_command_history(self, student_id: int = 1, limit: int = 50) -> List[Dict[str, Any]]:
        """获取学员命令历史"""
        rows = self._db.execute_sqlite(
            "SELECT * FROM command_history WHERE student_id = ? ORDER BY executed_at DESC LIMIT ?",
            (student_id, limit),
        )
        return [dict(r) for r in rows]


# 全局单例
_orchestrator_instance: Optional[AgentOrchestrator] = None


def get_orchestrator(db: Optional[DatabaseConnector] = None, config: Optional[Config] = None) -> AgentOrchestrator:
    """获取 AgentOrchestrator 单例"""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        if db is None:
            db = DatabaseConnector(config)
        _orchestrator_instance = AgentOrchestrator(db, config)
    return _orchestrator_instance