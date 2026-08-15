"""
场景模拟引导模块 - 任务管理器

管理学员运维任务的生命周期：
- 任务注册与分发
- 任务状态跟踪
- 任务结果验证与评分
- 操作步骤合规性校验
"""
import json
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from datetime import datetime

from core.database_connector import DatabaseConnector


@dataclass
class TaskDefinition:
    """任务定义"""
    task_id: str
    title: str
    description: str
    task_type: str  # baseline, permission, recovery, sqli, waf, report
    difficulty: str  # easy, medium, hard
    expected_commands: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    max_retries: int = 3
    time_limit_minutes: int = 15


# 预定义任务
PREDEFINED_TASKS = {
    "fix_weak_passwords": TaskDefinition(
        task_id="fix_weak_passwords",
        title="修复弱口令问题",
        description="识别并修复数据库中的弱口令账号",
        task_type="baseline",
        difficulty="medium",
        expected_commands=["ALTER USER", "SET PASSWORD"],
        hints=["使用 ALTER USER 命令修改密码", "确保密码强度达到80分以上"],
        max_retries=3,
    ),
    "revoke_excessive_privs": TaskDefinition(
        task_id="revoke_excessive_privs",
        title="撤销过度授权",
        description="撤销测试账号和开发账号的过度授权，遵循最小权限原则",
        task_type="permission",
        difficulty="medium",
        expected_commands=["REVOKE", "SHOW GRANTS"],
        hints=["先查看用户权限: SHOW GRANTS FOR user", "使用 REVOKE 撤销多余权限"],
        max_retries=3,
    ),
    "restore_full_backup": TaskDefinition(
        task_id="restore_full_backup",
        title="恢复全量备份",
        description="使用全量备份文件恢复数据库",
        task_type="recovery",
        difficulty="medium",
        expected_commands=["xtrabackup", "mysqlbackup", "innobackupex"],
        hints=["全量备份文件位于 /backup/full/ 目录", "使用 xtrabackup --apply-log 应用日志"],
        max_retries=2,
        time_limit_minutes=20,
    ),
    "apply_binlog_pitr": TaskDefinition(
        task_id="apply_binlog_pitr",
        title="Binlog时间点恢复(PITR)",
        description="使用mysqlbinlog解析二进制日志，恢复到指定时间点",
        task_type="recovery",
        difficulty="hard",
        expected_commands=["mysqlbinlog", "mysqlbinlog --stop-datetime"],
        hints=["binlog文件位于 /backup/binlog/ 目录", "使用 mysqlbinlog 解析日志"],
        max_retries=2,
        time_limit_minutes=20,
    ),
    "verify_data_integrity": TaskDefinition(
        task_id="verify_data_integrity",
        title="验证数据完整性",
        description="恢复后校验数据完整性，检查是否有被篡改的字段",
        task_type="recovery",
        difficulty="medium",
        expected_commands=["SELECT COUNT(*)", "checksum table", "SELECT * FROM trade_flow"],
        hints=["使用 CHECKSUM TABLE 验证表完整性", "检查 trade_flow 表的关键字段"],
        max_retries=3,
    ),
    "analyze_slow_query_log": TaskDefinition(
        task_id="analyze_slow_query_log",
        title="分析慢查询日志",
        description="分析慢查询日志，定位SQL注入攻击语句",
        task_type="sqli",
        difficulty="easy",
        expected_commands=["tail slow_query.log", "grep UNION", "grep SELECT"],
        hints=["慢查询日志位于 /var/log/mysql/ 目录", "查找包含 UNION 或 SELECT 的可疑语句"],
        max_retries=3,
    ),
    "fix_vulnerable_code": TaskDefinition(
        task_id="fix_vulnerable_code",
        title="修复漏洞代码",
        description="修改后端代码，使用参数化查询替代字符串拼接",
        task_type="sqli",
        difficulty="hard",
        expected_commands=["edit api/user/profile.py", "使用参数化查询"],
        hints=["定位到 user/profile.py 中的查询语句", "将 f-string 拼接改为 ? 占位符"],
        max_retries=3,
        time_limit_minutes=15,
    ),
    "configure_waf": TaskDefinition(
        task_id="configure_waf",
        title="配置WAF规则",
        description="配置ModSecurity规则，拦截SQL注入攻击",
        task_type="waf",
        difficulty="medium",
        expected_commands=["SecRule", "编辑 waf.conf"],
        hints=["WAF配置文件位于 /etc/modsecurity/ 目录", "添加 SecRule 拦截SQL注入"],
        max_retries=3,
    ),
    "generate_report": TaskDefinition(
        task_id="generate_report",
        title="生成审计报告",
        description="生成《数据库安全运维与加固报告》",
        task_type="report",
        difficulty="easy",
        expected_commands=["generate_report", "export pdf"],
        hints=["使用 generate_report 命令生成报告"],
        max_retries=3,
    ),
}


class TaskManager:
    """
    任务管理器

    负责：
    - 任务的注册、分发和状态跟踪
    - 任务结果验证与评分
    - 操作步骤的合规性校验
    - 任务超时和重试管理
    """

    def __init__(self, db: DatabaseConnector):
        self._db = db
        self._task_handlers: Dict[str, Callable] = {}

    def register_handler(self, task_id: str, handler: Callable):
        """注册任务处理器"""
        self._task_handlers[task_id] = handler

    def get_task(self, task_id: str) -> Optional[TaskDefinition]:
        """获取任务定义"""
        return PREDEFINED_TASKS.get(task_id)

    def get_tasks_by_branch(self, branch: str) -> List[TaskDefinition]:
        """获取指定分支的所有任务"""
        from core.agent_orchestrator import STORY_BRANCHES
        branch_info = STORY_BRANCHES.get(branch)
        if not branch_info or "tasks" not in branch_info:
            return []
        return [PREDEFINED_TASKS[t] for t in branch_info["tasks"] if t in PREDEFINED_TASKS]

    def start_task(self, task_id: str, student_id: int = 1) -> Dict[str, Any]:
        """
        开始一个任务

        Args:
            task_id: 任务ID
            student_id: 学员ID

        Returns:
            任务初始信息
        """
        task = self.get_task(task_id)
        if not task:
            return {"error": f"未知任务: {task_id}"}

        # 检查是否已有进行中的任务
        existing = self._db.execute_sqlite(
            "SELECT * FROM task_records WHERE student_id = ? AND task_id = ? AND status = 'in_progress'",
            (student_id, task_id),
        )
        if existing:
            return {"error": "该任务已在进行中", "task": task}

        # 创建任务记录
        self._db.execute_sqlite_insert(
            "INSERT INTO task_records (student_id, task_id, task_name, task_type, status) VALUES (?, ?, ?, ?, ?)",
            (student_id, task_id, task.title, task.task_type, "in_progress"),
        )

        # 记录审计日志
        self._db.execute_sqlite_insert(
            "INSERT INTO audit_logs (student_id, action, detail) VALUES (?, ?, ?)",
            (student_id, "start_task", f"开始任务: {task.title}"),
        )

        return {
            "success": True,
            "task": {
                "task_id": task.task_id,
                "title": task.title,
                "description": task.description,
                "difficulty": task.difficulty,
                "hints": task.hints,
                "expected_commands": task.expected_commands,
                "time_limit_minutes": task.time_limit_minutes,
            },
        }

    def execute_task_command(self, task_id: str, command: str, student_id: int = 1) -> Dict[str, Any]:
        """
        执行任务中的一条命令

        Args:
            task_id: 任务ID
            command: 执行的命令
            student_id: 学员ID

        Returns:
            命令执行结果
        """
        task = self.get_task(task_id)
        if not task:
            return {"error": f"未知任务: {task_id}"}

        # 记录命令
        self._db.execute_sqlite_insert(
            "INSERT INTO command_history (student_id, command, output, is_valid) VALUES (?, ?, ?, ?)",
            (student_id, command, f"执行命令: {command}", 1),
        )

        # 模拟命令执行（根据命令匹配合适的模拟输出）
        output = self._simulate_command_output(command, task)
        is_valid = any(ec.lower() in command.lower() for ec in task.expected_commands)

        return {
            "success": True,
            "command": command,
            "output": output,
            "is_valid": is_valid,
            "hint": task.hints if not is_valid else None,
        }

    def _simulate_command_output(self, command: str, task: TaskDefinition) -> str:
        """模拟命令输出（基于命令关键词匹配）"""
        cmd_lower = command.lower()

        if "baseline" in cmd_lower or "check" in cmd_lower:
            return (
                "=== CIS MySQL Benchmark 安全检查 ===\n"
                "[FAIL] 匿名用户检查: 存在匿名用户(2个)\n"
                "[FAIL] 密码强度检查: 3个用户密码强度不足\n"
                "[FAIL] 过度授权检查: 5个用户存在过度授权\n"
                "[FAIL] 远程root登录: root@% 允许远程登录\n"
                "[FAIL] SSL启用检查: have_ssl=DISABLED\n"
                "[WARN] 默认端口检查: port=3306(默认)\n"
                "[FAIL] 审计日志检查: general_log=OFF\n"
                "[FAIL] 安全函数权限检查: 2个用户拥有FILE权限\n"
                "---\n"
                "总计: 8项检查, 7项失败, 1项警告\n"
                "安全评分: 12.5/100 (严重不达标)"
            )
        elif "show grants" in cmd_lower or "show" in cmd_lower:
            return (
                "Grants for test_user@%:\n"
                "GRANT SELECT, INSERT, UPDATE, DELETE, DROP ON *.* TO 'test_user'@'%'\n"
                "GRANT FILE ON *.* TO 'test_user'@'%'\n"
                "---\n"
                "⚠ 检测到过度授权: 测试账号拥有全局DELETE/DROP权限"
            )
        elif "revoke" in cmd_lower:
            return (
                "Query OK, 1 rows affected\n"
                "权限已撤销: REVOKE DELETE, DROP ON *.* FROM 'test_user'@'%';\n"
                "✓ 操作成功"
            )
        elif "alter user" in cmd_lower or "password" in cmd_lower:
            return (
                "Query OK, 1 rows affected\n"
                "密码已更新，强度评估: 85/100 (强)\n"
                "✓ 密码修改成功"
            )
        elif "xtrabackup" in cmd_lower or "apply-log" in cmd_lower:
            return (
                "[INFO] 备份文件: /backup/full/2024-01-15_full.xb\n"
                "[INFO] 应用redo日志...\n"
                "[INFO] 应用undo日志...\n"
                "[OK] xtrabackup --apply-log 完成\n"
                "✓ 全量备份已准备就绪"
            )
        elif "mysqlbinlog" in cmd_lower:
            return (
                "[INFO] 解析binlog文件: /backup/binlog/mysql-bin.000012\n"
                "[INFO] 时间范围: 2024-01-15 08:00:00 ~ 2024-01-17 18:00:00\n"
                "[INFO] 恢复点: 2024-01-17 17:53:21\n"
                "[OK] 回放binlog完成，恢复1500条交易记录\n"
                "✓ 时间点恢复(PITR)成功"
            )
        elif "checksum" in cmd_lower or "verify" in cmd_lower:
            return (
                "表名                          checksum\n"
                "trade_flow                    0x4A7F2B1C\n"
                "trade_flow_backup             0x4A7F2B1C\n"
                "---\n"
                "✓ 数据完整性校验通过\n"
                "⚠ 注意: 检查发现account_no字段有3条异常数据"
            )
        elif "slow_query" in cmd_lower or "grep" in cmd_lower or "tail" in cmd_lower:
            return (
                "# Time: 2024-01-17T15:23:11.123456Z\n"
                "# User@Host: unknown[192.168.1.105]\n"
                "# Query_time: 2.345  Lock_time: 0.001\n"
                "SELECT * FROM users WHERE id = '1' UNION SELECT * FROM credit_cards--';\n"
                "---\n"
                "⚠ 发现可疑SQL注入语句: UNION SELECT 注入模式"
            )
        elif "edit" in cmd_lower or "参数化" in cmd_lower or "placeholder" in cmd_lower:
            return (
                "文件: /app/api/user/profile.py\n"
                "修复前: cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
                "修复后: cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n"
                "---\n"
                "✓ 已使用参数化查询替代字符串拼接\n"
                "✓ 代码修复完成"
            )
        elif "secrule" in cmd_lower or "waf" in cmd_lower:
            return (
                "WAF规则已添加:\n"
                "SecRule ARGS \"(?:union(?:.+?)select|select(?:.+?)from)\" \\\n"
                '  "phase:2,deny,status:403,id:10001,msg:\'SQL Injection Union Attack\'"\n'
                "---\n"
                "✓ WAF规则配置成功\n"
                "✓ ModSecurity 已重新加载配置"
            )
        elif "report" in cmd_lower or "generate" in cmd_lower:
            return (
                "正在生成《数据库安全运维与加固报告》...\n"
                "[INFO] 收集操作记录...\n"
                "[INFO] 整理漏洞列表...\n"
                "[INFO] 生成修复建议...\n"
                "[INFO] 渲染PDF报告...\n"
                "---\n"
                "✓ 报告已生成: /data/reports/数据库安全运维与加固报告_20240118.pdf"
            )
        else:
            return f"命令 '{command}' 已执行，输出: (模拟环境暂不支持该命令的详细输出)"

    def complete_task(self, task_id: str, student_id: int = 1, result: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        完成任务

        Args:
            task_id: 任务ID
            student_id: 学员ID
            result: 任务结果

        Returns:
            完成结果
        """
        task = self.get_task(task_id)
        if not task:
            return {"error": f"未知任务: {task_id}"}

        # 更新任务记录
        self._db.execute_sqlite(
            "UPDATE task_records SET status = 'completed', result = ?, completed_at = CURRENT_TIMESTAMP "
            "WHERE student_id = ? AND task_id = ?",
            (json.dumps(result or {}), student_id, task_id),
        )

        # 记录审计日志
        self._db.execute_sqlite_insert(
            "INSERT INTO audit_logs (student_id, action, detail) VALUES (?, ?, ?)",
            (student_id, "complete_task", f"完成任务: {task.title}"),
        )

        # 更新学员状态（通过orchestrator）
        from core.agent_orchestrator import get_orchestrator
        orchestrator = get_orchestrator(self._db)
        orchestrator._complete_task(student_id, task_id)

        return {
            "success": True,
            "task_id": task_id,
            "task_name": task.title,
            "message": f"✓ 任务 '{task.title}' 已完成",
        }

    def fail_task(self, task_id: str, student_id: int = 1, reason: str = "") -> Dict[str, Any]:
        """标记任务失败"""
        task = self.get_task(task_id)
        state = self._db.execute_sqlite(
            "SELECT * FROM student_state WHERE id = ?", (student_id,)
        )

        # 更新失败次数
        if state:
            new_failed = state[0]["failed_count"] + 1
            self._db.execute_sqlite(
                "UPDATE student_state SET failed_count = ? WHERE id = ?",
                (new_failed, student_id),
            )

        # 更新任务记录
        self._db.execute_sqlite(
            "UPDATE task_records SET status = 'failed', result = ?, completed_at = CURRENT_TIMESTAMP "
            "WHERE student_id = ? AND task_id = ?",
            (json.dumps({"error": reason}), student_id, task_id),
        )

        # 检查是否达到最大重试次数
        retry_count = len(self._db.execute_sqlite(
            "SELECT * FROM task_records WHERE student_id = ? AND task_id = ? AND status = 'failed'",
            (student_id, task_id),
        ))

        return {
            "success": False,
            "task_id": task_id,
            "error": reason,
            "retry_count": retry_count,
            "max_retries": task.max_retries if task else 3,
            "can_retry": retry_count < (task.max_retries if task else 3),
        }

    def get_task_status(self, task_id: str, student_id: int = 1) -> Dict[str, Any]:
        """获取任务状态"""
        rows = self._db.execute_sqlite(
            "SELECT * FROM task_records WHERE student_id = ? AND task_id = ? ORDER BY started_at DESC LIMIT 1",
            (student_id, task_id),
        )
        if not rows:
            return {"task_id": task_id, "status": "not_started"}
        return dict(rows[0])

    def get_all_tasks_status(self, student_id: int = 1) -> List[Dict[str, Any]]:
        """获取所有任务状态"""
        rows = self._db.execute_sqlite(
            "SELECT * FROM task_records WHERE student_id = ? ORDER BY started_at DESC",
            (student_id,),
        )
        return [dict(r) for r in rows]