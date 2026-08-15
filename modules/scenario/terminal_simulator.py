"""
场景模拟引导模块 - 终端模拟器

模拟数据库命令行终端环境：
- 伪终端（CLI）命令解析与响应
- 模拟的 mysql/psql 命令行界面
- 命令历史记录与回放
- 输出格式化（类真实终端风格）
- **状态化权限系统**：SHOW GRANTS 反映当前真实权限状态
- **交互式SQL执行**：REVOKE/GRANT 等修改实时生效
- **3次错误提示机制**：修复命令错误3次后给出正确答案
"""
import re as re_mod
import shlex
import json
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime

from core.database_connector import DatabaseConnector


# ══════════════════════════════════════════════
# 初始权限状态定义
# ══════════════════════════════════════════════

INITIAL_PERMISSIONS = {
    "test_user@%": {
        "global_privs": ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "FILE", "CREATE", "ALTER"],
        "db_privs": {"*.*": ["ALL"]},
        "role": "测试账号",
        "password": "test123",
    },
    "root@localhost": {
        "global_privs": ["ALL PRIVILEGES"],
        "db_privs": {"*.*": ["ALL"]},
        "role": "管理员",
        "password": "RootP@ss1",
    },
    "root@%": {
        "global_privs": ["ALL PRIVILEGES"],
        "db_privs": {"*.*": ["ALL"]},
        "role": "管理员(远程)",
        "password": "RootP@ss1",
    },
    "dev_user@%": {
        "global_privs": ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE"],
        "db_privs": {"dev_db.*": ["ALL"]},
        "role": "开发账号",
        "password": "dev123",
    },
    "app_user@192.168.%": {
        "global_privs": ["SELECT", "INSERT", "UPDATE", "DELETE"],
        "db_privs": {"app_db.*": ["SELECT", "INSERT", "UPDATE", "DELETE"]},
        "role": "应用账号",
        "password": "AppP@ss456",
    },
    "backup_user@localhost": {
        "global_privs": ["SELECT", "LOCK TABLES"],
        "db_privs": {"*.*": ["SELECT", "LOCK TABLES"]},
        "role": "备份账号",
        "password": "B@ckup789",
    },
    "report_user@localhost": {
        "global_privs": ["SELECT"],
        "db_privs": {"core_bank.*": ["SELECT"]},
        "role": "报表账号",
        "password": "ReportP@ss1",
    },
    "audit_user@localhost": {
        "global_privs": ["SELECT"],
        "db_privs": {"mysql.*": ["SELECT"]},
        "role": "审计账号",
        "password": "AuditP@ss1",
    },
    "''@localhost": {
        "global_privs": [],
        "db_privs": {},
        "role": "匿名用户",
        "password": "",
    },
}


# ══════════════════════════════════════════════
# 修复任务定义（正确修复SQL + 验证逻辑）
# ══════════════════════════════════════════════

FIX_TASKS = [
    {
        "id": "fix_testuser_revoke",
        "title": "撤销 test_user 的过度权限",
        "target_user": "test_user",
        "target_host": "%",
        "expected_actions": [
            {"keyword": "DELETE", "type": "revoke"},
            {"keyword": "DROP", "type": "revoke"},
            {"keyword": "FILE", "type": "revoke"},
        ],
        "expected_sql": "REVOKE DELETE, DROP, FILE ON *.* FROM 'test_user'@'%';",
        "validate": lambda sql, sql_upper: (
            "REVOKE" in sql_upper and
            re_mod.search(r"'test_user'@'%'", sql) and
            ("DELETE" in sql_upper or "DROP" in sql_upper or "FILE" in sql_upper)
        ),
        "hint": "提示：使用 REVOKE + 具体权限 + ON *.* FROM 'test_user'@'%'",
    },
    {
        "id": "fix_root_remote",
        "title": "禁止 root 远程登录",
        "target_user": "root",
        "target_host": "%",
        "expected_actions": [
            {"keyword": "root@%", "type": "delete"},
        ],
        "expected_sql": "DELETE FROM mysql.user WHERE user='root' AND host='%';",
        "validate": lambda sql, sql_upper: (
            ("DELETE FROM MYSQL.USER" in sql_upper or "DROP USER" in sql_upper) and
            ("root" in sql.lower() and "'%'" in sql.lower())
        ),
        "hint": "提示：使用 DELETE FROM mysql.user WHERE user='root' AND host='%'",
    },
    {
        "id": "fix_devuser_revoke",
        "title": "撤销 dev_user 的过度权限",
        "target_user": "dev_user",
        "target_host": "%",
        "expected_actions": [
            {"keyword": "DELETE", "type": "revoke"},
            {"keyword": "DROP", "type": "revoke"},
            {"keyword": "ALTER", "type": "revoke"},
        ],
        "expected_sql": "REVOKE DELETE, DROP, ALTER ON *.* FROM 'dev_user'@'%';",
        "validate": lambda sql, sql_upper: (
            "REVOKE" in sql_upper and
            re_mod.search(r"'dev_user'@'%'", sql) and
            ("DELETE" in sql_upper or "DROP" in sql_upper or "ALTER" in sql_upper)
        ),
        "hint": "提示：使用 REVOKE 撤销 dev_user 的 DELETE/DROP/ALTER 全局权限",
    },
    {
        "id": "fix_anonymous",
        "title": "删除匿名用户",
        "target_user": "''",
        "target_host": "localhost",
        "expected_actions": [
            {"keyword": "匿名", "type": "drop"},
        ],
        "expected_sql": "DROP USER ''@'localhost';",
        "validate": lambda sql, sql_upper: (
            ("DROP USER" in sql_upper or "DELETE FROM" in sql_upper) and
            ("''@'localhost'" in sql.lower() or "'@'localhost" in sql.lower() or "''@localhost" in sql.lower()
             or ("user=''" in sql.lower() and "host='localhost'" in sql.lower()))
        ),
        "hint": "提示：使用 DROP USER ''@'localhost' 删除匿名用户",
    },
    {
        "id": "fix_appuser_revoke",
        "title": "限制 app_user 的权限范围",
        "target_user": "app_user",
        "target_host": "192.168.%",
        "expected_actions": [
            {"keyword": "DELETE", "type": "revoke"},
        ],
        "expected_sql": "REVOKE DELETE ON *.* FROM 'app_user'@'192.168.%';",
        "validate": lambda sql, sql_upper: (
            "REVOKE" in sql_upper and
            re_mod.search(r"'app_user'@'192", sql) and
            ("DELETE" in sql_upper or "DROP" in sql_upper)
        ),
        "hint": "提示：app_user 只需要 SELECT/INSERT/UPDATE，撤销 DELETE 权限",
    },
]


# ══════════════════════════════════════════════
# LLM 判定门槛（ADR-0001 D4）
# ══════════════════════════════════════════════

# 只有变更类命令才会触发 LLM 判定
_MUTATION_KEYWORDS = ('REVOKE', 'GRANT', 'ALTER USER', 'CREATE USER',
                      'DROP USER', 'SET PASSWORD', 'DELETE FROM MYSQL.USER')


def _normalize_sql(raw: str) -> str:
    """规范化命令文本为全大写、去尾分号，与 _execute_sql 的判定口径一致。"""
    return raw.strip().upper().rstrip(";")


def _is_mutation_sql(sql_upper: str) -> bool:
    """是否为变更类命令（_normalize_sql 之后的大写文本）。"""
    return any(sql_upper.startswith(kw) for kw in _MUTATION_KEYWORDS)


# ══════════════════════════════════════════════
# 终端模拟器主类
# ══════════════════════════════════════════════

class TerminalSimulator:
    """
    终端模拟器 - 可交互SQL执行版本

    状态化权限系统 + 3次错误提示 + 进度刷新
    """

    # 模拟文件系统路径（保持不变）
    MOCK_FILESYSTEM = {
        "/": {"type": "dir", "children": ["backup", "var", "etc", "app", "data"]},
        "/backup": {"type": "dir", "children": ["full", "binlog"]},
        "/backup/full": {"type": "dir", "children": ["2024-01-15_full.xb", "2024-01-16_full.xb"]},
        "/backup/binlog": {"type": "dir", "children": ["mysql-bin.000010", "mysql-bin.000011", "mysql-bin.000012"]},
        "/var": {"type": "dir", "children": ["log", "lib"]},
        "/var/log": {"type": "dir", "children": ["mysql"]},
        "/var/log/mysql": {"type": "dir", "children": ["slow_query.log", "error.log", "mysql.log"]},
        "/etc": {"type": "dir", "children": ["modsecurity", "mysql"]},
        "/etc/modsecurity": {"type": "dir", "children": ["waf.conf", "crs-rules"]},
        "/etc/mysql": {"type": "dir", "children": ["my.cnf"]},
        "/app": {"type": "dir", "children": ["api"]},
        "/app/api": {"type": "dir", "children": ["user", "search", "order"]},
        "/app/api/user": {"type": "dir", "children": ["profile.py"]},
        "/app/api/search": {"type": "dir", "children": ["product.py"]},
        "/app/api/order": {"type": "dir", "children": ["query.py"]},
        "/data": {"type": "dir", "children": ["reports"]},
    }

    MOCK_FILES = {
        "/app/api/user/profile.py": (
            "from flask import Flask, request\n"
            "import sqlite3\n\n"
            "@app.route('/api/user/profile')\n"
            "def get_user_profile():\n"
            "    user_id = request.args.get('id')\n"
            "    # 存在SQL注入漏洞的代码\n"
            '    query = f"SELECT * FROM users WHERE id = {user_id} "\n'
            "    cursor.execute(query)\n"
            "    return cursor.fetchall()\n"
        ),
        "/var/log/mysql/slow_query.log": (
            "# Time: 2024-01-17T15:23:11.123456Z\n"
            "# User@Host: unknown[192.168.1.105]\n"
            "# Query_time: 2.345  Lock_time: 0.001\n"
            "SELECT * FROM users WHERE id = '1' UNION SELECT * FROM credit_cards WHERE '1'='1';\n\n"
            "# Time: 2024-01-17T15:23:15.654321Z\n"
            "# User@Host: unknown[192.168.1.105]\n"
            "# Query_time: 3.012  Lock_time: 0.002\n"
            "SELECT * FROM orders WHERE id = 1 OR 1=1;\n"
            "# 攻击来源: /api/user/profile -> 漏洞文件: /app/api/user/profile.py\n"
            "# 建议使用 cat 查看该文件，然后 edit 修复\n"
        ),
        "/etc/modsecurity/waf.conf": (
            "# ModSecurity WAF Configuration\n"
            "# 当前规则: 基础防护\n"
            "SecRuleEngine On\n"
            "SecRequestBodyAccess On\n"
            "# TODO: 添加SQL注入防护规则\n"
        ),
        "/backup/full/2024-01-15_full.xb": "Percona XtraBackup full backup (2024-01-15)\nSize: 2.4GB\nTables: users, credit_cards, trade_flow, accounts",
        "/backup/full/2024-01-16_full.xb": "Percona XtraBackup full backup (2024-01-16)\nSize: 2.5GB\nTables: users, credit_cards, trade_flow, accounts",
        "/backup/binlog/mysql-bin.000010": "MySQL Binary Log (mysql-bin.000010)\nStart: 2024-01-15 00:00:00\nSize: 128MB",
        "/backup/binlog/mysql-bin.000011": "MySQL Binary Log (mysql-bin.000011)\nStart: 2024-01-16 00:00:00\nSize: 256MB",
        "/backup/binlog/mysql-bin.000012": "MySQL Binary Log (mysql-bin.000012)\nStart: 2024-01-17 00:00:00\nSize: 512MB\nContains missing transaction data - use mysqlbinlog for PITR",
    }

    def __init__(self, db: DatabaseConnector):
        self._db = db
        self._current_dir = "~"
        self._db_connected = False
        self._db_prompt = "mysql> "

        # ── 状态化权限系统 ──
        self._permissions = {}

        # ── 3次错误提示计数器 ──
        self._attempt_counts = {task["id"]: 0 for task in FIX_TASKS}
        self._completed_tasks = set()
        self._recovery_sim = None
        self._edit_mode = False
        self._edit_file = None
        self._edit_lines = []

        # ── 从持久化恢复状态 ──
        if not self._restore_state():
            self._reset_permissions()

    def _save_state(self):
        """将当前权限状态持久化到 SQLite"""
        try:
            import json
            state = {
                "permissions": self._permissions,
                "completed": list(self._completed_tasks),
                "attempt_counts": self._attempt_counts,
            }
            self._db.save_state("terminal_state", json.dumps(state, ensure_ascii=False))
        except Exception:
            pass

    def _restore_state(self) -> bool:
        """从 SQLite 恢复权限状态"""
        try:
            import json
            raw = self._db.load_state("terminal_state")
            if not raw:
                return False
            state = json.loads(raw)
            self._permissions = state.get("permissions", {})
            self._completed_tasks = set(state.get("completed", []))
            self._attempt_counts.update(state.get("attempt_counts", {}))
            return bool(self._permissions)
        except Exception:
            return False

    def _reset_permissions(self):
        """重置权限状态到初始（深拷贝防止污染 INITIAL_PERMISSIONS）"""
        import copy
        self._permissions = {}
        self._permissions.update({k: {
            "global_privs": list(v.get("global_privs", [])),
            "db_privs": {dk: list(dv) for dk, dv in v.get("db_privs", {}).items()},
            "role": v.get("role", ""),
            "password": v.get("password", ""),
        } for k, v in INITIAL_PERMISSIONS.items()})

    def reset(self):
        """重置终端状态"""
        self._current_dir = "~"
        self._db_connected = False
        self._db_prompt = "mysql> "
        self._reset_permissions()
        self._attempt_counts = {task["id"]: 0 for task in FIX_TASKS}
        self._completed_tasks = set()
        self._recovery_sim = None
        self._edit_mode = False
        self._edit_file = None
        self._edit_lines = []
        # 清除持久化状态
        try:
            self._db.delete_state("terminal_state")
        except Exception:
            pass

    # ══════════════════════════════════════════
    # 命令解析与分发
    # ══════════════════════════════════════════

    def execute(self, command_line: str, student_id: int = 1) -> Dict[str, Any]:
        """执行终端命令"""
        command_line = command_line.strip()
        if not command_line:
            return {"output": "", "prompt": self._get_prompt()}

        # 记录命令
        self._db.execute_sqlite_insert(
            "INSERT INTO command_history (student_id, command, is_valid) VALUES (?, ?, ?)",
            (student_id, command_line[:500], 1),
        )

        parts = shlex.split(command_line)
        cmd = parts[0].lower() if parts else ""
        args = parts[1:] if len(parts) > 1 else []

        output = ""
        if cmd in ("mysql", "psql"):
            output = self._handle_db_login(cmd, args)
        elif cmd == "exit":
            output = self._handle_exit()
        elif cmd == "clear":
            output = "\033[2J\033[H"
        elif cmd in ("ls", "dir"):
            output = self._handle_ls(args)
        elif cmd == "cd":
            output = self._handle_cd(args)
        elif cmd == "pwd":
            output = self._get_pwd()
        elif cmd == "cat":
            output = self._handle_cat(args)
        elif cmd == "echo":
            output = " ".join(args)
        elif cmd == "help":
            output = self._get_help()
        elif cmd == "run_baseline_check" or cmd == "run_baseline":
            output = self._run_baseline_check()
        elif cmd == "generate_report":
            output = self._generate_report()
        elif cmd == "edit":
            output = self._handle_edit(args)
        elif cmd == "history":
            output = self._get_history(student_id)
        elif self._edit_mode and cmd in ("save", "exit"):
            output = self._handle_edit_save(cmd, command_line, student_id)
        elif cmd.startswith("xtrabackup") or cmd == "xtrabackup":
            output = self._handle_recovery_command(command_line, student_id)
        elif cmd.startswith("mysqlbinlog") or cmd == "mysqlbinlog":
            output = self._handle_recovery_command(command_line, student_id)
        elif command_line.lower().startswith("show timeline"):
            output = self._handle_recovery_command(command_line, student_id)
        elif command_line.lower().startswith("list backup"):
            output = self._handle_recovery_command(command_line, student_id)
        elif command_line.lower().startswith("checksum"):
            output = self._handle_recovery_command(command_line, student_id)
        elif self._edit_mode:
            output = self._handle_edit_input(command_line)
        else:
            # SQL 命令识别（自动进入 mysql 模式）
            sql_upper = command_line.strip().upper()
            sql_keywords = ['REVOKE', 'GRANT', 'ALTER USER', 'DROP USER', 'CREATE USER',
                            'DELETE FROM', 'FLUSH PRIVILEGES', 'SET PASSWORD',
                            'UPDATE MYSQL.USER',
                            'SHOW', 'SELECT', 'USE', 'INSERT', 'CREATE']
            is_sql_command = any(sql_upper.startswith(kw) for kw in sql_keywords)
            if is_sql_command or self._db_connected:
                if not self._db_connected and is_sql_command:
                    self._db_connected = True
                    self._db_prompt = "mysql> "
                    # 输出自动连接提示
                    output = f"自动连接 MySQL 服务器...\nServer version: 8.0.35\n\n"
                output += self._execute_sql(command_line, student_id)
            else:
                output = f"bash: {cmd}: 命令未找到\n\n可用命令: help, ls, cd, cat, pwd, echo, clear, exit, mysql, run_baseline_check, show grants, generate_report"

        return {"output": output, "prompt": self._get_prompt(), "command": command_line}

    def _get_prompt(self) -> str:
        if self._db_connected:
            return self._db_prompt
        return f"{self._current_dir} $ "

    def _get_pwd(self) -> str:
        pwd_map = {"~": "/root", ".": __import__('os').getcwd() if "os" in dir() else "/root"}
        return pwd_map.get(self._current_dir, self._current_dir)

    # ══════════════════════════════════════════
    # 命令处理函数（基础）
    # ══════════════════════════════════════════

    def _handle_db_login(self, cmd: str, args: List[str]) -> str:
        if self._db_connected:
            return "Already connected to database server."
        self._db_connected = True
        self._db_prompt = "mysql> " if cmd == "mysql" else "psql> "
        host = "localhost"
        user = "root"
        for i, arg in enumerate(args):
            if arg == "-h" and i + 1 < len(args):
                host = args[i + 1]
            elif arg == "-u" and i + 1 < len(args):
                user = args[i + 1]
        output = (
            f"Welcome to the MySQL monitor.  Commands end with ; or \\g.\n"
            f"Server version: 8.0.35 MySQL Community Server - GPL\n\n"
            f"Type 'help;' or '\\h' for help. Type '\\c' to clear the current input statement.\n\n"
            f"Connected to: {host} (user: {user})\n"
        )
        self._db.execute_sqlite_insert(
            "INSERT INTO audit_logs (student_id, action, detail) VALUES (?, ?, ?)",
            (1, "db_login", f"登录数据库: {user}@{host}"),
        )
        return output

    def _handle_exit(self) -> str:
        if self._db_connected:
            self._db_connected = False
            self._db_prompt = "mysql> "
            return "Bye\n\nDisconnected from database."
        return "exit"

    def _handle_ls(self, args: List[str]) -> str:
        path = args[0] if args else "."
        resolved = self._resolve_path(path)
        entry = self.MOCK_FILESYSTEM.get(resolved)
        if not entry:
            return f"ls: 无法访问 '{path}': 没有那个文件或目录"
        if entry["type"] == "file":
            return resolved
        children = entry.get("children", [])
        if not children:
            return ""
        cols = 4
        rows = [children[i:i + cols] for i in range(0, len(children), cols)]
        return "\n".join("  ".join(f"{c:<20}" for c in row) for row in rows)

    def _handle_cd(self, args: List[str]) -> str:
        if not args:
            self._current_dir = "~"
            return ""
        target = args[0]
        if target == "..":
            self._current_dir = "/"
        elif target == "~":
            self._current_dir = "~"
        else:
            resolved = self._resolve_path(target)
            entry = self.MOCK_FILESYSTEM.get(resolved)
            if entry and entry["type"] == "dir":
                self._current_dir = resolved
            else:
                return f"cd: {target}: 没有那个文件或目录"
        return ""

    def _handle_cat(self, args: List[str]) -> str:
        if not args:
            return ""
        path = self._resolve_path(args[0])
        content = self.MOCK_FILES.get(path)
        if content is None:
            entry = self.MOCK_FILESYSTEM.get(path)
            if entry and entry["type"] == "dir":
                return f"cat: {args[0]}: 是一个目录"
            return f"cat: {args[0]}: 没有那个文件或目录"
        # 查看慢查询日志自动标记任务完成
        if "slow_query.log" in path:
            from core.agent_orchestrator import get_orchestrator
            try:
                get_orchestrator(self._db)._complete_task(1, "analyze_slow_query_log")
            except Exception:
                pass
        return content



    def _handle_edit(self, args):
        if not args:
            return "用法: edit <文件路径>"
        path = self._resolve_path(args[0])
        fc = self.MOCK_FILES.get(path)
        if fc is None:
            return f"edit: {args[0]}: 没有那个文件或目录"
        self._edit_mode = True
        self._edit_file = path
        self._edit_lines = []
        sep = chr(92) + chr(110)
        fl = fc.split(sep)
        nl = sep.join(f"{i+1:3d}| {l}" for i, l in enumerate(fl))
        eq60 = chr(61) * 60
        return (f"正在编辑: {path}" + chr(10) + eq60 + chr(10) + nl + chr(10) + eq60 + chr(10)
                + "请输入修复后的代码行 (每次一行)" + chr(10)
                + "输入 save 保存, exit 取消" + chr(10))

    def _handle_edit_input(self, command_line):
        self._edit_lines.append(command_line)
        sep = chr(92) + chr(110)
        restored = sep.join(self._edit_lines)
        if self._edit_file:
            self.MOCK_FILES[self._edit_file] = restored
        return f"  已记录: {command_line[:60]}"


    def _handle_edit_save(self, cmd, command_line, student_id):
        if cmd == "exit":
            self._edit_mode = False
            self._edit_file = None
            self._edit_lines = []
            return "已退出编辑模式"
        if cmd == "save" and self._edit_file:
            self._edit_mode = False
            sf = self._edit_file
            self._edit_file = None
            self._edit_lines = []
            nc = self.MOCK_FILES.get(sf, "")
            nl = chr(10)
            from core.agent_orchestrator import get_orchestrator
            orch = get_orchestrator(self._db)
            # WAF配置检测
            if "waf.conf" in sf:
                if "SecRule" in nc:
                    try:
                        orch._complete_task(student_id, "configure_waf")
                    except Exception:
                        pass
                    return "已保存修改到 " + sf + nl + "WAF规则已配置, SQL注入攻击已被拦截!" + nl + "任务已完成!"
                else:
                    # D5: WAF 规则未正确配置 → 1 次失败
                    self._record_fix_failure(student_id, "configure_waf", "WAF规则未正确配置(缺少SecRule)")
                    return "已保存修改到 " + sf + nl + "❌ WAF规则未正确配置(缺少 SecRule 指令)" + nl + "该操作已记为一次失败。"
            # 漏洞代码修复检测
            if "?" in nc and 'f"' not in nc:
                try:
                    orch._complete_task(student_id, "fix_vulnerable_code")
                except Exception:
                    pass
                return "已保存修改到 " + sf + nl + "参数化查询已应用, SQL注入漏洞已修复!" + nl + "任务已完成!"
            else:
                # D5: 代码仍未修复 → 1 次失败
                self._record_fix_failure(student_id, "fix_vulnerable_code", "代码仍存在字符串拼接，未使用参数化查询")
                return "已保存修改到 " + sf + nl + "❌ 仍存在字符串拼接, 请使用 ? 占位符" + nl + "该操作已记为一次失败。"
        return "已退出编辑模式"

    
    
    
    def _handle_recovery_command(self, command_line: str, student_id: int = 1) -> str:
        """处理恢复相关命令（持久化状态+进度更新）。
        D5：命令返回失败（缺参/顺序错/文件错/违反SOP顺序）→ 记 1 次失败。"""
        if self._recovery_sim is None:
            from modules.toolkit.recovery_simulator import RecoverySimulator
            self._recovery_sim = RecoverySimulator()
        result = self._recovery_sim.execute_command(command_line)
        if result.get("success"):
            self._sync_recovery_progress(student_id)
            return result.get("output", str(result))
        else:
            self._record_fix_failure(student_id, "recovery",
                                     (result.get("output") or "恢复命令错误")[:200])
            return (result.get("output", str(result))
                    + "\n\n[提醒] 该命令未成功执行，已记为一次操作失误。")

    def _sync_recovery_progress(self, student_id: int = 1):
        if self._recovery_sim is None:
            return
        steps = self._recovery_sim._executed_steps
        try:
            from core.agent_orchestrator import get_orchestrator
            orch = get_orchestrator(self._db)
            if 2 in steps:
                orch._complete_task(student_id, "restore_full_backup")
            if 3 in steps:
                orch._complete_task(student_id, "apply_binlog_pitr")
            if 4 in steps or 5 in steps:
                orch._complete_task(student_id, "verify_data_integrity")
        except Exception:
            pass

    def _resolve_path(self, path: str) -> str:
        if path.startswith("/"):
            return path
        if path.startswith("~"):
            return path.replace("~", "/root", 1)
        if self._current_dir.startswith("/"):
            base = self._current_dir
        else:
            base = "/root"
        if base.endswith("/"):
            return base + path
        return base + "/" + path

    # ══════════════════════════════════════════
    # ★ 核心：状态化SQL执行引擎
    # ══════════════════════════════════════════

    def _execute_sql(self, sql: str, student_id: int = 1) -> str:
        """执行SQL语句（状态化）"""
        sql_upper = _normalize_sql(sql)

        # ── SHOW GRANTS（读取当前状态） ──
        if sql_upper.startswith("SHOW") and "GRANTS" in sql_upper:
            return self._show_grants_stateful(sql)

        # ── SHOW DATABASES ──
        elif sql_upper.startswith("SHOW DATABASES"):
            return ("+--------------------+\n| Database           |\n+--------------------+\n"
                    "| information_schema |\n| mysql              |\n"
                    "| performance_schema |\n| core_bank          |\n"
                    "| app_db             |\n| dev_db             |\n+--------------------+\n"
                    "6 rows in set (0.00 sec)")

        # ── USE 数据库 ──
        elif sql_upper.startswith("USE "):
            return f"Database changed to {sql_upper.replace('USE ', '').strip()}"

        # ── SHOW TABLES ──
        elif sql_upper.startswith("SHOW TABLES"):
            return ("+---------------------+\n| Tables_in_core_bank |\n+---------------------+\n"
                    "| users               |\n| credit_cards        |\n"
                    "| trade_flow          |\n| accounts            |\n"
                    "| audit_log           |\n+---------------------+\n"
                    "5 rows in set (0.00 sec)")

        # ── SELECT authentication_string FROM mysql.user（密码hash查询） ──
        elif "SELECT" in sql_upper and "AUTHENTICATION_STRING" in sql_upper and "FROM MYSQL.USER" in sql_upper:
            return self._show_users_with_hash(sql, sql_upper)

        # ── SELECT FROM mysql.user（读取当前状态） ──
        elif "SELECT" in sql_upper and "FROM MYSQL.USER" in sql_upper:
            return self._show_users_stateful()

        # ── SHOW VARIABLES（模拟MySQL系统变量） ──
        elif sql_upper.startswith("SHOW VARIABLES") or sql_upper.startswith("SHOW GLOBAL VARIABLES"):
            return self._handle_show_variables(sql, sql_upper)

        # ── STATUS（模拟MySQL状态） ──
        elif sql_upper.startswith("STATUS") or sql_upper.startswith("\\s"):
            return self._handle_status()

        # ── SELECT FROM users ──
        elif "SELECT" in sql_upper and "FROM USERS" in sql_upper and "MYSQL" not in sql_upper:
            return ("+----+------------------+---------------------+\n"
                    "| id | username          | email               |\n"
                    "+----+------------------+---------------------+\n"
                    "| 1  | admin            | admin@corebank.com  |\n"
                    "| 2  | user01           | user01@example.com  |\n"
                    "| 3  | user02           | user02@example.com  |\n"
                    "+----+------------------+---------------------+\n"
                    "3 rows in set (0.00 sec)")

        # ── 检测SQL注入攻击 ──
        elif "UNION" in sql_upper or "OR 1=1" in sql_upper:
            return ("⚠ 安全告警: 检测到SQL注入攻击特征!\n"
                    "攻击类型: UNION注入 / 恒真条件注入\n"
                    "来源IP: 192.168.1.105\n"
                    "建议: 请勿在生产环境执行恶意SQL语句!")

        # ── ★ LLM 判定：变更类命令且存在待修复错误点 ──
        #   仅对"疑似修复命令"调用 LLM 裁决；LLM 不可用/超时自动降级到下方确定性逻辑
        if _is_mutation_sql(sql_upper):
            pending = self._pending_fix_tasks()
            if pending:
                handled, out = self._llm_judge_and_handle(sql, sql_upper, student_id, pending)
                if handled:
                    return out
                if out:
                    # 未命中任何待修复错误点（或仅安全告警）→ 提示后降级到确定性执行
                    return out + self._run_deterministic_mutation(sql, sql_upper, student_id)
                # out 为空 → LLM 不可用，继续下方确定性分发

        # ── ★ REVOKE（状态化执行 + 验证 + 3次提示） ──
        elif sql_upper.startswith("REVOKE"):
            return self._handle_revoke_stateful(sql, sql_upper, student_id)

        # ── GRANT ──
        elif sql_upper.startswith("GRANT"):
            return self._handle_grant_stateful(sql, sql_upper)

        # ── ALTER USER ──
        elif sql_upper.startswith("ALTER USER"):
            return self._handle_alter_user_stateful(sql, sql_upper)

        # ── CREATE USER（状态化） ──
        elif sql_upper.startswith("CREATE USER"):
            return self._handle_create_user_stateful(sql, sql_upper)

        # ── DROP USER（状态化） ──
        elif sql_upper.startswith("DROP USER"):
            return self._handle_drop_user_stateful(sql, sql_upper, student_id)

        # ── DELETE FROM mysql.user（状态化） ──
        elif "DELETE FROM MYSQL.USER" in sql_upper:
            return self._handle_delete_user_stateful(sql, sql_upper, student_id)

        # ── FLUSH PRIVILEGES ──
        elif sql_upper.startswith("FLUSH PRIVILEGES"):
            return ("Query OK, 1 rows affected (0.01 sec)\n\n"
                    "✓ 权限已刷新，所有权限更改立即生效")

        # ── SET PASSWORD ──
        elif sql_upper.startswith("SET PASSWORD"):
            return ("Query OK, 1 rows affected (0.02 sec)\n\n"
                    "✓ 密码已设置，强度评估: 88/100")

        # ── 其他 SQL ──
        else:
            return "Query OK, 1 rows affected (0.01 sec)"

    # ══════════════════════════════════════════
    # ★ 状态化SHOW GRANTS
    # ══════════════════════════════════════════

    def _show_grants_stateful(self, sql: str = "") -> str:
        """根据当前状态显示权限"""
        # 解析要查看的用户
        user_match = re_mod.search(r"FOR\s+'([^']+)'@'([^']+)'", sql, re_mod.IGNORECASE)
        if user_match:
            username = user_match.group(1)
            host = user_match.group(2)
            # 处理匿名用户 ''@localhost 的特殊情况
            if username == "" and "''" in sql:
                username = "''"
            target_user = f"{username}@{host}"
        else:
            target_user = "test_user@%"

        if target_user not in self._permissions:
            return f"ERROR: 用户 {target_user} 不存在\n"

        perms = self._permissions[target_user]
        global_privs = perms.get("global_privs", [])
        db_privs = perms.get("db_privs", {})

        lines = [
            "+----------------------------------------------------------------------+",
            f"| Grants for {target_user:<62s}|",
            "+----------------------------------------------------------------------+",
        ]

        if not global_privs and not db_privs:
            lines.append(f"| (该用户没有任何权限)                                           |")
        else:
            # 构建用户引用字符串
            user_ref = f"'{user_match.group(1)}'@'{user_match.group(2)}'" if user_match else target_user
            for priv in global_privs:
                if priv == "ALL PRIVILEGES":
                    lines.append(f"| GRANT ALL PRIVILEGES ON *.* TO {user_ref:<55s}|")
                else:
                    lines.append(f"| GRANT {priv:<20s} ON *.* TO {user_ref:<30s}|")
            for db, privs in db_privs.items():
                for priv in privs:
                    lines.append(f"| GRANT {priv:<20s} ON {db:<15s} TO {user_ref:<30s}|")

        lines.append("+----------------------------------------------------------------------+")
        priv_count = max(len(global_privs) + sum(len(v) for v in db_privs.values()), 0)
        lines.append(f"{priv_count} row(s) in set (0.00 sec)")

        # 检查是否存在过度授权问题（教学提示）
        warning = self._check_excessive_privs(target_user, perms)
        if warning:
            lines.append(f"\n{warning}")

        return "\n".join(lines)

    def _check_excessive_privs(self, username: str, perms: dict) -> str:
        """检查过度授权并给出提示"""
        privs = perms.get("global_privs", [])
        issues = []
        if "DELETE" in privs and perms.get("role") in ("测试账号", "开发账号", "应用账号"):
            issues.append("全局DELETE权限")
        if "DROP" in privs and perms.get("role") in ("测试账号", "开发账号", "应用账号"):
            issues.append("全局DROP权限")
        if "FILE" in privs and perms.get("role") not in ("管理员",):
            issues.append("FILE权限（可读取服务器文件）")
        if "ALL PRIVILEGES" in privs and perms.get("role") not in ("管理员",):
            issues.append("ALL PRIVILEGES（过度授权）")
        if username.endswith("@%"):
            issues.append("允许任意IP(%)连接")

        if issues:
            return ("⚠ 安全警告: 该用户存在以下风险:\n"
                    + "\n".join(f"  • {issue}" for issue in issues)
                    + "\n建议遵循最小权限原则，使用 REVOKE 撤销多余权限")
        return ""

    # ══════════════════════════════════════════
    # ★ 状态化SHOW TABLES / SELECT FROM mysql.user
    # ══════════════════════════════════════════

    def _show_users_stateful(self) -> str:
        """根据当前状态显示用户列表"""
        lines = ["+----------+-----------+-----------+",
                 "| user     | host      | status    |",
                 "+----------+-----------+-----------+"]
        for user_key, perms in self._permissions.items():
            u, h = user_key.split("@")
            u_display = f"'{u}'" if u else "''"
            status = "ACTIVE" if perms.get("global_privs") else "NO_PRIVS"
            lines.append(f"| {u_display:<8s} | {h:<9s} | {status:<9s} |")
        lines.append("+----------+-----------+-----------+")
        lines.append(f"{len(self._permissions)} rows in set (0.00 sec)")
        return "\n".join(lines)

    def _show_users_with_hash(self, sql: str, sql_upper: str) -> str:
        """SELECT authentication_string FROM mysql.user — 显示密码hash"""
        sql_lower = sql.lower()
        target_user = None
        if "where" in sql_lower:
            import re as re_mod2
            um = re_mod2.search(r"user\s*=\s*'([^']*)'", sql_lower)
            if um:
                target_user = um.group(1)

        lines = ["+------------------+-----------+-------------------------------------------+",
                 "| user             | host      | authentication_string                     |",
                 "+------------------+-----------+-------------------------------------------+"]
        for user_key, perms in self._permissions.items():
            u, h = user_key.split("@")
            if target_user and u != target_user and u != f"'{target_user}'":
                continue
            u_display = f"'{u}'" if u else "''"
            auth_hash = self._mock_password_hash(u, perms.get("password", ""))
            lines.append(f"| {u_display:<16s} | {h:<9s} | {auth_hash:<41s} |")
        lines.append("+------------------+-----------+-------------------------------------------+")
        return "\n".join(lines)

    @staticmethod
    def _mock_password_hash(username: str, password: str) -> str:
        """基于实际密码生成模拟密码hash"""
        if not password:
            return ""
        import hashlib
        return f"*{hashlib.md5(password.encode()).hexdigest().upper()[:40]}"

    # SHOW VARIABLES handler
    def _handle_show_variables(self, sql: str, sql_upper: str) -> str:
        sql_lower = sql.lower()
        if "have_ssl" in sql_lower:
            return ("+---------------+-------+\n| Variable_name | Value |\n+---------------+-------+\n| have_ssl      | YES   |\n+---------------+-------+\n1 row in set (0.00 sec)")
        elif "ssl" in sql_lower:
            return ("+-------------------------------+---------------------+\n| Variable_name                 | Value               |\n+-------------------------------+---------------------+\n| have_openssl                  | YES                 |\n| have_ssl                      | YES                 |\n| ssl_ca                        | /etc/mysql/ca.pem   |\n| ssl_cert                      | /etc/mysql/server-cert.pem |\n| ssl_key                       | /etc/mysql/server-key.pem  |\n+-------------------------------+---------------------+\n5 rows in set (0.00 sec)")
        elif "port" in sql_lower:
            return ("+---------------+-------+\n| Variable_name | Value |\n+---------------+-------+\n| port          | 3306  |\n+---------------+-------+\n1 row in set (0.00 sec)")
        elif "version" in sql_lower:
            return ("+-------------------------+---------------------------+\n| Variable_name           | Value                     |\n+-------------------------+---------------------------+\n| version                 | 8.0.35                    |\n| version_comment         | MySQL Community Server    |\n| version_compile_machine | x86_64                    |\n+-------------------------+---------------------------+\n3 rows in set (0.00 sec)")
        elif "log" in sql_lower or "general" in sql_lower:
            return ("+-------------------+-------+\n| Variable_name     | Value |\n+-------------------+-------+\n| general_log       | ON    |\n| general_log_file  | /var/log/mysql/mysql.log |\n| slow_query_log    | ON    |\n| slow_query_log_file | /var/log/mysql/slow_query.log |\n+-------------------+-------+\n4 rows in set (0.00 sec)")
        else:
            return ("+-------------------------+---------------------+\n| Variable_name           | Value               |\n+-------------------------+---------------------+\n| version                 | 8.0.35              |\n| port                    | 3306                |\n| have_ssl                | YES                 |\n| general_log             | ON                  |\n| slow_query_log          | ON                  |\n| max_connections         | 151                 |\n| character_set_server    | utf8mb4             |\n| collation_server        | utf8mb4_unicode_ci  |\n+-------------------------+---------------------+\n8 rows in set (0.00 sec)")

    def _handle_status(self) -> str:
        return ("--------------\nmysql  Ver 8.0.35 for Linux on x86_64 (MySQL Community Server - GPL)\n\n"
                "Connection id:          12\nCurrent database:       core_bank\nCurrent user:           root@localhost\n"
                "SSL:                    Cipher in use is TLS_AES_256_GCM_SHA384\n"
                "Server version:         8.0.35 MySQL Community Server - GPL\n"
                "Protocol version:       10\nConnection:             Localhost via UNIX socket\n"
                "Server characterset:    utf8mb4\nDb characterset:        utf8mb4\n"
                "Client characterset:    utf8mb4\nConn. characterset:     utf8mb4\n"
                "UNIX socket:            /var/run/mysqld/mysqld.sock\n"
                "Uptime:                 7 days 12 hours 34 min 21 sec\n\n"
                "Threads: 2  Questions: 15897  Slow queries: 3  Opens: 124  Flush tables: 1\n"
                "Open tables: 76  Queries per second avg: 0.025\n--------------")

    # ══════════════════════════════════════════
    # ★ 状态化REVOKE + 验证 + 3次提示
    # ══════════════════════════════════════════

    def _handle_revoke_stateful(self, sql: str, sql_upper: str, student_id: int) -> str:
        """执行 REVOKE - 状态化修改权限"""
        # 解析用户和权限
        user_match = re_mod.search(r"FROM\s+'([^']+)'@'([^']+)'", sql)
        if not user_match:
            return ("ERROR 1064: SQL 语法错误\n"
                    "正确用法: REVOKE privilege ON *.* FROM 'user'@'host';\n"
                    "例如: REVOKE DELETE, DROP ON *.* FROM 'test_user'@'%';")

        target_user_key = f"{user_match.group(1)}@{user_match.group(2)}"

        # 检查用户是否存在
        if target_user_key not in self._permissions:
            return f"ERROR 1146: 用户 '{user_match.group(1)}'@'{user_match.group(2)}' 不存在"

        # 解析撤销的权限
        priv_match = re_mod.search(r"REVOKE\s+(.+?)\s+ON", sql_upper)
        if not priv_match:
            return ("ERROR 1064: 无法解析要撤销的权限\n"
                    "正确用法: REVOKE DELETE, DROP ON *.* FROM 'user'@'host';")

        privs_to_revoke = [p.strip() for p in priv_match.group(1).split(",")]

        # ── 验证：检查这个 REVOKE 是否匹配某个修复任务 ──
        matched_task = self._find_matching_fix_task("revoke", target_user_key, privs_to_revoke)

        if matched_task:
            # 这是一个修复任务 → 执行验证
            return self._execute_fix_task(sql, sql_upper, matched_task, target_user_key,
                                          privs_to_revoke, student_id)

        # ── 非任务匹配的普通REVOKE → 直接执行状态修改 ──
        current_privs = self._permissions[target_user_key]["global_privs"]
        # 处理 REVOKE ALL (PRIVILEGES) 语法 → 清空所有权限
        revoke_all = any(p.upper() in ("ALL", "ALL PRIVILEGES") for p in privs_to_revoke)
        if revoke_all or "ALL PRIVILEGES" in privs_to_revoke:
            current_privs.clear()
            # 同时清空数据库级别权限，防止 SHOW GRANTS 仍显示旧权限
            self._permissions[target_user_key]["db_privs"].clear()
            self._save_state()
            self._log_perm_change(student_id, "REVOKE", user_match.group(1),
                                  user_match.group(2), "ALL PRIVILEGES")
            return (f"Query OK, 1 rows affected (0.02 sec)\n\n"
                    f"✓ 已撤销 {target_user_key} 的所有权限\n"
                    f"  当前权限: (无)\n"
                    f"  执行 SHOW GRANTS FOR '{user_match.group(1)}'@'{user_match.group(2)}' 验证")

        actually_revoked = [p for p in privs_to_revoke if p in current_privs]
        if not actually_revoked:
            return (f"Query OK, 0 rows affected (0.01 sec)\n\n"
                    f"注意: 用户 {target_user_key} 当前不拥有这些权限: {', '.join(privs_to_revoke)}\n"
                    f"当前权限: {', '.join(current_privs) if current_privs else '(无)'}")

        # 执行撤销
        for p in actually_revoked:
            if p in current_privs:
                current_privs.remove(p)

        self._log_perm_change(student_id, "REVOKE", user_match.group(1),
                              user_match.group(2), ", ".join(actually_revoked))

        return (f"Query OK, 1 rows affected (0.02 sec)\n\n"
                f"✓ 权限已撤销: {', '.join(actually_revoked)}\n"
                f"  用户 {target_user_key} 当前权限: {', '.join(current_privs) if current_privs else '(无)'}\n"
                f"  执行 SHOW GRANTS FOR '{user_match.group(1)}'@'{user_match.group(2)}' 验证")

    # ══════════════════════════════════════════
    # ★ 修复任务匹配与执行（含3次提示）
    # ══════════════════════════════════════════

    def _find_matching_fix_task(self, action_type: str, target_user: str, privs: list) -> Optional[dict]:
        """查找匹配的修复任务（按操作类型+目标用户）"""
        # 操作类型映射
        type_map = {"revoke": ["revoke"], "drop": ["drop", "delete"], "delete": ["drop", "delete"]}
        allowed_types = type_map.get(action_type, [action_type])
        for task in FIX_TASKS:
            if task["id"] in self._completed_tasks:
                continue
            # 检查操作类型是否匹配
            task_action_types = set(a["type"] for a in task["expected_actions"])
            if not any(t in allowed_types for t in task_action_types):
                continue
            expected_user = f"{task['target_user']}@{task['target_host']}"
            if target_user == expected_user:
                return task
        return None

    def _execute_fix_task(self, sql: str, sql_upper: str, task: dict,
                          target_user: str, privs: list, student_id: int) -> str:
        """执行修复任务验证"""
        task_id = task["id"]
        self._attempt_counts.setdefault(task_id, 0)

        # 检查验证函数
        is_correct = task["validate"](sql, sql_upper)

        if is_correct:
            # ✓ 正确：执行状态修改
            current_privs = self._permissions[target_user]["global_privs"]
            has_drop_action = any(a["type"] in ("drop", "delete") for a in task["expected_actions"])
            for action in task["expected_actions"]:
                kw = action["keyword"]
                if kw == "ALL PRIVILEGES":
                    current_privs.clear()
                elif kw in current_privs:
                    current_privs.remove(kw)

            # 如果是 DROP 类型任务，直接从权限表中删除该用户
            if has_drop_action:
                del self._permissions[target_user]

            # 持久化状态
            self._save_state()

            # 标记任务完成
            self._completed_tasks.add(task_id)
            self._attempt_counts[task_id] = 0

            # 记录到数据库
            self._log_perm_change(student_id, "REVOKE",
                                  task["target_user"], task["target_host"],
                                  ", ".join(a["keyword"] for a in task["expected_actions"]))

            # 刷新进度（更新tasks表）
            branch_complete = self._update_task_progress(task_id, student_id)

            result = (f"Query OK, 1 rows affected (0.02 sec)\n\n"
                      f"✓ 修复成功！已撤销 {target_user} 的 {', '.join(a['keyword'] for a in task['expected_actions'])} 权限\n"
                      f"✅ 任务「{task['title']}」已完成！\n"
                      f"   执行 SHOW GRANTS FOR '{task['target_user']}'@'{task['target_host']}' 验证")

            # 不在此处显示下一阶段信息，用户可通过点击左侧故事线按钮查看进度
            if branch_complete:
                result += "\n💡 当前分支所有修复任务已完成！点击左侧故事线按钮查看下一阶段。\n"

            return result

        else:
            # ✗ 错误：每次错误尝试记一次失败（D2），并保留教学提示
            self._attempt_counts[task_id] = self._attempt_counts.get(task_id, 0) + 1
            attempts = self._attempt_counts[task_id]
            self._record_fix_failure(student_id, task_id, f"修复命令不正确: {task['expected_sql']}")
            hint = task["hint"]
            if attempts >= 3:
                hint += f"\n正确答案: {task['expected_sql']}"
            return (f"❌ SQL 语句不完全正确。\n"
                    f"  {hint}\n"
                    f"  该命令已记为一次操作失误。")

    # ══════════════════════════════════════════
    # ★ LLM 判定辅助（ADR-0001）
    # ══════════════════════════════════════════

    def will_trigger_llm(self, command_line: str) -> bool:
        """预测该命令执行时是否会触发 LLM 判定（ADR-0001 D4 门槛）。

        供路由在调用 execute **之前**决定是否推送"正在分析中..."提示，
        从而保证提示先于 LLM 调用刷到客户端。门槛与 _execute_sql 内部门槛同源
        （_is_mutation_sql + _pending_fix_tasks），单一来源不漂移。
        """
        return _is_mutation_sql(_normalize_sql(command_line)) and bool(self._pending_fix_tasks())

    def _pending_fix_tasks(self) -> List[dict]:
        """当前未完成的修复任务（即待修复错误点清单）。"""
        return [t for t in FIX_TASKS if t["id"] not in self._completed_tasks]

    def _render_error_points(self, pending: List[dict]) -> str:
        """将待修复错误点渲染为 LLM 可读文本。"""
        if not pending:
            return "(无待修复错误点)"
        lines = []
        for t in pending:
            lines.append(f"- id: {t['id']}")
            lines.append(f"  错误点: {t['title']}")
            lines.append(f"  期望修复: {t['expected_sql']}")
            lines.append(f"  目标用户: {t['target_user']}@{t['target_host']}")
        return "\n".join(lines)

    def _render_perms(self) -> str:
        """渲染当前权限状态快照。"""
        try:
            return json.dumps(self._permissions, ensure_ascii=False, default=str)
        except Exception:
            return str(self._permissions)

    def _record_fix_failure(self, student_id: int, task_id: Optional[str], error: str):
        """记录一次操作失误（D2：1 次失误 = 1 次失败），并持久化尝试计数。"""
        try:
            from core.agent_orchestrator import get_orchestrator
            orch = get_orchestrator(self._db)
            orch._record_failure(student_id, task_id or "sql_operation_error", error)
        except Exception:
            pass
        try:
            self._save_state()  # 失败时也保存，防止重启丢失尝试计数
        except Exception:
            pass

    def _llm_judge_and_handle(self, sql: str, sql_upper: str, student_id: int,
                              pending: List[dict]):
        """调用 LLM 裁决并按 ADR-0001 D6 记账。

        Returns:
            (handled, out)：
            - handled=True  → out 为最终终端输出，直接返回
            - handled=False → out 为空表示 LLM 不可用（降级到确定性逻辑）；
                              out 非空表示"未命中错误点"提示（含可能的安全告警），
                              调用方须将其拼接到确定性执行结果前。
        """
        try:
            from modules.toolkit.sql_judge import judge_sql
        except Exception:
            return False, ""

        verdict = judge_sql(sql, self._render_error_points(pending), self._render_perms())
        if verdict is None:
            return False, ""  # LLM 不可用/超时 → 降级

        warn = ""
        if verdict.get("security_issue"):
            warn = ("⚠ 安全告警: 该 SQL 存在安全风险("
                    + (verdict.get("explanation") or "疑似注入/危险操作") + ")\n\n")

        # 语法错误 → 1 次失败
        if not verdict.get("syntax_valid"):
            self._record_fix_failure(student_id, None, verdict.get("syntax_error") or "SQL 语法错误")
            return True, warn + ("❌ SQL 语法错误: %s\n该命令已记为一次操作失误。\n"
                                 % (verdict.get("syntax_error") or "无法解析"))

        target = verdict.get("targets_error_point")

        # 正确修复 → 完成任务
        if target and verdict.get("fixes_error_point"):
            self._apply_fix_state_change(target, student_id)
            return True, warn + self._complete_fix_task(target, student_id)

        # 命中错误点但未修复 → 1 次失败
        if target:
            task = next((t for t in pending if t["id"] == target), None)
            title = task["title"] if task else target
            self._record_fix_failure(student_id, target, f"针对「{title}」的修复命令未正确执行")
            return True, warn + ("❌ 该命令不能修复「%s」。\n%s\n该命令已记为一次操作失误。\n"
                                 % (title, verdict.get("explanation") or ""))

        # 未命中任何错误点 → 提示 + 安全告警，不计失败，降级到确定性执行
        return False, warn + "ℹ 该操作未命中当前待修复项。\n\n"

    def _apply_fix_state_change(self, task_id: str, student_id: int) -> bool:
        """按修复任务确定性应用权限状态变更（LLM 判定成功后调用）。"""
        task = next((t for t in FIX_TASKS if t["id"] == task_id), None)
        if not task:
            return False
        target_user = f"{task['target_user']}@{task['target_host']}"
        if target_user in self._permissions:
            current_privs = self._permissions[target_user]["global_privs"]
            has_drop_action = any(a["type"] in ("drop", "delete") for a in task["expected_actions"])
            for action in task["expected_actions"]:
                kw = action["keyword"]
                if kw == "ALL PRIVILEGES":
                    current_privs.clear()
                elif kw in current_privs:
                    current_privs.remove(kw)
            if has_drop_action:
                del self._permissions[target_user]
        self._save_state()
        self._completed_tasks.add(task_id)
        self._attempt_counts[task_id] = 0
        return True

    def _complete_fix_task(self, task_id: str, student_id: int) -> str:
        """完成任务并返回成功提示。"""
        task = next((t for t in FIX_TASKS if t["id"] == task_id), None)
        title = task["title"] if task else task_id
        target_user = task["target_user"] if task else ""
        target_host = task["target_host"] if task else ""
        try:
            self._log_perm_change(student_id, "REVOKE", target_user, target_host,
                                  ", ".join(a["keyword"] for a in task["expected_actions"]) if task else "")
        except Exception:
            pass
        branch_complete = self._update_task_progress(task_id, student_id)
        result = (f"Query OK, 1 rows affected (0.02 sec)\n\n"
                  f"✓ 修复成功！已完成「{title}」\n"
                  f"✅ 任务已完成！\n"
                  f"   执行 SHOW GRANTS FOR '{target_user}'@'{target_host}' 验证")
        if branch_complete:
            result += "\n💡 当前分支所有修复任务已完成！点击左侧故事线按钮查看下一阶段。\n"
        return result

    def _run_deterministic_mutation(self, sql: str, sql_upper: str, student_id: int) -> str:
        """未命中错误点时的确定性执行（与既有状态化处理器保持一致）。"""
        if sql_upper.startswith("REVOKE"):
            return self._handle_revoke_stateful(sql, sql_upper, student_id)
        if sql_upper.startswith("GRANT"):
            return self._handle_grant_stateful(sql, sql_upper)
        if sql_upper.startswith("ALTER USER"):
            return self._handle_alter_user_stateful(sql, sql_upper)
        if sql_upper.startswith("CREATE USER"):
            return self._handle_create_user_stateful(sql, sql_upper)
        if sql_upper.startswith("DROP USER"):
            return self._handle_drop_user_stateful(sql, sql_upper, student_id)
        if "DELETE FROM MYSQL.USER" in sql_upper:
            return self._handle_delete_user_stateful(sql, sql_upper, student_id)
        if sql_upper.startswith("SET PASSWORD"):
            return ("Query OK, 1 rows affected (0.02 sec)\n\n"
                    "✓ 密码已设置，强度评估: 88/100")
        return "Query OK, 1 rows affected (0.01 sec)"

    # ══════════════════════════════════════════
    # ★ GRANT（状态化）
    # ══════════════════════════════════════════

    def _handle_grant_stateful(self, sql: str, sql_upper: str) -> str:
        user_match = re_mod.search(r"TO\s+'([^']+)'@'([^']+)'", sql, re_mod.IGNORECASE)
        if not user_match:
            # 试试解析没有@host的格式
            user_match = re_mod.search(r"TO\s+'([^']+)'", sql, re_mod.IGNORECASE)
            if user_match:
                target_key = f"{user_match.group(1)}@%"
                self._permissions.setdefault(target_key, {"global_privs": [], "db_privs": {}, "role": "自定义"})
                priv_match = re_mod.search(r"GRANT\s+(.+?)\s+ON", sql_upper)
                if priv_match:
                    for p in [x.strip() for x in priv_match.group(1).split(",")]:
                        if p not in self._permissions[target_key]["global_privs"]:
                            self._permissions[target_key]["global_privs"].append(p)
                return (f"Query OK, 1 rows affected (0.01 sec)\n\n"
                        f"✓ 权限授予成功: {target_key}\n"
                        f"  执行 SHOW GRANTS 验证")
            return "ERROR 1064: GRANT 语法错误\n正确用法: GRANT SELECT ON db.* TO 'user'@'host';"

        target_key = f"{user_match.group(1)}@{user_match.group(2)}"
        if target_key not in self._permissions:
            self._permissions[target_key] = {"global_privs": [], "db_privs": {}, "role": "自定义"}

        priv_match = re_mod.search(r"GRANT\s+(.+?)\s+ON", sql_upper)
        if priv_match:
            for p in [x.strip() for x in priv_match.group(1).split(",")]:
                if p not in self._permissions[target_key]["global_privs"]:
                    self._permissions[target_key]["global_privs"].append(p)
        self._save_state()

        return (f"Query OK, 1 rows affected (0.01 sec)\n\n"
                f"✓ 权限授予成功: {target_key}\n"
                f"  执行 SHOW GRANTS FOR '{user_match.group(1)}'@'{user_match.group(2)}' 验证")

    # ══════════════════════════════════════════
    # ★ CREATE USER（状态化）— 新增
    # ══════════════════════════════════════════

    def _handle_create_user_stateful(self, sql: str, sql_upper: str) -> str:
        """处理 CREATE USER — 在状态中创建用户"""
        user_match = re_mod.search(r"'([^']*)'@'([^']+)'", sql)
        if not user_match:
            return ("ERROR 1064: CREATE USER 语法错误\n"
                    "正确用法: CREATE USER 'user'@'host' IDENTIFIED BY 'password';\n"
                    "例如: CREATE USER 'test_user'@'%' IDENTIFIED BY 'StrongP@ss123';")

        new_user_key = f"{user_match.group(1)}@{user_match.group(2)}"

        # 如果用户已存在，报错
        if new_user_key in self._permissions:
            return (f"ERROR 1396: 用户 '{user_match.group(1)}'@'{user_match.group(2)}' 已存在\n"
                    f"提示: 可以先 DROP 再 CREATE，或使用 ALTER USER 修改属性")

        # 解析密码强度（模拟）
        pwd_strength = "85/100"
        if "IDENTIFIED BY" in sql_upper:
            pwd_match = re_mod.search(r"IDENTIFIED BY\s+'([^']+)'", sql)
            if pwd_match:
                pwd = pwd_match.group(1)
                # 模拟密码强度评估
                if len(pwd) >= 12 and any(c.isupper() for c in pwd) and any(c.isdigit() for c in pwd):
                    pwd_strength = "95/100 (强)"
                elif len(pwd) >= 8:
                    pwd_strength = "75/100 (中)"
                else:
                    pwd_strength = "40/100 (弱) — 建议使用更长的密码"

        # 创建用户
        self._permissions[new_user_key] = {
            "global_privs": [],
            "db_privs": {},
            "role": "自定义",
        }

        # 记录审计日志
        try:
            self._db.execute_sqlite_insert(
                "INSERT INTO audit_logs (student_id, action, detail) VALUES (?, ?, ?)",
                (1, "create_user", f"创建用户: {new_user_key}"),
            )
        except Exception:
            pass

        self._save_state()

        return (f"Query OK, 1 rows affected (0.01 sec)\n\n"
                f"✓ 用户 '{user_match.group(1)}'@'{user_match.group(2)}' 已创建\n"
                f"  密码强度评估: {pwd_strength}\n"
                f"  该用户当前没有任何权限，使用 GRANT 授予权限")

    # ══════════════════════════════════════════
    # ★ DROP USER（状态化）
    # ══════════════════════════════════════════

    def _handle_drop_user_stateful(self, sql: str, sql_upper: str, student_id: int) -> str:
        user_match = re_mod.search(r"'([^']*)'@'([^']+)'", sql)
        if not user_match:
            return "ERROR 1064: DROP USER 语法错误\n正确用法: DROP USER 'user'@'host';"

        username = user_match.group(1)
        host = user_match.group(2)
        # 处理匿名用户 ''@localhost 的特殊情况
        if username == "" and "''" in sql:
            username = "''"
        target_key = f"{username}@{host}"
        if target_key not in self._permissions:
            return f"ERROR 1146: 用户 '{user_match.group(1)}'@'{user_match.group(2)}' 不存在"

        # 检查是否是修复任务
        task = self._find_matching_fix_task("drop", target_key, [])
        if task:
            # 验证
            return self._execute_fix_task(sql, sql_upper, task, target_key, [], student_id)

        # 直接删除
        del self._permissions[target_key]
        self._save_state()
        self._log_perm_change(student_id, "DROP USER", user_match.group(1), user_match.group(2), "DROP USER")
        return (f"Query OK, 1 rows affected (0.01 sec)\n\n"
                f"✓ 用户 {target_key} 已删除")

    # ══════════════════════════════════════════
    # ★ DELETE FROM mysql.user（状态化）
    # ══════════════════════════════════════════

    def _handle_delete_user_stateful(self, sql: str, sql_upper: str, student_id: int) -> str:
        # 提取 WHERE 条件
        user_m = re_mod.search(r"user='([^']*)'", sql)
        host_m = re_mod.search(r"host='([^']+)'", sql)
        if not user_m or not host_m:
            # 手动指定
            target_key = None
            if "'root'" in sql and "'%'" in sql:
                target_key = "root@%"
        else:
            username = user_m.group(1)
            hostname = host_m.group(1)
            if username == "" and "''" in sql:
                username = "''"
            target_key = f"{username}@{hostname}"

        if target_key and target_key in self._permissions:
            task = self._find_matching_fix_task("delete", target_key, [])
            if task:
                return self._execute_fix_task(sql, sql_upper, task, target_key, [], student_id)

            del self._permissions[target_key]
            self._save_state()
            self._log_perm_change(student_id, "DELETE", user_m.group(1) if user_m else "",
                                  host_m.group(1) if host_m else "%", "DELETE USER")
            return (f"Query OK, 1 row affected (0.01 sec)\n\n"
                    f"✓ 用户记录已删除\n注意: 需要执行 FLUSH PRIVILEGES 使更改生效")

        return (f"Query OK, 0 rows affected (0.01 sec)\n\n"
                f"未找到匹配的用户记录")

    # ══════════════════════════════════════════
    # ★ ALTER USER（状态化）
    # ══════════════════════════════════════════

    def _handle_alter_user_stateful(self, sql: str, sql_upper: str) -> str:
        if "IDENTIFIED BY" in sql_upper:
            # 提取用户名和密码，更新状态
            user_match = re_mod.search(r"'([^']*)'@'([^']+)'", sql)
            pwd_match = re_mod.search(r"IDENTIFIED BY\s+'([^']+)'", sql)
            if user_match and pwd_match:
                target_key = f"{user_match.group(1)}@{user_match.group(2)}"
                new_pwd = pwd_match.group(1)
                if target_key in self._permissions:
                    self._permissions[target_key]["password"] = new_pwd
                    self._save_state()
            return ("Query OK, 1 rows affected (0.02 sec)\n\n"
                    "✓ 密码已修改，强度评估: 85/100 (强)\n"
                    "  建议使用包含大小写字母、数字和特殊字符的强密码")
        elif "ACCOUNT LOCK" in sql_upper:
            return ("Query OK, 1 rows affected (0.01 sec)\n\n"
                    "✓ 用户已锁定\n该账号已无法登录")
        elif "ACCOUNT UNLOCK" in sql_upper:
            return ("Query OK, 1 rows affected (0.01 sec)\n\n" "✓ 用户已解锁")
        else:
            return ("Query OK, 1 rows affected (0.01 sec)\n\n" "✓ 用户属性已修改")

    # ══════════════════════════════════════════
    # ★ 辅助方法
    # ══════════════════════════════════════════

    def _log_perm_change(self, student_id: int, change_type: str, user: str, host: str, privilege: str):
        """记录权限变更到数据库"""
        try:
            self._db.execute_sqlite_insert(
                "INSERT INTO permission_changes (student_id, change_type, target_user, target_host, privilege, status) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (student_id, change_type, user, host, privilege[:60], "applied"),
            )
        except Exception:
            pass

    def _update_task_progress(self, task_id: str, student_id: int) -> bool:
        """更新任务进度，返回当前分支是否全部完成"""
        try:
            from core.agent_orchestrator import get_orchestrator, STORY_BRANCHES
            orch = get_orchestrator(self._db)
            # FIX_TASK id 直接作为分支任务 id（基线分支现在使用所有5个修复任务ID）
            branch_task_id = task_id

            # 记录完成前的分支和任务状态
            state_before = orch.get_story_state(student_id)
            branch_before = state_before.current_branch
            tasks_before = set(state_before.completed_tasks)

            # 完成任务
            orch._complete_task(student_id, branch_task_id)

            # 完成后检查状态变化
            state_after = orch.get_story_state(student_id)
            tasks_after = set(state_after.completed_tasks)

            # 判断是否完成了当前分支的所有任务
            branch_info = STORY_BRANCHES.get(branch_before, {})
            branch_tasks = set(branch_info.get("tasks", []))
            if branch_tasks:
                # 检查分支所有任务是否都已标记完成
                branch_done = branch_tasks.issubset(tasks_after)
                # 如果分支变了或者所有任务都完成了
                branch_changed = state_after.current_branch != branch_before
                return branch_done or branch_changed

            return False
        except Exception:
            return False

    # ══════════════════════════════════════════
    # 基线检查 & 报告
    # ══════════════════════════════════════════

    def _run_baseline_check(self) -> str:
        """运行基线检查 — 基于当前状态动态检测"""
        # 基于当前 _permissions 状态做实际检查
        from core.security_monitor import get_monitor
        monitor = get_monitor()

        checks = [
            ("anon_user", "匿名用户检查", self._bl_check_anon_user()),
            ("password_strength", "密码强度检查", self._bl_check_password_strength()),
            ("excessive_privs", "过度授权检查", self._bl_check_excessive_privs()),
            ("remote_root", "远程root登录检查", self._bl_check_remote_root()),
            ("ssl_enabled", "SSL启用检查", self._bl_check_ssl()),
            ("default_port", "默认端口检查", self._bl_check_default_port()),
            ("log_enabled", "审计日志检查", self._bl_check_audit_log()),
            ("safe_privs", "安全函数权限检查", self._bl_check_file_priv()),
        ]

        output_lines = ["=== CIS MySQL Benchmark 安全检查 (基于当前状态) ===", "=" * 50]
        for cid, cname, result in checks:
            icon = "✓" if result["status"] == "pass" else "✗" if result["status"] == "fail" else "⚠"
            sev = result.get("severity", "medium").upper()
            output_lines.append(f"[{icon}] [{sev}] {cname}: {result['actual_value']}")
            if result["status"] == "fail" and result.get("suggestion"):
                output_lines.append(f"      -> 建议: {result['suggestion']}")

        output_lines.append("=" * 50)
        fail_count = sum(1 for _, _, r in checks if r["status"] == "fail")
        score = max(0, 100 - fail_count * 12.5)
        output_lines.append(f"总计: {len(checks)}项检查, {fail_count}项失败")
        output_lines.append(f"安全评分: {score:.1f}/100 {'(严重不达标)' if score < 60 else '(需改进)' if score < 80 else '(达标)'}" if score < 100 else "(满分)")

        return "\n".join(output_lines)

    def _bl_check_anon_user(self) -> dict:
        """检查匿名用户"""
        key = "''@localhost"
        exists = key in self._permissions
        return {
            "status": "fail" if exists else "pass",
            "actual_value": f"存在匿名用户({key})" if exists else "无匿名用户",
            "severity": "high",
            "suggestion": "DROP USER ''@'localhost'; 删除匿名用户" if exists else "",
        }

    def _bl_check_remote_root(self) -> dict:
        """检查 root 远程登录"""
        key = "root@%"
        exists = key in self._permissions
        return {
            "status": "fail" if exists else "pass",
            "actual_value": "root@% 允许远程登录" if exists else "root仅限本地登录",
            "severity": "critical",
            "suggestion": "DELETE FROM mysql.user WHERE user='root' AND host='%';" if exists else "",
        }

    def _bl_check_excessive_privs(self) -> dict:
        """检查过度授权"""
        excessive = []
        for key, info in self._permissions.items():
            privs = info.get("global_privs", [])
            role = info.get("role", "")
            if ("DELETE" in privs or "DROP" in privs) and role in ("测试账号", "开发账号", "应用账号"):
                excessive.append(f"{key}({','.join(p for p in ['DELETE','DROP'] if p in privs)})")
        if excessive:
            return {
                "status": "fail",
                "actual_value": f"{len(excessive)}个用户过度授权: {', '.join(excessive[:3])}",
                "severity": "critical",
                "suggestion": "使用 REVOKE 撤销非管理员用户的全局 DELETE/DROP 权限",
            }
        return {"status": "pass", "actual_value": "无过度授权用户", "severity": "low", "suggestion": ""}

    def _bl_check_file_priv(self) -> dict:
        """检查 FILE 权限"""
        file_users = [k for k, v in self._permissions.items()
                      if "FILE" in v.get("global_privs", []) and v.get("role") not in ("管理员",)]
        if file_users:
            return {
                "status": "fail",
                "actual_value": f"{len(file_users)}个用户拥有FILE权限: {', '.join(file_users[:3])}",
                "severity": "high",
                "suggestion": "REVOKE FILE ON *.* FROM 相关用户;",
            }
        return {"status": "pass", "actual_value": "无非法FILE权限用户", "severity": "low", "suggestion": ""}

    def _bl_check_password_strength(self) -> dict:
        """检查密码强度（基于实际密码）"""
        weak_users = []
        for key, info in self._permissions.items():
            pwd = info.get("password", "")
            role = info.get("role", "")
            if not pwd:
                continue
            score = 0
            if len(pwd) >= 8: score += 25
            if any(c.isupper() for c in pwd): score += 25
            if any(c.islower() for c in pwd): score += 25
            if any(c.isdigit() for c in pwd): score += 15
            if any(c in "!@#$%^&*" for c in pwd): score += 10
            if score < 60 and role not in ("管理员",):
                weak_users.append(f"{key}(强度:{score})")
        if weak_users:
            return {
                "status": "fail",
                "actual_value": f"{len(weak_users)}个账号密码强度不足: {', '.join(weak_users[:3])}",
                "severity": "high",
                "suggestion": "使用 ALTER USER 更新密码，确保长度≥8且包含大小写字母和数字",
            }
        return {"status": "pass", "actual_value": "密码策略合规", "severity": "low", "suggestion": ""}

    def _bl_check_ssl(self) -> dict:
        """检查 SSL（已启用，无需修复）"""
        return {"status": "pass", "actual_value": "have_ssl=YES (已启用)", "severity": "low",
                "suggestion": "✓ SSL已启用，无需修复"}


    def _bl_check_default_port(self) -> dict:
        """检查默认端口（仅提醒，无法通过SQL修复）"""
        return {"status": "warn", "actual_value": "port=3306(默认，需在my.cnf中修改)", "severity": "low",
                "suggestion": "提示：生产环境建议修改为其他端口，需在my.cnf中配置并重启MySQL服务"}

    def _bl_check_audit_log(self) -> dict:
        """检查审计日志（模拟）"""
        return {"status": "fail", "actual_value": "general_log=OFF(模拟)", "severity": "medium",
                "suggestion": "SET GLOBAL general_log=ON; 开启审计日志"}
        output_lines.append(f"总计: {len(results)}项检查, {fail_count}项失败")
        output_lines.append(f"安全评分: {score:.1f}/100")
        return "\n".join(output_lines)

    def _generate_report(self) -> str:
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        return (f"正在生成《数据库安全运维与加固报告》...\n"
                f"[INFO] 收集操作记录... 完成\n"
                f"[INFO] 整理漏洞列表... 完成\n"
                f"[INFO] 生成修复建议... 完成\n"
                f"[INFO] 渲染PDF报告... 完成\n"
                f"---\n"
                f"✓ 报告已生成: /data/reports/数据库安全运维与加固报告_{now}.pdf")

    def _get_help(self) -> str:
        return ("可用命令:\n"
                "  story                   - 查看/开始故事线\n"
                "  help                    - 显示此帮助信息\n"
                "  ls, cd, cat, pwd        - 文件系统操作\n"
                "  mysql [选项]            - 连接MySQL数据库\n"
                "  exit                    - 退出\n"
                "  clear                   - 清屏\n"
                "  generate_report         - 生成审计报告\n\n"
                "SQL语句(自动识别无需先连接):\n"
                "  SHOW GRANTS FOR 'user'@'host';   - 查看用户权限\n"
                "  SHOW DATABASES;                  - 查看数据库列表\n"
                "  SELECT * FROM mysql.user;        - 查看所有用户\n"
                "  REVOKE priv ON *.* FROM 'u'@'h';  - 撤销权限\n"
                "  GRANT priv ON db.* TO 'u'@'h';    - 授予权限\n"
                "  DROP USER 'u'@'h';                - 删除用户\n"
                "  ALTER USER 'u'@'h' IDENTIFIED BY 'pwd';  - 修改密码")

    def _get_history(self, student_id: int) -> str:
        rows = self._db.execute_sqlite(
            "SELECT command, executed_at FROM command_history WHERE student_id = ? ORDER BY executed_at DESC LIMIT 20",
            (student_id,),
        )
        if not rows:
            return "没有命令历史记录"
        lines = ["最近命令历史:"]
        for i, row in enumerate(reversed(rows), 1):
            ts = row["executed_at"][:19] if row["executed_at"] else ""
            lines.append(f"  {i:3d}  [{ts}] {row['command'][:80]}")
        return "\n".join(lines)


# 用于 _get_pwd 中的 os.getcwd
import os
