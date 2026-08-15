"""
数据库安全运维智能体 - 数据库连接器

管理 SQLite（持久化存储）和 Redis（缓存/会话）两种数据库的连接生命周期。
提供连接池、自动重连和上下文管理器支持。
"""
import sqlite3
import os
import json
from contextlib import contextmanager
from typing import Optional, Any, Dict, List

from config.settings import get_config

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None


class DatabaseConnector:
    """
    数据库连接管理器

    统一管理 SQLite 和 Redis 连接，提供：
    - SQLite：表结构自动初始化、上下文管理器、查询辅助方法
    - Redis：连接池管理、缓存装饰器（需 Python 3.8+ 兼容）
    """

    def __init__(self, config=None):
        self._config = config or get_config()
        self._sqlite_conn: Optional[sqlite3.Connection] = None
        self._redis_client: Optional[Any] = None
        self._redis_pool: Optional[Any] = None

    # ──────────────────────────────────────────
    # SQLite 操作
    # ──────────────────────────────────────────

    def _ensure_sqlite_dir(self):
        """确保 SQLite 数据库目录存在"""
        db_dir = os.path.dirname(self._config.SQLITE_DB_PATH)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    def get_sqlite_conn(self) -> sqlite3.Connection:
        """获取 SQLite 连接（单例，自动创建目录）"""
        if self._sqlite_conn is None:
            self._ensure_sqlite_dir()
            self._sqlite_conn = sqlite3.connect(
                self._config.SQLITE_DB_PATH,
                detect_types=sqlite3.PARSE_DECLTYPES,
                check_same_thread=False,
            )
            self._sqlite_conn.row_factory = sqlite3.Row
            self._sqlite_conn.execute("PRAGMA journal_mode=WAL")
            self._sqlite_conn.execute("PRAGMA foreign_keys=ON")
        return self._sqlite_conn

    @contextmanager
    def sqlite_session(self):
        """SQLite 会话上下文管理器，自动提交/回滚"""
        conn = self.get_sqlite_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def init_sqlite_schema(self):
        """初始化所有 SQLite 表结构"""
        schema_statements = [
            # 学员状态表
            """CREATE TABLE IF NOT EXISTS student_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_name TEXT NOT NULL DEFAULT '默认学员',
                current_decision INTEGER DEFAULT 0,
                current_branch TEXT DEFAULT 'start',
                completed_tasks TEXT DEFAULT '[]',
                failed_count INTEGER DEFAULT 0,
                retry_count INTEGER DEFAULT 0,
                score INTEGER DEFAULT 0,
                story_phase TEXT DEFAULT 'intro',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            # 任务记录表
            """CREATE TABLE IF NOT EXISTS task_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                task_id TEXT NOT NULL,
                task_name TEXT NOT NULL,
                task_type TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                result TEXT DEFAULT '{}',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES student_state(id)
            )""",
            # 命令历史表
            """CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                command TEXT NOT NULL,
                output TEXT DEFAULT '',
                is_valid INTEGER DEFAULT 0,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES student_state(id)
            )""",
            # 漏洞发现记录表
            """CREATE TABLE IF NOT EXISTS vulnerability_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                vuln_type TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                fixed_at TIMESTAMP,
                fixed_method TEXT DEFAULT '',
                is_fixed INTEGER DEFAULT 0,
                FOREIGN KEY (student_id) REFERENCES student_state(id)
            )""",
            # 基线检查结果表
            """CREATE TABLE IF NOT EXISTS baseline_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                check_id TEXT NOT NULL,
                check_name TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                actual_value TEXT DEFAULT '',
                expected_value TEXT DEFAULT '',
                suggestion TEXT DEFAULT '',
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES student_state(id)
            )""",
            # 权限变更记录表
            """CREATE TABLE IF NOT EXISTS permission_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                change_type TEXT NOT NULL,
                target_user TEXT NOT NULL,
                target_host TEXT DEFAULT '%',
                privilege TEXT NOT NULL,
                grant_sql TEXT NOT NULL,
                revoke_sql TEXT DEFAULT '',
                status TEXT DEFAULT 'applied',
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES student_state(id)
            )""",
            # 审计日志表
            """CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                detail TEXT DEFAULT '',
                ip_address TEXT DEFAULT '127.0.0.1',
                logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES student_state(id)
            )""",
            # 终端状态持久化表（权限状态等）
            """CREATE TABLE IF NOT EXISTS state_store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
        ]
        with self.sqlite_session() as conn:
            for stmt in schema_statements:
                conn.execute(stmt)

            # ── 迁移：兼容旧库，为 student_state 增加分支错误计数列 ──
            cols = [row["name"] for row in conn.execute("PRAGMA table_info(student_state)")]
            if "branch_failed_counts" not in cols:
                conn.execute(
                    "ALTER TABLE student_state ADD COLUMN branch_failed_counts TEXT DEFAULT '{}'"
                )
            if "unlocked_branches" not in cols:
                conn.execute(
                    "ALTER TABLE student_state ADD COLUMN unlocked_branches TEXT DEFAULT '[]'"
                )

    def execute_sqlite(self, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        """执行 SQLite 查询并返回结果列表"""
        with self.sqlite_session() as conn:
            cursor = conn.execute(sql, params)
            return cursor.fetchall()

    def execute_sqlite_insert(self, sql: str, params: tuple = ()) -> int:
        """执行 SQLite 插入并返回 lastrowid"""
        with self.sqlite_session() as conn:
            cursor = conn.execute(sql, params)
            return cursor.lastrowid

    def close_sqlite(self):
        """关闭 SQLite 连接"""
        if self._sqlite_conn:
            self._sqlite_conn.close()
            self._sqlite_conn = None

    # ──────────────────────────────────────────
    # 状态持久化（state_store 表）
    # ──────────────────────────────────────────

    def save_state(self, key: str, value: str):
        """保存状态到 state_store 表"""
        self.execute_sqlite(
            "INSERT OR REPLACE INTO state_store (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
            (key, value),
        )

    def load_state(self, key: str) -> Optional[str]:
        """从 state_store 表加载状态"""
        rows = self.execute_sqlite(
            "SELECT value FROM state_store WHERE key = ?", (key,)
        )
        return rows[0]["value"] if rows else None

    def delete_state(self, key: str):
        """删除状态"""
        self.execute_sqlite("DELETE FROM state_store WHERE key = ?", (key,))

    # ──────────────────────────────────────────
    # Redis 操作
    # ──────────────────────────────────────────

    def get_redis(self):
        """获取 Redis 客户端（连接池模式）"""
        if redis_lib is None:
            raise ImportError("redis 库未安装，请执行: pip install redis")

        if self._redis_client is None:
            self._redis_pool = redis_lib.ConnectionPool(
                host=self._config.REDIS_HOST,
                port=self._config.REDIS_PORT,
                db=self._config.REDIS_DB,
                password=self._config.REDIS_PASSWORD,
                decode_responses=self._config.REDIS_DECODE_RESPONSES,
            )
            self._redis_client = redis_lib.Redis(connection_pool=self._redis_pool)
        return self._redis_client

    def redis_set_json(self, key: str, value: Any, ex: int = None) -> bool:
        """向 Redis 写入 JSON 数据"""
        r = self.get_redis()
        return r.set(key, json.dumps(value, ensure_ascii=False), ex=ex)

    def redis_get_json(self, key: str) -> Optional[Any]:
        """从 Redis 读取 JSON 数据"""
        r = self.get_redis()
        data = r.get(key)
        if data is None:
            return None
        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return data

    def redis_delete(self, *keys: str) -> int:
        """删除 Redis 中的键"""
        r = self.get_redis()
        return r.delete(*keys)

    def close_redis(self):
        """关闭 Redis 连接池"""
        if self._redis_pool:
            self._redis_pool.disconnect()
            self._redis_pool = None
            self._redis_client = None

    # ──────────────────────────────────────────
    # 生命周期管理
    # ──────────────────────────────────────────

    def close_all(self):
        """关闭所有数据库连接"""
        self.close_sqlite()
        self.close_redis()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_all()
        return False