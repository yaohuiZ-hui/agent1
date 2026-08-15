"""
数据库安全运维智能体 - 配置管理模块

集中管理所有配置项，包括数据库连接、Redis、故事线、安全策略等。
"""
import os
import json


class Config:
    """应用配置类，支持从环境变量覆盖默认值"""

    # Flask 配置
    SECRET_KEY = os.environ.get("SECRET_KEY", "agent1-secret-key-change-in-production")
    DEBUG = os.environ.get("DEBUG", "True").lower() == "true"
    HOST = os.environ.get("HOST", "127.0.0.1")
    PORT = int(os.environ.get("PORT", 5000))

    # SQLite 配置（学员状态、任务进度、故事线持久化）
    SQLITE_DB_PATH = os.environ.get(
        "SQLITE_DB_PATH",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "agent1.db"),
    )

    # Redis 配置（会话缓存、实时状态、攻击模拟结果缓存）
    REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
    REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
    REDIS_DB = int(os.environ.get("REDIS_DB", 0))
    REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", None)
    REDIS_DECODE_RESPONSES = True

    # 场景故事线配置
    STORY_DECISIONS = {
        1: {"title": "安全基线扫描与权限管控", "description": "先进行安全基线扫描与权限梳理"},
        2: {"title": "数据库备份恢复", "description": "直接处理数据丢失问题"},
        3: {"title": "SQL注入攻防", "description": "优先分析异常流量日志"},
    }

    # 安全基线检查项 (CIS MySQL Benchmark 子集)
    BASELINE_CHECKS = [
        {"id": "anon_user", "title": "匿名用户检查", "command": "SELECT COUNT(*) FROM mysql.user WHERE user=''"},
        {"id": "password_strength", "title": "密码强度检查", "command": "检查用户密码策略"},
        {"id": "excessive_privs", "title": "过度授权检查", "command": "检查拥有全局DELETE/DROP权限的用户"},
        {"id": "remote_root", "title": "远程root登录检查", "command": "SELECT user, host FROM mysql.user WHERE user='root' AND host='%'"},
        {"id": "ssl_enabled", "title": "SSL启用检查", "command": "SHOW VARIABLES LIKE 'have_ssl'"},
        {"id": "default_port", "title": "默认端口检查", "command": "SHOW VARIABLES LIKE 'port'"},
        {"id": "log_enabled", "title": "审计日志检查", "command": "SHOW VARIABLES LIKE 'general_log%'"},
        {"id": "safe_privs", "title": "安全函数权限检查", "command": "检查FILE权限用户"},
    ]

    # 攻防演练靶场配置
    VULNERABLE_ENDPOINTS = [
        {"path": "/api/user/profile", "method": "GET", "params": {"id": "int"}, "vuln_type": "union_inject"},
        {"path": "/api/search/product", "method": "GET", "params": {"keyword": "str"}, "vuln_type": "blind_inject"},
        {"path": "/api/order/query", "method": "POST", "params": {"order_id": "int"}, "vuln_type": "error_inject"},
    ]

    # 数据恢复模拟配置
    BACKUP_BASE_DIR = os.environ.get(
        "BACKUP_BASE_DIR",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "backup_sim"),
    )

    # 报告生成配置
    REPORT_OUTPUT_DIR = os.environ.get(
        "REPORT_OUTPUT_DIR",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "reports"),
    )

    # 日志配置
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FILE = os.environ.get(
        "LOG_FILE",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "agent1.log"),
    )


def get_config() -> Config:
    """获取配置实例（工厂函数）"""
    return Config()