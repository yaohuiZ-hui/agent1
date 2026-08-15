"""
数据库安全运维智能体 - 安全监控模块

负责实时监控数据库安全状态，包括：
- 异常查询检测（慢查询、错误日志分析）
- SQL注入行为特征识别
- 基线安全合规检查
- 告警生成与推送
"""
import re
import time
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field, asdict

from config.settings import get_config, Config


@dataclass
class SecurityAlert:
    """安全告警数据类"""
    alert_id: str
    alert_type: str  # sql_injection, weak_password, excessive_priv, anomaly_query
    severity: str  # critical, high, medium, low
    title: str
    description: str
    source: str  # audit_log, slow_query, baseline_check
    detected_at: str = field(default_factory=lambda: datetime.now().isoformat())
    details: Dict[str, Any] = field(default_factory=dict)
    suggestion: str = ""


@dataclass
class BaselineCheckResult:
    """基线检查结果数据类"""
    check_id: str
    check_name: str
    status: str  # pass, fail, warn, error
    actual_value: str = ""
    expected_value: str = ""
    suggestion: str = ""
    severity: str = "medium"


class SecurityMonitor:
    """
    安全监控器

    提供数据库安全监控的核心逻辑，包括：
    - SQL注入特征检测（基于正则表达式匹配）
    - 异常查询行为分析
    - 基线检查项执行
    - 告警级别判定
    """

    # SQL注入攻击特征正则模式
    SQL_INJECTION_PATTERNS = [
        (r"('|\")\s*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\s*", "关键字注入"),
        (r"UNION\s+(ALL\s+)?SELECT", "UNION注入"),
        (r"'\s*(OR|AND)\s+'[^']*'\s*=\s*'", "恒真/恒假注入"),
        (r"SELECT.*INTO\s+(OUT|DUMP)FILE", "文件写入注入"),
        (r"BENCHMARK\s*\(\s*\d+\s*,", "基于时间的盲注"),
        (r"SLEEP\s*\(\s*\d+\s*\)", "基于时间的盲注(SLEEP)"),
        (r"WAITFOR\s+DELAY\s*'[^']+'", "基于时间的盲注(WAITFOR)"),
        (r"--\s*$|#\s*$|/\*.*\*/", "注释符注入"),
        (r"(OR|AND)\s+1\s*=\s*1", "恒真条件"),
        (r"LOAD_FILE\s*\(", "文件读取函数"),
        (r"INTO\s+@+", "变量注入"),
    ]

    # 敏感操作关键字
    SENSITIVE_OPERATIONS = [
        "DROP TABLE", "DROP DATABASE", "TRUNCATE", "DELETE FROM",
        "ALTER TABLE", "ALTER USER", "GRANT ALL", "REVOKE",
        "CREATE USER", "DROP USER", "FLUSH PRIVILEGES",
    ]

    def __init__(self, config: Optional[Config] = None):
        self._config = config or get_config()
        self._alerts: List[SecurityAlert] = []
        self._alert_counter = 0

    # ──────────────────────────────────────────
    # SQL注入检测
    # ──────────────────────────────────────────

    def detect_sql_injection(self, query: str) -> List[Dict[str, Any]]:
        """
        检测SQL语句中是否存在注入特征

        Args:
            query: 待检测的SQL语句

        Returns:
            检测到的注入特征列表，每项包含 pattern 和 inject_type
        """
        findings = []
        for pattern, inject_type in self.SQL_INJECTION_PATTERNS:
            matches = re.findall(pattern, query, re.IGNORECASE)
            if matches:
                findings.append({
                    "pattern": pattern,
                    "inject_type": inject_type,
                    "matched_text": str(matches[0] if isinstance(matches[0], str) else matches[0][0]),
                })
        return findings

    def analyze_query_log(self, query: str, source: str = "slow_query_log") -> Optional[SecurityAlert]:
        """
        分析单条查询日志，检测安全威胁

        Args:
            query: SQL查询语句
            source: 日志来源

        Returns:
            如果检测到威胁则返回 SecurityAlert，否则返回 None
        """
        findings = self.detect_sql_injection(query)
        if findings:
            self._alert_counter += 1
            alert = SecurityAlert(
                alert_id=f"SQL_INJECT_{self._alert_counter:04d}",
                alert_type="sql_injection",
                severity="critical",
                title="检测到SQL注入攻击特征",
                description=f"在 {source} 中发现可疑SQL语句，涉及 {len(findings)} 种注入特征",
                source=source,
                details={
                    "query": query[:500],
                    "findings": findings,
                },
                suggestion="1. 立即检查对应接口的输入过滤\n2. 确认是否已使用参数化查询\n3. 检查WAF规则是否生效",
            )
            self._alerts.append(alert)
            return alert
        return None

    def analyze_sensitive_operation(self, query: str, user: str = "unknown") -> Optional[SecurityAlert]:
        """
        检测敏感操作（DDL/DCL 等高危语句）

        Args:
            query: SQL语句
            user: 执行用户

        Returns:
            如果检测到敏感操作则返回告警
        """
        for op in self.SENSITIVE_OPERATIONS:
            if op in query.upper():
                self._alert_counter += 1
                return SecurityAlert(
                    alert_id=f"SENSITIVE_{self._alert_counter:04d}",
                    alert_type="anomaly_query",
                    severity="high",
                    title=f"检测到敏感操作: {op}",
                    description=f"用户 {user} 执行了高危操作: {query[:300]}",
                    source="audit_log",
                    details={"user": user, "operation": op, "query": query[:500]},
                    suggestion="确认该操作是否经过审批，遵循最小权限原则",
                )
        return None

    # ──────────────────────────────────────────
    # 基线检查
    # ──────────────────────────────────────────

    def run_baseline_check(self, check_id: str) -> BaselineCheckResult:
        """
        执行单条基线检查项

        Args:
            check_id: 检查项ID

        Returns:
            检查结果
        """
        check_map = {c["id"]: c for c in self._config.BASELINE_CHECKS}
        if check_id not in check_map:
            return BaselineCheckResult(
                check_id=check_id, check_name="未知检查项",
                status="error", suggestion="检查项ID不存在",
            )

        check = check_map[check_id]
        # 模拟检查逻辑（真实环境中连接数据库执行）
        simulated_results = {
            "anon_user": {"status": "fail", "actual": "存在匿名用户(2个)", "expected": "不存在匿名用户",
                          "suggestion": "删除匿名用户: DROP USER ''@'localhost';", "severity": "high"},
            "password_strength": {"status": "fail", "actual": "3个用户密码强度不足", "expected": "所有用户密码强度≥80分",
                                  "suggestion": "使用 ALTER USER 更新弱密码用户", "severity": "high"},
            "excessive_privs": {"status": "fail", "actual": "存在5个过度授权用户", "expected": "最小权限原则",
                                "suggestion": "REVOKE 多余权限，保留最小必要权限", "severity": "critical"},
            "remote_root": {"status": "fail", "actual": "root@% 允许远程登录", "expected": "root仅允许localhost登录",
                            "suggestion": "执行: DELETE FROM mysql.user WHERE user='root' AND host='%'", "severity": "critical"},
            # "ssl_enabled": {"status": "fail", "actual": "have_ssl=DISABLED", "expected": "have_ssl=YES",
            #                 "suggestion": "启用SSL: 配置 ca-cert.pem, server-cert.pem, server-key.pem", "severity": "medium"},
            # "default_port": {"status": "warn", "actual": "port=3306(默认)", "expected": "建议修改非默认端口",
            #                  "suggestion": "修改 my.cnf 中的 port 配置项", "severity": "low"},
            "log_enabled": {"status": "fail", "actual": "general_log=OFF", "expected": "general_log=ON",
                            "suggestion": "开启审计日志: SET GLOBAL general_log=ON", "severity": "medium"},
            "safe_privs": {"status": "fail", "actual": "2个用户拥有FILE权限", "expected": "FILE权限仅限管理员",
                           "suggestion": "REVOKE FILE ON *.* FROM user;", "severity": "high"},
        }

        result = simulated_results.get(check_id, {"status": "pass", "actual": "符合规范", "expected": "符合规范",
                                                   "suggestion": "", "severity": "low"})
        return BaselineCheckResult(
            check_id=check_id,
            check_name=check["title"],
            status=result["status"],
            actual_value=result["actual"],
            expected_value=result["expected"],
            suggestion=result["suggestion"],
            severity=result["severity"],
        )

    def run_all_baseline_checks(self) -> List[BaselineCheckResult]:
        """运行所有基线检查项"""
        return [self.run_baseline_check(c["id"]) for c in self._config.BASELINE_CHECKS]

    # ──────────────────────────────────────────
    # 告警管理
    # ──────────────────────────────────────────

    def get_alerts(self, alert_type: Optional[str] = None, severity: Optional[str] = None) -> List[SecurityAlert]:
        """获取告警列表，支持按类型和严重级别过滤"""
        results = self._alerts
        if alert_type:
            results = [a for a in results if a.alert_type == alert_type]
        if severity:
            results = [a for a in results if a.severity == severity]
        return results

    def get_alert_count_by_severity(self) -> Dict[str, int]:
        """按严重级别统计告警数量"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for alert in self._alerts:
            sev = alert.severity if alert.severity in counts else "low"
            counts[sev] += 1
        return counts

    def clear_alerts(self):
        """清除所有告警"""
        self._alerts.clear()
        self._alert_counter = 0

    # ──────────────────────────────────────────
    # 权限分析
    # ──────────────────────────────────────────

    def analyze_permissions(self, simulated_users: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        分析数据库用户权限，识别过度授权

        Args:
            simulated_users: 模拟用户列表，包含用户和权限信息

        Returns:
            过度授权用户列表及建议
        """
        if simulated_users is None:
            # 模拟数据
            simulated_users = [
                {"user": "test_user", "host": "%", "global_privs": ["SELECT", "INSERT", "DELETE", "DROP"],
                 "db_privs": ["*.*"], "role": "测试账号"},
                {"user": "app_user", "host": "192.168.%", "global_privs": ["SELECT", "INSERT", "UPDATE"],
                 "db_privs": ["app_db.*"], "role": "应用账号"},
                {"user": "backup_user", "host": "localhost", "global_privs": ["SELECT", "LOCK TABLES"],
                 "db_privs": ["*.*"], "role": "备份账号"},
                {"user": "admin", "host": "localhost", "global_privs": ["ALL PRIVILEGES"],
                 "db_privs": ["*.*"], "role": "管理员"},
                {"user": "dev_user", "host": "%", "global_privs": ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER"],
                 "db_privs": ["dev_db.*"], "role": "开发账号"},
            ]

        excessive = []
        for user in simulated_users:
            issues = []
            # 检查全局DELETE/DROP
            if "DELETE" in user.get("global_privs", []) and user["role"] not in ["管理员"]:
                issues.append("不必要的全局DELETE权限")
            if "DROP" in user.get("global_privs", []) and user["role"] not in ["管理员"]:
                issues.append("不必要的全局DROP权限")
            if "ALL PRIVILEGES" in user.get("global_privs", []) and user["role"] not in ["管理员"]:
                issues.append("过度授权: 拥有ALL PRIVILEGES")
            if user.get("host") == "%" and user["role"] in ["测试账号", "开发账号"]:
                issues.append("允许任意IP访问")
            if "FILE" in user.get("global_privs", []) and user["role"] not in ["管理员"]:
                issues.append("不必要的FILE权限")
            if user.get("host") == "%" and user.get("user") == "root":
                issues.append("root用户允许远程登录，极度危险")

            if issues:
                revoke_sqls = []
                for priv in ["DELETE", "DROP", "FILE", "ALTER"]:
                    if priv in user.get("global_privs", []) and user["role"] not in ["管理员"]:
                        revoke_sqls.append(f"REVOKE {priv} ON *.* FROM '{user['user']}'@'{user['host']}';")
                if "ALL PRIVILEGES" in user.get("global_privs", []) and user["role"] not in ["管理员"]:
                    revoke_sqls.append(f"REVOKE ALL PRIVILEGES ON *.* FROM '{user['user']}'@'{user['host']}';")

                excessive.append({
                    "user": user["user"],
                    "host": user["host"],
                    "role": user["role"],
                    "issues": issues,
                    "revoke_suggestions": revoke_sqls or ["无需撤销"],
                    "severity": "high" if "ALL PRIVILEGES" in str(issues) else "medium",
                })

        return excessive


# 单例模式
_monitor_instance: Optional[SecurityMonitor] = None


def get_monitor(config: Optional[Config] = None) -> SecurityMonitor:
    """获取 SecurityMonitor 单例"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = SecurityMonitor(config)
    return _monitor_instance