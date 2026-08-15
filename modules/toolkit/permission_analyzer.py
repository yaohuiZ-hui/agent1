"""
运维工具箱模块 - 权限分析器

分析数据库用户权限，识别过度授权：
- 从information_schema模拟数据提取权限信息
- 检测过度授权（全局DELETE/DROP/FILE/ALL等）
- 生成最小权限建议（REVOKE语句）
- 权限变更记录追踪
"""
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class UserPrivilege:
    """用户权限信息"""
    user: str
    host: str
    role: str
    global_privileges: List[str]
    db_privileges: Dict[str, List[str]]  # db -> [privileges]
    is_active: bool = True
    days_since_last_login: int = 0


@dataclass
class PermIssue:
    """权限问题"""
    user: str
    host: str
    issue_type: str  # excessive_priv, wrong_host, unused_user, same_user
    description: str
    severity: str  # critical, high, medium, low
    revoke_suggestion: str


# 模拟用户权限数据
SIMULATED_USERS = [
    UserPrivilege(
        user="root", host="localhost", role="管理员",
        global_privileges=["ALL PRIVILEGES"],
        db_privileges={"*.*": ["ALL PRIVILEGES"]},
        days_since_last_login=0,
    ),
    UserPrivilege(
        user="root", host="%", role="管理员",
        global_privileges=["ALL PRIVILEGES"],
        db_privileges={"*.*": ["ALL PRIVILEGES"]},
        days_since_last_login=15,
    ),
    UserPrivilege(
        user="test_user", host="%", role="测试账号",
        global_privileges=["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "FILE"],
        db_privileges={"*.*": ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP"]},
        days_since_last_login=30,
    ),
    UserPrivilege(
        user="app_user", host="192.168.%", role="应用账号",
        global_privileges=["SELECT", "INSERT", "UPDATE"],
        db_privileges={"app_db.*": ["SELECT", "INSERT", "UPDATE"]},
        days_since_last_login=0,
    ),
    UserPrivilege(
        user="backup_user", host="localhost", role="备份账号",
        global_privileges=["SELECT", "LOCK TABLES"],
        db_privileges={"*.*": ["SELECT", "LOCK TABLES"]},
        days_since_last_login=1,
    ),
    UserPrivilege(
        user="dev_user", host="%", role="开发账号",
        global_privileges=["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE"],
        db_privileges={"dev_db.*": ["ALL"]},
        days_since_last_login=7,
    ),
    UserPrivilege(
        user="report_user", host="localhost", role="报表账号",
        global_privileges=["SELECT"],
        db_privileges={"core_bank.*": ["SELECT"]},
        days_since_last_login=2,
    ),
    UserPrivilege(
        user="audit_user", host="localhost", role="审计账号",
        global_privileges=["SELECT"],
        db_privileges={"mysql.*": ["SELECT"]},
        days_since_last_login=3,
    ),
]


class PermissionAnalyzer:
    """
    权限分析器

    分析数据库用户权限，识别过度授权和安全风险。
    """

    # 高危全局权限
    HIGH_RISK_PRIVS = ["ALL PRIVILEGES", "FILE", "SUPER", "PROCESS", "SHUTDOWN"]
    # 中等风险权限
    MEDIUM_RISK_PRIVS = ["DELETE", "DROP", "ALTER", "CREATE", "GRANT OPTION"]

    def __init__(self):
        self._users = SIMULATED_USERS
        self._change_log: List[Dict[str, Any]] = []

    # ──────────────────────────────────────────
    # 权限分析
    # ──────────────────────────────────────────

    def analyze_all(self) -> Dict[str, Any]:
        """分析所有用户权限"""
        issues = []
        for user in self._users:
            user_issues = self._analyze_user(user)
            issues.extend(user_issues)

        return {
            "summary": {
                "total_users": len(self._users),
                "total_issues": len(issues),
                "critical_count": sum(1 for i in issues if i.severity == "critical"),
                "high_count": sum(1 for i in issues if i.severity == "high"),
                "medium_count": sum(1 for i in issues if i.severity == "medium"),
                "low_count": sum(1 for i in issues if i.severity == "low"),
            },
            "users": [asdict(u) for u in self._users],
            "issues": [asdict(i) for i in issues],
            "recommendations": self._generate_recommendations(issues),
        }

    def _analyze_user(self, user: UserPrivilege) -> List[PermIssue]:
        """分析单个用户的权限"""
        issues = []

        # 1. 检查全局高危权限
        for priv in self.HIGH_RISK_PRIVS:
            if priv in user.global_privileges and user.role not in ("管理员",):
                issues.append(PermIssue(
                    user=user.user, host=user.host,
                    issue_type="excessive_priv",
                    description=f"非管理员用户'{user.user}'拥有全局{priv}权限",
                    severity="critical",
                    revoke_suggestion=f"REVOKE {priv} ON *.* FROM '{user.user}'@'{user.host}';",
                ))

        # 2. 检查全局高危操作权限
        for priv in self.MEDIUM_RISK_PRIVS:
            if priv in user.global_privileges and user.role not in ("管理员", "应用账号", "备份账号"):
                issues.append(PermIssue(
                    user=user.user, host=user.host,
                    issue_type="excessive_priv",
                    description=f"'{user.role}'用户'{user.user}'拥有不必要的全局{priv}权限",
                    severity="high",
                    revoke_suggestion=f"REVOKE {priv} ON *.* FROM '{user.user}'@'{user.host}';",
                ))

        # 3. 检查任意IP访问
        if user.host == "%" and user.role in ("测试账号", "开发账号"):
            issues.append(PermIssue(
                user=user.user, host=user.host,
                issue_type="wrong_host",
                description=f"'{user.role}'用户'{user.user}'允许从任意IP(%)访问",
                severity="high",
                revoke_suggestion=f"DROP USER '{user.user}'@'%'; CREATE USER '{user.user}'@'192.168.%' IDENTIFIED BY '***';",
            ))

        # 4. 检查root远程登录
        if user.user == "root" and user.host == "%":
            issues.append(PermIssue(
                user=user.user, host=user.host,
                issue_type="wrong_host",
                description="root用户允许从任意IP远程登录，极度危险",
                severity="critical",
                revoke_suggestion="DELETE FROM mysql.user WHERE user='root' AND host='%'; FLUSH PRIVILEGES;",
            ))

        # 5. 检查长时间未登录的用户
        if user.days_since_last_login > 14 and user.role not in ("审计账号", "报表账号"):
            issues.append(PermIssue(
                user=user.user, host=user.host,
                issue_type="unused_user",
                description=f"用户'{user.user}'已{user.days_since_last_login}天未登录，建议禁用",
                severity="medium",
                revoke_suggestion=f"ALTER USER '{user.user}'@'{user.host}' ACCOUNT LOCK;",
            ))

        return issues

    def _generate_recommendations(self, issues: List[PermIssue]) -> List[str]:
        """生成建议"""
        recs = []
        seen = set()

        for issue in issues:
            if issue.issue_type == "excessive_priv" and issue.severity == "critical":
                key = f"revoke_critical_{issue.user}"
                if key not in seen:
                    recs.append(f"【紧急】撤销用户'{issue.user}'的高危全局权限: {issue.revoke_suggestion}")
                    seen.add(key)
            elif issue.issue_type == "wrong_host":
                if issue.user == "root":
                    recs.append(f"【紧急】禁止root远程登录: {issue.revoke_suggestion}")
                else:
                    recs.append(f"【重要】限制用户'{issue.user}'的访问IP范围: {issue.revoke_suggestion}")

        # 添加通用建议
        recs.append("【建议】对所有用户执行最小权限原则审查")
        recs.append("【建议】启用审计插件(McAfee/MariaDB Audit Plugin)记录所有权限变更")
        recs.append("【建议】定期(每季度)审查数据库用户权限")

        return recs

    # ──────────────────────────────────────────
    # 权限变更记录
    # ──────────────────────────────────────────

    def record_change(self, user: str, host: str, change_type: str, grant_sql: str, revoke_sql: str = ""):
        """记录权限变更"""
        self._change_log.append({
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "host": host,
            "change_type": change_type,
            "grant_sql": grant_sql,
            "revoke_sql": revoke_sql,
        })

    def get_change_log(self) -> List[Dict[str, Any]]:
        """获取权限变更记录"""
        return self._change_log

    # ──────────────────────────────────────────
    # 最小权限建议生成
    # ──────────────────────────────────────────

    def generate_minimal_priv_script(self) -> Dict[str, Any]:
        """生成最小权限配置脚本"""
        script_lines = [
            "-- ============================================",
            "-- 数据库最小权限配置脚本",
            f"-- 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "-- ============================================",
            "",
            "-- 1. 删除匿名用户",
            "DROP USER IF EXISTS ''@'localhost';",
            "DROP USER IF EXISTS ''@'%';",
            "",
            "-- 2. 禁止root远程登录",
            "DELETE FROM mysql.user WHERE user='root' AND host='%';",
            "",
            "-- 3. 撤销测试账号的过度权限",
            "REVOKE DELETE, DROP, FILE, CREATE, ALTER ON *.* FROM 'test_user'@'%';",
            "GRANT SELECT ON *.* TO 'test_user'@'%';",
            "",
            "-- 4. 限制开发账号的访问IP",
            "DROP USER 'dev_user'@'%';",
            "CREATE USER 'dev_user'@'192.168.%' IDENTIFIED BY '***';",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON dev_db.* TO 'dev_user'@'192.168.%';",
            "",
            "-- 5. 应用账号仅保留业务所需权限",
            "REVOKE DELETE, DROP ON *.* FROM 'app_user'@'192.168.%';",
            "",
            "-- 6. 锁定长时间未使用的用户",
            "ALTER USER 'test_user'@'%' ACCOUNT LOCK;",
            "ALTER USER 'dev_user'@'%' ACCOUNT LOCK;",
            "",
            "-- 7. 刷新权限",
            "FLUSH PRIVILEGES;",
            "",
            "-- ============================================",
            "-- 配置完成，请验证应用功能是否正常",
            "-- ============================================",
        ]

        return {
            "script": "\n".join(script_lines),
            "changes": [
                {"action": "DROP", "target": "匿名用户"},
                {"action": "DELETE", "target": "root远程登录"},
                {"action": "REVOKE", "target": "test_user过度权限", "sql": "REVOKE DELETE, DROP, FILE, CREATE, ALTER ON *.* FROM 'test_user'@'%';"},
                {"action": "DROP/CREATE", "target": "dev_user访问IP限制"},
                {"action": "REVOKE", "target": "app_user删除权限"},
                {"action": "LOCK", "target": "未使用用户"},
            ],
        }

    # ──────────────────────────────────────────
    # 权限报告
    # ──────────────────────────────────────────

    # def generate_report(self) -> str:
        """生成权限分析报告"""
        analysis = self.analyze_all()
        lines = [
            "=" * 60,
            "  数据库用户权限分析报告",
            "=" * 60,
            f"分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "【用户概览】",
            f"  总用户数: {analysis['summary']['total_users']}",
            f"  发现权限问题: {analysis['summary']['total_issues']}",
            f"    严重: {analysis['summary']['critical_count']}",
            f"    高危: {analysis['summary']['high_count']}",
            f"    中危: {analysis['summary']['medium_count']}",
            f"    低危: {analysis['summary']['low_count']}",
            "",
            "【权限问题详情】",
        ]

        for issue in analysis["issues"]:
            sev_icon = {"critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM", "low": "🔵 LOW"}
            icon = sev_icon.get(issue["severity"], "⚪")
            lines.append(f"  [{icon}] {issue['user']}@{issue['host']}")
            lines.append(f"    问题: {issue['description']}")
            lines.append(f"    建议: {issue['revoke_suggestion']}")
            lines.append("")

        lines.append("【改进建议】")
        for rec in analysis["recommendations"]:
            lines.append(f"  • {rec}")

        return "\n".join(lines)