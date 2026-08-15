"""
运维工具箱模块 - 基线检查器

基于 CIS MySQL Benchmark 的自动化安全基线检查工具：
- 预定义检查项（匿名用户、密码强度、权限、SSL等）
- 一键运行全部检查
- 逐项修复指导
- 检查结果导出
"""
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
from datetime import datetime

from config.settings import get_config, Config


@dataclass
class CheckItem:
    """检查项"""
    check_id: str
    check_name: str
    category: str  # authentication, authorization, encryption, audit, general
    description: str
    severity: str  # critical, high, medium, low
    check_command: str
    expected_value: str
    fix_command: str
    risk_description: str


# CIS MySQL Benchmark 基线检查项
CIS_BASELINE_ITEMS = [
    CheckItem(
        check_id="1.1", check_name="匿名用户检查", category="authentication",
        description="检查是否存在匿名用户账号",
        severity="high", check_command="SELECT COUNT(*) FROM mysql.user WHERE user=''",
        expected_value="不存在匿名用户", fix_command="DROP USER ''@'localhost'; DROP USER ''@'%';",
        risk_description="匿名用户可以无需认证访问数据库，存在未授权访问风险",
    ),
    CheckItem(
        check_id="1.2", check_name="密码过期策略", category="authentication",
        description="检查是否设置了密码过期策略",
        severity="medium", check_command="SHOW VARIABLES LIKE 'default_password_lifetime'",
        expected_value="default_password_lifetime = 180", fix_command="SET GLOBAL default_password_lifetime=180;",
        risk_description="密码长期不更换增加被破解风险",
    ),
    CheckItem(
        check_id="1.3", check_name="密码强度验证", category="authentication",
        description="检查是否启用了密码强度验证插件",
        severity="medium", check_command="SHOW VARIABLES LIKE 'validate_password%'",
        expected_value="validate_password.policy=MEDIUM+", fix_command="INSTALL PLUGIN validate_password SONAME 'validate_password.so';",
        risk_description="弱密码容易被暴力破解",
    ),
    CheckItem(
        check_id="2.1", check_name="root远程登录", category="authorization",
        description="检查root是否允许远程登录",
        severity="critical", check_command="SELECT user, host FROM mysql.user WHERE user='root' AND host='%'",
        expected_value="root仅允许localhost登录", fix_command="DELETE FROM mysql.user WHERE user='root' AND host='%'; FLUSH PRIVILEGES;",
        risk_description="root远程登录是数据库安全的重大威胁",
    ),
    CheckItem(
        check_id="2.2", check_name="过度授权检查", category="authorization",
        description="检查拥有全局DELETE/DROP权限的用户",
        severity="critical", check_command="SELECT user, host FROM mysql.user WHERE Delete_priv='Y' OR Drop_priv='Y'",
        expected_value="仅管理员拥有DELETE/DROP权限", fix_command="REVOKE DELETE, DROP ON *.* FROM 'user'@'host';",
        risk_description="过多的删除权限可能导致数据丢失",
    ),
    CheckItem(
        check_id="2.3", check_name="FILE权限检查", category="authorization",
        description="检查拥有FILE权限的用户",
        severity="high", check_command="SELECT user, host FROM mysql.user WHERE File_priv='Y'",
        expected_value="仅管理员拥有FILE权限", fix_command="REVOKE FILE ON *.* FROM 'user'@'host';",
        risk_description="FILE权限可被用来读取服务器文件或写入webshell",
    ),
    CheckItem(
        check_id="2.4", check_name="SUPER权限检查", category="authorization",
        description="检查拥有SUPER权限的用户",
        severity="high", check_command="SELECT user, host FROM mysql.user WHERE Super_priv='Y'",
        expected_value="仅管理员拥有SUPER权限", fix_command="REVOKE SUPER ON *.* FROM 'user'@'host';",
        risk_description="SUPER权限可绕过所有权限检查",
    ),
    CheckItem(
        check_id="3.1", check_name="SSL/TLS启用", category="encryption",
        description="检查是否启用了SSL连接",
        severity="medium", check_command="SHOW VARIABLES LIKE 'have_ssl'",
        expected_value="have_ssl=YES", fix_command="在my.cnf中配置SSL证书路径并重启",
        risk_description="未加密的传输可能被中间人攻击窃听",
    ),
    CheckItem(
        check_id="4.1", check_name="审计日志启用", category="audit",
        description="检查是否启用了通用查询日志",
        severity="medium", check_command="SHOW VARIABLES LIKE 'general_log%'",
        expected_value="general_log=ON", fix_command="SET GLOBAL general_log=ON;",
        risk_description="未开启审计日志无法追踪数据库操作历史",
    ),
    CheckItem(
        check_id="4.2", check_name="慢查询日志", category="audit",
        description="检查是否启用了慢查询日志",
        severity="low", check_command="SHOW VARIABLES LIKE 'slow_query_log%'",
        expected_value="slow_query_log=ON", fix_command="SET GLOBAL slow_query_log=ON;",
        risk_description="慢查询日志有助于发现性能问题",
    ),
    CheckItem(
        check_id="5.1", check_name="默认端口修改", category="general",
        description="检查是否使用了默认端口3306",
        severity="low", check_command="SHOW VARIABLES LIKE 'port'",
        expected_value="建议修改非默认端口", fix_command="修改my.cnf中的port=3307",
        risk_description="默认端口容易成为针对性扫描的目标",
    ),
    CheckItem(
        check_id="5.2", check_name="本地文件加载", category="general",
        description="检查是否禁用了LOAD DATA LOCAL",
        severity="high", check_command="SHOW VARIABLES LIKE 'local_infile'",
        expected_value="local_infile=OFF", fix_command="SET GLOBAL local_infile=OFF;",
        risk_description="允许本地文件加载可被利用来读取敏感文件",
    ),
]


class BaselineChecker:
    """
    基线检查器

    基于CIS MySQL Benchmark的自动化安全基线检查工具。
    提供一键检查、逐项修复、结果导出等功能。
    """

    def __init__(self, config: Optional[Config] = None):
        self._config = config or get_config()
        self._results: Dict[str, Dict[str, Any]] = {}

    def get_all_checks(self) -> List[Dict[str, Any]]:
        """获取所有检查项"""
        return [asdict(item) for item in CIS_BASELINE_ITEMS]

    def get_checks_by_category(self, category: str) -> List[Dict[str, Any]]:
        """按分类获取检查项"""
        return [asdict(item) for item in CIS_BASELINE_ITEMS if item.category == category]

    def get_checks_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """按严重级别获取检查项"""
        return [asdict(item) for item in CIS_BASELINE_ITEMS if item.severity == severity]

    def run_single_check(self, check_id: str) -> Dict[str, Any]:
        """
        执行单条基线检查

        Args:
            check_id: 检查项ID

        Returns:
            检查结果
        """
        item = next((c for c in CIS_BASELINE_ITEMS if c.check_id == check_id), None)
        if not item:
            return {"error": f"未知检查项: {check_id}", "check_id": check_id}

        # 模拟检查结果
        simulated = self._simulate_check(item)
        self._results[check_id] = simulated
        simulated["check_time"] = datetime.now().isoformat()
        return simulated

    def _simulate_check(self, item: CheckItem) -> Dict[str, Any]:
        """模拟检查结果"""
        # 模拟不同检查项的通过/失败状态
        fail_map = {
            "1.1": True, "1.2": True, "1.3": True,
            "2.1": True, "2.2": True, "2.3": True, "2.4": False,
            "3.1": True, "4.1": True, "4.2": False,
            "5.1": True, "5.2": True,
        }
        is_fail = fail_map.get(item.check_id, False)

        actual_values = {
            "1.1": "存在2个匿名用户(''@'localhost', ''@'%')",
            "1.2": "default_password_lifetime = 0 (永不过期)",
            "1.3": "validate_password.policy = LOW",
            "2.1": "存在 root@% 远程登录账号",
            "2.2": "3个用户拥有全局DELETE权限, 2个用户拥有DROP权限",
            "2.3": "2个用户拥有FILE权限 (test_user, dev_user)",
            "2.4": "仅管理员拥有SUPER权限",
            "3.1": "have_ssl = DISABLED",
            "4.1": "general_log = OFF",
            "4.2": "slow_query_log = ON",
            "5.1": "port = 3306 (默认端口)",
            "5.2": "local_infile = ON",
        }

        return {
            "check_id": item.check_id,
            "check_name": item.check_name,
            "category": item.category,
            "severity": item.severity,
            "status": "fail" if is_fail else "pass",
            "actual_value": actual_values.get(item.check_id, "符合预期"),
            "expected_value": item.expected_value,
            "fix_command": item.fix_command if is_fail else "",
            "risk_description": item.risk_description if is_fail else "",
            "description": item.description,
            "check_command": item.check_command,
        }

    def run_all_checks(self) -> Dict[str, Any]:
        """运行所有基线检查"""
        results = []
        for item in CIS_BASELINE_ITEMS:
            result = self.run_single_check(item.check_id)
            results.append(result)

        fail_count = sum(1 for r in results if r.get("status") == "fail")
        pass_count = sum(1 for r in results if r.get("status") == "pass")
        score = max(0, 100 - (fail_count / len(results)) * 100)

        return {
            "summary": {
                "total": len(results),
                "passed": pass_count,
                "failed": fail_count,
                "score": round(score, 1),
                "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "F",
                "timestamp": datetime.now().isoformat(),
            },
            "details": results,
        }

    def get_high_risk_checks(self) -> List[Dict[str, Any]]:
        """获取高风险检查结果"""
        return [
            r for r in self._results.values()
            if r.get("status") == "fail" and r.get("severity") in ("critical", "high")
        ]

    def generate_fix_script(self, check_ids: List[str] = None) -> str:
        """
        生成修复脚本

        Args:
            check_ids: 要修复的检查项ID列表，None则修复所有失败项

        Returns:
            修复SQL脚本
        """
        if check_ids:
            items = [c for c in CIS_BASELINE_ITEMS if c.check_id in check_ids]
        else:
            items = [c for c in CIS_BASELINE_ITEMS
                     if self._results.get(c.check_id, {}).get("status") == "fail"]

        lines = [
            "-- ============================================",
            "-- 数据库安全基线加固脚本",
            f"-- 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "-- ============================================",
            "",
        ]

        for item in items:
            result = self._results.get(item.check_id, {})
            if result.get("status") == "fail":
                lines.append(f"-- [{item.severity.upper()}] {item.check_id}: {item.check_name}")
                lines.append(f"-- 风险: {item.risk_description}")
                lines.append(f"{item.fix_command}")
                lines.append("")

        if len(lines) == 3:
            lines.append("-- 无待修复项，所有检查已通过")

        return "\n".join(lines)

    def export_report(self, format: str = "text") -> str:
        """
        导出检查报告

        Args:
            format: 输出格式 (text/json)

        Returns:
            报告内容
        """
        result = self.run_all_checks()

        if format == "json":
            import json
            return json.dumps(result, ensure_ascii=False, indent=2)

        # 文本格式
        s = result["summary"]
        lines = [
            "=" * 60,
            "  数据库安全基线检查报告 (CIS MySQL Benchmark)",
            "=" * 60,
            f"检查时间: {s['timestamp']}",
            f"总计: {s['total']}项 | 通过: {s['passed']} | 失败: {s['failed']}",
            f"安全评分: {s['score']}/100 | 等级: {s['grade']}",
            "-" * 60,
            "",
        ]

        for detail in result["details"]:
            icon = "✓" if detail["status"] == "pass" else "✗"
            lines.append(f"[{icon}] [{detail['severity'].upper()}] {detail['check_id']} {detail['check_name']}")
            if detail["status"] == "fail":
                lines.append(f"     实际值: {detail['actual_value']}")
                lines.append(f"     期望值: {detail['expected_value']}")
                lines.append(f"     修复: {detail['fix_command']}")
            lines.append("")

        return "\n".join(lines)