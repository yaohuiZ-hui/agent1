"""
攻防演练靶场模块 - 防御验证器

验证学员的防御措施是否有效：
- 代码修复验证（参数化查询检查）
- WAF规则验证（ModSecurity规则模拟）
- 攻击重放验证（修复后是否仍可被攻破）
- 修复效果评分
"""
import re
import json
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from modules.shooting_range.vulnerable_app import VulnerableAppSimulator
from modules.shooting_range.attack_simulator import AttackSimulator


@dataclass
class DefenseTestResult:
    """防御测试结果"""
    test_id: str
    test_name: str
    defense_type: str  # code_fix, waf_rule, both
    status: str  # pass, fail, partial
    score: float
    details: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


class DefenseValidator:
    """
    防御验证器

    验证学员的防御措施是否有效：
    1. 代码修复验证 - 检查是否使用了参数化查询
    2. WAF规则验证 - 测试WAF规则能否拦截攻击
    3. 攻击重放验证 - 修复后重新攻击测试
    4. 综合评分
    """

    # 参数化查询的正则模式
    PARAMETERIZED_QUERY_PATTERNS = [
        r"cursor\.execute\([^,]+,\s*\([^)]*\)",  # cursor.execute("...", (params,))
        r"cursor\.execute\([^,]+,\s*\[[^\]]*\]",  # cursor.execute("...", [params])
        r"execute\([^,]+,\s*\{[^}]*\}",           # execute("...", {params})
        r"cursor\.execute\([^,]+,\s*{'",           # 命名参数
        r"execute\([^,]+,\s*(\(|\[|\{)",           # 一般参数化
    ]

    # 反模式：字符串拼接
    SQL_STRING_CONCAT_PATTERNS = [
        r'f"SELECT.*\{',         # f-string 拼接
        r"'SELECT.*' \+ ",       # 字符串连接
        r'"SELECT.*" \+ ',       # 字符串连接
        r"\"SELECT.*\" % ",      # % 格式化
        r"'SELECT.*' % ",        # % 格式化
        r"format\(.*SELECT",     # format方法
    ]

    # ModSecurity SQL注入规则模板
    WAF_RULE_TEMPLATES = {
        "union_inject": (
            'SecRule ARGS "(?:union(?:.+?)select|select(?:.+?)from)" '
            '"phase:2,deny,status:403,id:10001,msg:\'SQL Injection Union Attack\'"'
        ),
        "blind_inject": (
            "SecRule ARGS \"(?:\\\\bOR\\\\b|\\\\bAND\\\\b)\\\\s+[0-9]+\\\\s*=\\\\s*[0-9]+\" "
            "\"phase:2,deny,status:403,id:10002,msg:'SQL Injection Tautology Attack'\""
        ),
        "error_inject": (
            'SecRule ARGS "(?:EXTRACTVALUE|UPDATEXML|EXP\\\\()" '
            '"phase:2,deny,status:403,id:10003,msg:\'SQL Injection Error-Based Attack\'"'
        ),
    }

    def __init__(self, vuln_app: VulnerableAppSimulator, attack_sim: AttackSimulator):
        self._vuln_app = vuln_app
        self._attack_sim = attack_sim
        self._test_results: List[DefenseTestResult] = []

    # ──────────────────────────────────────────
    # 代码修复验证
    # ──────────────────────────────────────────

    def validate_code_fix(self, path: str, source_code: str) -> DefenseTestResult:
        """
        验证代码修复是否使用了参数化查询

        Args:
            path: API路径
            source_code: 学员提交的修复代码

        Returns:
            验证结果
        """
        test_id = f"code_fix_{path.replace('/', '_')}"
        details = []
        suggestions = []

        # 检查是否使用了参数化查询
        param_used = False
        for pattern in self.PARAMETERIZED_QUERY_PATTERNS:
            if re.search(pattern, source_code, re.DOTALL):
                param_used = True
                details.append("✓ 检测到参数化查询")
                break

        # 检查是否还存在字符串拼接
        concat_found = False
        for pattern in self.SQL_STRING_CONCAT_PATTERNS:
            if re.search(pattern, source_code, re.DOTALL):
                concat_found = True
                details.append(f"✗ 发现字符串拼接模式: {pattern}")
                break

        # 检查是否还有SQL关键字拼接
        if re.search(r'\{.*\}', source_code) and 'SELECT' in source_code.upper():
            if not param_used:
                concat_found = True
                details.append("✗ 发现f-string/SQL拼接")

        # 判定
        if param_used and not concat_found:
            status = "pass"
            score = 100.0
            details.append("✓ 代码修复完整：已使用参数化查询，无字符串拼接")
        elif param_used and concat_found:
            status = "partial"
            score = 50.0
            details.append("⚠ 部分修复：使用了参数化查询，但仍有字符串拼接代码")
            suggestions.append("移除所有字符串拼接，统一使用参数化查询")
        else:
            status = "fail"
            score = 0.0
            details.append("✗ 未检测到参数化查询，代码仍存在SQL注入风险")
            suggestions.append("使用 ? 占位符替代字符串拼接")
            suggestions.append('示例: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))')

        # 检查是否注释了漏洞说明
        if "参数化" in source_code or "parameterized" in source_code.lower():
            details.append("✓ 代码注释中包含参数化说明")
            score = min(score + 5, 100)

        result = DefenseTestResult(
            test_id=test_id,
            test_name=f"代码修复验证 - {path}",
            defense_type="code_fix",
            status=status,
            score=score,
            details=details,
            suggestions=suggestions,
        )
        self._test_results.append(result)
        return result

    # ──────────────────────────────────────────
    # WAF规则验证
    # ──────────────────────────────────────────

    def validate_waf_rule(self, waf_rules: str, target_path: str = None) -> DefenseTestResult:
        """
        验证WAF规则配置是否有效

        Args:
            waf_rules: 学员提交的WAF规则文本
            target_path: 目标路径

        Returns:
            验证结果
        """
        test_id = f"waf_rule_{datetime.now().strftime('%H%M%S')}"
        details = []
        suggestions = []

        # 检查是否包含SecRule
        has_secrule = "SecRule" in waf_rules
        has_phase = "phase:" in waf_rules
        has_deny = "deny" in waf_rules

        if has_secrule:
            details.append("✓ 检测到 SecRule 指令")
        else:
            details.append("✗ 缺少 SecRule 指令")

        if has_phase:
            details.append("✓ 检测到 phase 参数")
        else:
            details.append("✗ 缺少 phase 参数")

        if has_deny:
            details.append("✓ 检测到 deny 动作")
        else:
            details.append("✗ 缺少 deny 动作（规则不会拦截请求）")

        # 检查是否覆盖了不同注入类型
        covered_types = []
        for vuln_type, template in self.WAF_RULE_TEMPLATES.items():
            # 提取关键特征
            if "union" in waf_rules.lower() and "select" in waf_rules.lower():
                if "union" not in covered_types:
                    covered_types.append("union_inject")
            if "or" in waf_rules.lower() and ("=" in waf_rules):
                if "blind_inject" not in covered_types:
                    covered_types.append("blind_inject")
            if "extractvalue" in waf_rules.lower() or "updatexml" in waf_rules.lower():
                if "error_inject" not in covered_types:
                    covered_types.append("error_inject")

        if covered_types:
            details.append(f"✓ 规则覆盖注入类型: {', '.join(covered_types)}")
        else:
            suggestions.append("添加针对 UNION SELECT 的过滤规则")
            suggestions.append("添加针对恒真条件(OR 1=1)的过滤规则")

        # 判定
        if has_secrule and has_deny and covered_types:
            status = "pass"
            score = 90.0 + len(covered_types) * 5
        elif has_secrule and has_deny:
            status = "partial"
            score = 50.0
            suggestions.append("优化规则的正则表达式，覆盖更多攻击向量")
        else:
            status = "fail"
            score = 0.0
            suggestions.append("参考: " + self.WAF_RULE_TEMPLATES["union_inject"])

        result = DefenseTestResult(
            test_id=test_id,
            test_name="WAF规则验证",
            defense_type="waf_rule",
            status=status,
            score=min(score, 100),
            details=details,
            suggestions=suggestions,
        )
        self._test_results.append(result)
        return result

    # ──────────────────────────────────────────
    # 攻击重放验证
    # ──────────────────────────────────────────

    def replay_attack_test(self, path: str) -> DefenseTestResult:
        """
        修复后重放攻击，验证防御效果

        Args:
            path: API路径

        Returns:
            验证结果
        """
        test_id = f"replay_{path.replace('/', '_')}"
        details = []

        ep = self._vuln_app.get_endpoint(path)
        if not ep:
            return DefenseTestResult(
                test_id=test_id, test_name=f"攻击重放 - {path}",
                defense_type="both", status="fail", score=0,
                details=["端点不存在"],
            )

        # 使用多种攻击向量测试
        test_payloads = [
            "1 UNION SELECT 1,2,3,4",
            "1' OR '1'='1",
            "1 AND SLEEP(3)",
            "1 UNION SELECT * FROM credit_cards",
        ]

        blocked = 0
        for payload in test_payloads:
            result = self._attack_sim.run_attack(path, payload)
            if not result.get("success"):
                blocked += 1
                details.append(f"✓ 已拦截: {payload[:30]}...")

        # 获取端点状态
        if ep.fixed:
            # 代码修复 + 可能有WAF
            if blocked >= 3:
                status = "pass"
                score = 100.0
                details.append("✓ 防御有效：所有攻击向量均被拦截")
            elif blocked >= 1:
                status = "partial"
                score = 60.0
                details.append(f"⚠ 部分防御：{blocked}/{len(test_payloads)} 的攻击被拦截")
            else:
                status = "fail"
                score = 20.0
                details.append("✗ 防御无效：所有攻击均成功")
        else:
            if blocked >= 3:
                status = "partial"
                score = 50.0
                details.append("⚠ 代码未修复但WAF起效")
            else:
                status = "fail"
                score = 0.0
                details.append("✗ 端点未修复，攻击全部成功")

        # 端点本身状态
        details.append(f"端点修复状态: {'已修复(参数化查询)' if ep.fixed else '未修复(仍有漏洞)'}")

        result = DefenseTestResult(
            test_id=test_id,
            test_name=f"攻击重放验证 - {path}",
            defense_type="both",
            status=status,
            score=score,
            details=details,
            suggestions=[] if status == "pass" else ["修复代码并使用参数化查询", "配置WAF规则拦截SQL注入"],
        )
        self._test_results.append(result)
        return result

    # ──────────────────────────────────────────
    # 综合评分
    # ──────────────────────────────────────────

    def get_overall_defense_score(self) -> Dict[str, Any]:
        """获取防御综合评分"""
        if not self._test_results:
            return {"score": 0, "grade": "N/A", "message": "尚无防御测试记录"}

        total_score = sum(r.score for r in self._test_results)
        avg_score = total_score / len(self._test_results)

        if avg_score >= 90:
            grade = "A (优秀)"
            message = "防御措施完善，系统安全"
        elif avg_score >= 75:
            grade = "B (良好)"
            message = "防御措施基本有效，建议进一步优化"
        elif avg_score >= 60:
            grade = "C (合格)"
            message = "部分防御有效，需加强关键点防护"
        else:
            grade = "F (不合格)"
            message = "防御措施不足，系统仍存在严重风险"

        return {
            "score": round(avg_score, 1),
            "grade": grade,
            "message": message,
            "test_count": len(self._test_results),
            "passed": sum(1 for r in self._test_results if r.status == "pass"),
            "failed": sum(1 for r in self._test_results if r.status == "fail"),
            "details": [
                {
                    "test_name": r.test_name,
                    "status": r.status,
                    "score": r.score,
                    "suggestions": r.suggestions,
                }
                for r in self._test_results
            ],
        }

    def clear_results(self):
        """清除测试结果"""
        self._test_results.clear()