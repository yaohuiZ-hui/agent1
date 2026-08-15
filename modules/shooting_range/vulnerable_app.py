"""
攻防演练靶场模块 - 漏洞应用模拟器

模拟存在SQL注入漏洞的银行核心业务系统"老旧接口"：
- 提供3个存在漏洞的模拟API端点
- 支持 Union 注入、盲注、错误注入
- 模拟真实业务数据（用户、信用卡、订单）
- 漏洞源码可查看和编辑修复
"""
import json
import re
import random
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class VulnerableEndpoint:
    """漏洞端点定义"""
    path: str
    method: str
    params: Dict[str, str]
    vuln_type: str  # union_inject, blind_inject, error_inject
    description: str
    fixed: bool = False
    source_code: str = ""


# 模拟数据库表
MOCK_DB = {
    "users": [
        {"id": 1, "username": "admin", "password_hash": "e10adc3949ba59abbe56e057f20f883e",
         "email": "admin@corebank.com", "phone": "13800138001", "role": "admin"},
        {"id": 2, "username": "zhangli", "password_hash": "fcea920f7412b5da7be0cf42b8c93759",
         "email": "zhangli@corebank.com", "phone": "13800138002", "role": "manager"},
        {"id": 3, "username": "wangwu", "password_hash": "96e79218965eb72c92a549dd5a330112",
         "email": "wangwu@corebank.com", "phone": "13800138003", "role": "clerk"},
        {"id": 101, "username": "customer01", "password_hash": "5d41402abc4b2a76b9719d911017c592",
         "email": "customer01@example.com", "phone": "13900139001", "role": "customer"},
        {"id": 102, "username": "customer02", "password_hash": "7d793037a0760186574b0282f2f435e7",
         "email": "customer02@example.com", "phone": "13900139002", "role": "customer"},
    ],
    "credit_cards": [
        {"id": 1, "user_id": 101, "card_no": "6228480012345678", "balance": 50000.00,
         "expiry": "2026-12", "cvv": "123"},
        {"id": 2, "user_id": 101, "card_no": "6228480012345679", "balance": 120000.00,
         "expiry": "2027-06", "cvv": "456"},
        {"id": 3, "user_id": 102, "card_no": "6228480012345680", "balance": 80000.00,
         "expiry": "2026-09", "cvv": "789"},
    ],
    "trade_flow": [
        {"id": 1, "from_account": "6228480012345678", "to_account": "6228480012349000",
         "amount": 15000.00, "type": "TRANSFER", "timestamp": "2024-01-15 09:30:00"},
        {"id": 2, "from_account": "6228480012345679", "to_account": "6228480012349001",
         "amount": 5000.00, "type": "TRANSFER", "timestamp": "2024-01-15 10:15:00"},
        {"id": 3, "from_account": "6228480012345680", "to_account": "6228480012349002",
         "amount": 20000.00, "type": "PAYMENT", "timestamp": "2024-01-16 14:20:00"},
    ],
    "accounts": [
        {"id": 1, "account_no": "6228480012345678", "customer_name": "张三", "balance": 150000.00},
        {"id": 2, "account_no": "6228480012345679", "customer_name": "张三", "balance": 300000.00},
        {"id": 3, "account_no": "6228480012345680", "customer_name": "李四", "balance": 200000.00},
    ],
}


class VulnerableAppSimulator:
    """
    漏洞应用模拟器

    模拟存在SQL注入漏洞的银行核心业务系统API。
    提供3个漏洞端点，支持攻击复现和源码查看。
    """

    def __init__(self):
        self._endpoints = self._init_endpoints()

    def _init_endpoints(self) -> List[VulnerableEndpoint]:
        """初始化漏洞端点"""
        return [
            VulnerableEndpoint(
                path="/api/user/profile",
                method="GET",
                params={"id": "int"},
                vuln_type="union_inject",
                description="用户信息查询接口（存在Union注入漏洞）",
                source_code=(
                    "@app.route('/api/user/profile')\n"
                    "def get_user_profile():\n"
                    "    user_id = request.args.get('id')\n"
                    "    # 漏洞: 直接拼接用户输入\n"
                    '    query = f"SELECT id, username, email, phone FROM users WHERE id = {user_id}"\n'
                    "    cursor.execute(query)\n"
                    "    return jsonify(cursor.fetchall())\n"
                ),
            ),
            VulnerableEndpoint(
                path="/api/search/product",
                method="GET",
                params={"keyword": "str"},
                vuln_type="blind_inject",
                description="产品搜索接口（存在盲注漏洞）",
                source_code=(
                    "@app.route('/api/search/product')\n"
                    "def search_product():\n"
                    "    keyword = request.args.get('keyword')\n"
                    "    # 漏洞: 直接拼接用户输入\n"
                    '    query = f"SELECT * FROM products WHERE name LIKE \'%{keyword}%\'"\n'
                    "    cursor.execute(query)\n"
                    "    return jsonify(cursor.fetchall())\n"
                ),
            ),
            VulnerableEndpoint(
                path="/api/order/query",
                method="POST",
                params={"order_id": "int"},
                vuln_type="error_inject",
                description="订单查询接口（存在错误注入漏洞）",
                source_code=(
                    "@app.route('/api/order/query', methods=['POST'])\n"
                    "def query_order():\n"
                    "    order_id = request.json.get('order_id')\n"
                    "    # 漏洞: 直接拼接用户输入\n"
                    '    query = f"SELECT * FROM orders WHERE id = {order_id}"\n'
                    "    cursor.execute(query)\n"
                    "    return jsonify(cursor.fetchall())\n"
                ),
            ),
        ]

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """获取所有端点信息"""
        return [
            {
                "path": ep.path,
                "method": ep.method,
                "params": ep.params,
                "vuln_type": ep.vuln_type,
                "description": ep.description,
                "fixed": ep.fixed,
            }
            for ep in self._endpoints
        ]

    def get_endpoint(self, path: str) -> Optional[VulnerableEndpoint]:
        """获取指定端点"""
        for ep in self._endpoints:
            if ep.path == path:
                return ep
        return None

    def get_source_code(self, path: str) -> Optional[str]:
        """获取端点源码"""
        ep = self.get_endpoint(path)
        return ep.source_code if ep else None

    # ──────────────────────────────────────────
    # 请求处理
    # ──────────────────────────────────────────

    def handle_request(self, path: str, method: str, params: Dict[str, str]) -> Dict[str, Any]:
        """
        处理模拟API请求（模拟SQL注入漏洞）

        Args:
            path: API路径
            method: HTTP方法
            params: 请求参数

        Returns:
            API响应（如果存在漏洞，可能返回不应泄露的数据）
        """
        ep = self.get_endpoint(path)
        if not ep:
            return {"error": "Not Found", "status": 404}

        if ep.method != method:
            return {"error": "Method Not Allowed", "status": 405}

        # 如果已修复，返回安全响应
        if ep.fixed:
            if path == "/api/user/profile":
                user_id = params.get("id", "1")
                if user_id.isdigit():
                    user = self._get_user(int(user_id))
                    if user:
                        return {"status": 200, "data": user}
                return {"status": 404, "error": "User not found"}
            return {"status": 200, "data": {"message": "Query executed safely"}}

        # 未修复：模拟漏洞响应
        return self._simulate_vulnerable_response(ep, params)

    def _simulate_vulnerable_response(self, ep: VulnerableEndpoint, params: Dict[str, str]) -> Dict[str, Any]:
        """模拟存在漏洞的API响应"""
        if ep.vuln_type == "union_inject":
            return self._simulate_union_inject(params)
        elif ep.vuln_type == "blind_inject":
            return self._simulate_blind_inject(params)
        elif ep.vuln_type == "error_inject":
            return self._simulate_error_inject(params)
        return {"status": 200, "data": {"message": "OK"}}

    def _simulate_union_inject(self, params: Dict[str, str]) -> Dict[str, Any]:
        """模拟Union注入响应"""
        user_input = params.get("id", "1")

        # 检测Union注入攻击
        union_match = re.search(r"UNION\s+(ALL\s+)?SELECT", user_input, re.IGNORECASE)
        if union_match:
            # 模拟注入成功，泄露信用卡数据
            return {
                "status": 200,
                "vuln_detected": True,
                "vuln_type": "union_inject",
                "original_query": f"SELECT id, username, email, phone FROM users WHERE id = {user_input}",
                "injected_data": [
                    {"id": 1, "username": "admin", "email": "admin@corebank.com", "phone": "13800138001"},
                    {"id": 1, "card_no": "6228480012345678", "balance": 50000.00, "cvv": "123"},
                    {"id": 2, "card_no": "6228480012345679", "balance": 120000.00, "cvv": "456"},
                    {"id": 3, "card_no": "6228480012345680", "balance": 80000.00, "cvv": "789"},
                ],
                "warning": "⚠ 存在Union注入漏洞！信用卡数据已泄露！",
            }

        # 正常请求
        user_id = user_input if user_input.isdigit() else "1"
        user = self._get_user(int(user_id))
        if user:
            return {"status": 200, "data": user}
        return {"status": 404, "error": "User not found"}

    def _simulate_blind_inject(self, params: Dict[str, str]) -> Dict[str, Any]:
        """模拟盲注响应"""
        keyword = params.get("keyword", "")

        # 检测盲注特征
        if re.search(r"1\s*=\s*1|true\s*or", keyword, re.IGNORECASE):
            return {
                "status": 200,
                "vuln_detected": True,
                "vuln_type": "blind_inject",
                "data": [{"id": 1, "name": "ALL_PRODUCTS_LEAKED", "price": 999999}],
                "warning": "⚠ 存在盲注漏洞！恒真条件返回了所有数据！",
            }

        if re.search(r"SLEEP|BENCHMARK|WAITFOR", keyword, re.IGNORECASE):
            return {
                "status": 200,
                "vuln_detected": True,
                "vuln_type": "blind_inject",
                "data": [{"id": 1, "name": "Time-based Blind", "delay": "3.0s"}],
                "warning": "⚠ 存在基于时间的盲注漏洞！",
            }

        # 正常搜索
        return {
            "status": 200,
            "data": [{"id": 1, "name": f"产品({keyword})", "price": 99.99}],
        }

    def _simulate_error_inject(self, params: Dict[str, str]) -> Dict[str, Any]:
        """模拟错误注入响应"""
        order_id = params.get("order_id", "1")

        # 检测错误注入
        if re.search(r"EXTRACTVALUE|UPDATEXML|CONVERT|EXP", order_id, re.IGNORECASE):
            return {
                "status": 500,
                "vuln_detected": True,
                "vuln_type": "error_inject",
                "error_message": f"XPATH syntax error: '~admin@corebank.com~'",
                "warning": "⚠ 存在错误注入漏洞！数据库错误信息泄露了数据！",
            }

        return {
            "status": 200,
            "data": {"order_id": int(order_id) if order_id.isdigit() else 0, "status": "completed", "amount": 15000.00},
        }

    def _get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """获取模拟用户数据"""
        for user in MOCK_DB["users"]:
            if user["id"] == user_id:
                return {
                    "id": user["id"],
                    "username": user["username"],
                    "email": user["email"],
                    "phone": user["phone"],
                    "role": user["role"],
                }
        return None

    # ──────────────────────────────────────────
    # 修复管理
    # ──────────────────────────────────────────

    def fix_endpoint(self, path: str, new_code: str = None) -> Dict[str, Any]:
        """
        修复端点漏洞（切换为参数化查询）

        Args:
            path: API路径
            new_code: 新的源码（可选）

        Returns:
            修复结果
        """
        ep = self.get_endpoint(path)
        if not ep:
            return {"error": "端点不存在", "success": False}

        if ep.fixed:
            return {"message": "该端点已修复", "success": True}

        ep.fixed = True
        if new_code:
            ep.source_code = new_code

        # 生成修复后的代码
        if ep.vuln_type == "union_inject":
            ep.source_code = (
                "@app.route('/api/user/profile')\n"
                "def get_user_profile():\n"
                "    user_id = request.args.get('id')\n"
                "    # 已修复: 使用参数化查询\n"
                '    query = "SELECT id, username, email, phone FROM users WHERE id = ?"\n'
                "    cursor.execute(query, (user_id,))\n"
                "    return jsonify(cursor.fetchall())\n"
            )
        elif ep.vuln_type == "blind_inject":
            ep.source_code = (
                "@app.route('/api/search/product')\n"
                "def search_product():\n"
                "    keyword = request.args.get('keyword')\n"
                "    # 已修复: 使用参数化查询\n"
                '    query = "SELECT * FROM products WHERE name LIKE ?"\n'
                '    cursor.execute(query, (f"%{keyword}%",))\n'
                "    return jsonify(cursor.fetchall())\n"
            )
        elif ep.vuln_type == "error_inject":
            ep.source_code = (
                "@app.route('/api/order/query', methods=['POST'])\n"
                "def query_order():\n"
                "    order_id = request.json.get('order_id')\n"
                "    # 已修复: 使用参数化查询\n"
                '    query = "SELECT * FROM orders WHERE id = ?"\n'
                "    cursor.execute(query, (order_id,))\n"
                "    return jsonify(cursor.fetchall())\n"
            )

        return {"success": True, "message": "端点已修复，已使用参数化查询替代字符串拼接", "path": path}

    def reset_endpoint(self, path: str) -> Dict[str, Any]:
        """重置端点（恢复漏洞）"""
        ep = self.get_endpoint(path)
        if not ep:
            return {"error": "端点不存在", "success": False}
        ep.fixed = False
        return {"success": True, "message": "端点已重置（恢复漏洞状态）", "path": path}

    def reset_all(self):
        """重置所有端点"""
        self._endpoints = self._init_endpoints()

    # ──────────────────────────────────────────
    # 数据查询
    # ──────────────────────────────────────────

    def get_mock_db_snapshot(self) -> Dict[str, Any]:
        """获取模拟数据库快照"""
        return {
            "users_count": len(MOCK_DB["users"]),
            "credit_cards_count": len(MOCK_DB["credit_cards"]),
            "trade_flow_count": len(MOCK_DB["trade_flow"]),
            "sample_data": {
                "users": MOCK_DB["users"][:2],
                "credit_cards": MOCK_DB["credit_cards"][:2],
            },
        }

    def get_scan_result(self) -> Dict[str, Any]:
        """获取漏洞扫描结果"""
        results = []
        for ep in self._endpoints:
            results.append({
                "path": ep.path,
                "method": ep.method,
                "vuln_type": ep.vuln_type,
                "description": ep.description,
                "fixed": ep.fixed,
                "risk_level": "HIGH" if not ep.fixed else "LOW",
            })
        return {
            "total_endpoints": len(results),
            "vulnerable_count": sum(1 for r in results if not r["fixed"]),
            "fixed_count": sum(1 for r in results if r["fixed"]),
            "details": results,
        }