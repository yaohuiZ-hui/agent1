"""
工具函数 - 通用辅助函数

提供项目中常用的工具函数。
"""
import os
import re
import json
from typing import Any, Dict, List, Optional, Union
from datetime import datetime


def ensure_dir(dir_path: str) -> str:
    """确保目录存在，不存在则创建"""
    os.makedirs(dir_path, exist_ok=True)
    return dir_path


def truncate_text(text: str, max_length: int = 100) -> str:
    """截断文本并添加省略号"""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def sanitize_sql(sql: str) -> str:
    """
    脱敏SQL语句中的敏感信息

    Args:
        sql: 原始SQL语句

    Returns:
        脱敏后的SQL（替换密码和具体值）
    """
    # 替换密码
    sql = re.sub(r"(IDENTIFIED BY\s+)['\"][^'\"]+['\"]",
                 r"\1'***'", sql, flags=re.IGNORECASE)
    # 替换具体数值
    sql = re.sub(r"(PASSWORD\s*=\s*)['\"][^'\"]+['\"]",
                 r"\1'***'", sql, flags=re.IGNORECASE)
    return sql


def format_timestamp(ts: Optional[str] = None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """格式化时间戳"""
    if ts:
        return ts[:19] if len(ts) >= 19 else ts
    return datetime.now().strftime(fmt)


def dict_to_table(data: List[Dict[str, Any]], headers: Optional[List[str]] = None) -> str:
    """
    将字典列表转换为表格字符串

    Args:
        data: 字典列表
        headers: 表头列表，None则使用字典key

    Returns:
        表格字符串
    """
    if not data:
        return "(空)"

    if headers is None:
        headers = list(data[0].keys())

    # 计算列宽
    col_widths = {h: len(str(h)) for h in headers}
    for row in data:
        for h in headers:
            val = str(row.get(h, ""))
            col_widths[h] = max(col_widths[h], len(val))

    # 构建表格
    sep = "+" + "+".join("-" * (col_widths[h] + 2) for h in headers) + "+"
    header_line = "| " + " | ".join(str(h).ljust(col_widths[h]) for h in headers) + " |"

    lines = [sep, header_line, sep]
    for row in data:
        line = "| " + " | ".join(str(row.get(h, "")).ljust(col_widths[h]) for h in headers) + " |"
        lines.append(line)
    lines.append(sep)

    return "\n".join(lines)


def parse_command_line(cmd: str) -> Dict[str, Any]:
    """
    解析命令行输入

    Args:
        cmd: 完整的命令行

    Returns:
        {"command": str, "args": list, "options": dict}
    """
    parts = cmd.strip().split()
    if not parts:
        return {"command": "", "args": [], "options": {}}

    command = parts[0].lower()
    args = []
    options = {}

    i = 1
    while i < len(parts):
        if parts[i].startswith("--"):
            # --key=value 或 --key value
            if "=" in parts[i]:
                key, value = parts[i][2:].split("=", 1)
                options[key] = value
            else:
                key = parts[i][2:]
                if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                    i += 1
                    options[key] = parts[i]
                else:
                    options[key] = True
        elif parts[i].startswith("-"):
            # -k value 或 -k
            key = parts[i][1:]
            if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                i += 1
                options[key] = parts[i]
            else:
                options[key] = True
        else:
            args.append(parts[i])
        i += 1

    return {"command": command, "args": args, "options": options}


def generate_id(prefix: str = "AG") -> str:
    """生成唯一ID（基于时间戳）"""
    now = datetime.now()
    return f"{prefix}{now.strftime('%Y%m%d%H%M%S')}{now.microsecond // 1000:03d}"


def colorize(text: str, color: str = "green") -> str:
    """
    包裹ANSI颜色代码

    Args:
        text: 文本
        color: 颜色名 (green, red, yellow, blue, cyan, magenta, white)

    Returns:
        带ANSI颜色的文本
    """
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "magenta": "\033[95m",
        "white": "\033[97m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }
    c = colors.get(color, colors["green"])
    reset = colors["reset"]
    return f"{c}{text}{reset}"