"""
运维工具箱模块 - SQL 判定器（LangGraph + 大模型）

对学员输入终端的 SQL 进行三层判定：
1. 语法是否正确
2. 是否命中当前分支的某个待修复错误点
3. 是否能正确修复该错误点，以及是否存在 SQL 安全风险

底层使用 LangGraph 两节点图（judge → reframe），接入 ChatAnthropic。
模型配置与 ~/.claude/settings.json 保持一致（ANTHROPIC_BASE_URL / AUTH_TOKEN / MODEL）。
LLM 异常 / 超时 / 响应不可解析时返回 None，由调用方降级到确定性校验。
"""
import json
import os
import threading
from typing import Dict, Any, Optional, List, TypedDict

try:
    from langgraph.graph import StateGraph, START, END
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_anthropic import ChatAnthropic
    _DEPS_OK = True
except Exception:  # pragma: no cover - 依赖缺失时静默降级
    _DEPS_OK = False

# 模型配置（与 C:\\Users\\31779\\.claude\\settings.json 保持一致；环境变量优先）
DEFAULT_BASE_URL = "https://raytoken.com.cn"
DEFAULT_API_KEY = "webray-key-0e88e21887e47fa8a5fbd9b343e52d5e"
DEFAULT_MODEL = "deepseek-v4-flash"
TIMEOUT_SECONDS = 20
MAX_RETRIES = 2  # JSON 解析失败时的重试次数（reframe 节点）

SYSTEM_PROMPT = (
    "你是一个数据库安全专家，对于用户输入的sql代码进行判断语法是否错误，"
    "是否会存在sql安全问题。"
)

# ══════════════════════════════════════════
# 配置加载
# ══════════════════════════════════════════

def _load_model_config() -> Dict[str, str]:
    """按优先级读取模型配置：环境变量 → ~/.claude/settings.json → 默认值。"""
    cfg = {
        "base_url": os.environ.get("ANTHROPIC_BASE_URL", ""),
        "api_key": os.environ.get("ANTHROPIC_AUTH_TOKEN", "") or os.environ.get("ANTHROPIC_API_KEY", ""),
        "model": os.environ.get("ANTHROPIC_MODEL", ""),
    }
    if not (cfg["base_url"] and cfg["api_key"] and cfg["model"]):
        try:
            with open(os.path.join(os.path.expanduser("~"), ".claude", "settings.json"),
                      "r", encoding="utf-8") as f:
                env = json.load(f).get("env", {})
            if not cfg["base_url"]:
                cfg["base_url"] = env.get("ANTHROPIC_BASE_URL", "")
            if not cfg["api_key"]:
                cfg["api_key"] = env.get("ANTHROPIC_AUTH_TOKEN", "") or env.get("ANTHROPIC_API_KEY", "")
            if not cfg["model"]:
                cfg["model"] = env.get("ANTHROPIC_MODEL", "")
        except Exception:
            pass
    cfg["base_url"] = cfg["base_url"] or DEFAULT_BASE_URL
    cfg["api_key"] = cfg["api_key"] or DEFAULT_API_KEY
    cfg["model"] = cfg["model"] or DEFAULT_MODEL
    return cfg

_llm = None
_llm_lock = threading.Lock()


def _get_llm():
    """懒加载全局 LLM 实例（单例）。"""
    global _llm
    if _llm is None:
        if not _DEPS_OK:
            return None
        with _llm_lock:
            if _llm is None:
                cfg = _load_model_config()
                _llm = ChatAnthropic(
                    model=cfg["model"],
                    api_key=cfg["api_key"],
                    base_url=cfg["base_url"],
                    timeout=TIMEOUT_SECONDS,
                    max_tokens=1024,
                    temperature=0,
                    default_headers={"Authorization": f"Bearer {cfg['api_key']}"},
                )
    return _llm


# ══════════════════════════════════════════
# Prompt 组装与响应解析
# ══════════════════════════════════════════

def _extract_text(content: Any) -> str:
    """从模型响应中提取纯文本（兼容 str 与 langchain 内容块列表）。"""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text" and item.get("text"):
                    parts.append(item["text"])
                elif item.get("type") == "text_delta" and item.get("delta"):
                    parts.append(item["delta"])
            elif isinstance(item, str):
                parts.append(item)
        return "".join(parts)
    return str(content)


def _parse_verdict(text: str) -> Optional[Dict[str, Any]]:
    """从模型输出中解析结构化裁决 JSON；失败返回 None。"""
    if not text:
        return None
    t = text.strip()
    # 去掉 markdown 代码围栏
    if t.startswith("```"):
        t = t.strip("`").strip()
        if t.lower().startswith("json"):
            t = t[4:].strip()
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        obj = json.loads(t[start:end + 1])
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    return {
        "syntax_valid": bool(obj.get("syntax_valid", True)),
        "syntax_error": (obj.get("syntax_error") or "").strip(),
        "targets_error_point": (obj.get("targets_error_point") or None),
        "fixes_error_point": bool(obj.get("fixes_error_point", False)),
        "security_issue": bool(obj.get("security_issue", False)),
        "explanation": (obj.get("explanation") or "").strip(),
    }


def _build_user_prompt(state: Dict[str, Any], extra: str = "") -> str:
    lines = [
        "请对学员输入到终端的 SQL 语句进行判定，并仅输出一个 JSON 对象（不要输出任何其他文字）。",
        "",
        "【当前待修复的错误点清单】",
        state.get("error_points", "(无)"),
        "",
        "【当前权限状态快照】",
        state.get("perms_snapshot", "(无)"),
        "",
        "【学员输入的 SQL】",
        state.get("sql", ""),
    ]
    if extra:
        lines += ["", extra]
    lines += [
        "",
        '输出 JSON 格式: {"syntax_valid": 布尔, "syntax_error": 字符串或null, '
        '"targets_error_point": 错误点ID或null, "fixes_error_point": 布尔, '
        '"security_issue": 布尔, "explanation": 字符串}',
        "判定规则：",
        "- syntax_valid: SQL 语法是否正确（大小写、关键字、引号等）。",
        "- targets_error_point: 从上方【待修复的错误点清单】中选出这条 SQL 意图修复的错误点 ID；"
        "若与任何错误点无关则为 null。",
        "- fixes_error_point: 这条 SQL 能否真正修复该错误点（权限是否移除、用户是否删除、密码是否修改等）。",
        "- security_issue: 这条 SQL 本身是否构成安全风险（如 SQL 注入特征、危险操作）。",
        "- explanation: 用一句中文说明判断依据。",
    ]
    return "\n".join(lines)


# ══════════════════════════════════════════
# LangGraph 图
# ══════════════════════════════════════════


class JudgeState(TypedDict, total=False):
    """LangGraph 状态：{'sql','error_points','perms_snapshot','verdict','retries_left','last_error'}"""
    sql: str
    error_points: str
    perms_snapshot: str
    verdict: Optional[Dict[str, Any]]
    retries_left: int
    last_error: str


def _judge_node(state: JudgeState) -> dict:
    """judge 节点：调用 LLM 并尝试解析结构化裁决。"""
    llm = _get_llm()
    if llm is None:
        return {"verdict": None, "last_error": "LLM 不可用", "retries_left": 0}
    try:
        resp = llm.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=_build_user_prompt(state)),
        ])
        verdict = _parse_verdict(_extract_text(resp.content))
        if verdict is None:
            return {"verdict": None, "last_error": "JSON 解析失败",
                    "retries_left": max(state.get("retries_left", 0) - 1, 0)}
        return {"verdict": verdict, "last_error": "", "retries_left": state.get("retries_left", 0)}
    except Exception as e:  # 网络/鉴权/超时
        return {"verdict": None, "last_error": f"调用异常: {e}",
                "retries_left": max(state.get("retries_left", 0) - 1, 0)}


def _reframe_node(state: JudgeState) -> dict:
    """reframe 节点：重新提示"必须输出合法 JSON"，再做一次解析（有界，不再循环）。"""
    llm = _get_llm()
    if llm is None:
        return {"verdict": None, "last_error": "LLM 不可用", "retries_left": 0}
    extra = "上一次输出未能解析为合法 JSON。请重新判定，并且必须只输出一个合法 JSON 对象，不要包含任何解释性文字。"
    try:
        resp = llm.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=_build_user_prompt(state, extra)),
        ])
        verdict = _parse_verdict(_extract_text(resp.content))
        return {"verdict": verdict, "last_error": "" if verdict else "JSON 解析失败", "retries_left": 0}
    except Exception as e:
        return {"verdict": None, "last_error": f"调用异常: {e}", "retries_left": 0}


def _route(state: JudgeState) -> str:
    if state.get("verdict") is None and state.get("retries_left", 0) > 0:
        return "reframe"
    return "end"


_graph = None
_graph_lock = threading.Lock()


def _get_graph():
    """懒加载并缓存编译后的 LangGraph 图（全局复用）。"""
    global _graph
    if _graph is None:
        if not _DEPS_OK:
            return None
        with _graph_lock:
            if _graph is None:
                g = StateGraph(JudgeState)
                g.add_node("judge", _judge_node)
                g.add_node("reframe", _reframe_node)
                g.add_edge(START, "judge")
                g.add_conditional_edges("judge", _route, {"reframe": "reframe", "end": END})
                g.add_edge("reframe", END)
                _graph = g.compile()
    return _graph


# ══════════════════════════════════════════
# 对外接口
# ══════════════════════════════════════════

def judge_sql(sql: str, error_points: str, perms_snapshot: str) -> Optional[Dict[str, Any]]:
    """
    对 SQL 进行结构化裁决。

    Args:
        sql: 学员输入的 SQL 语句
        error_points: 渲染好的待修复错误点清单文本（含错误点 ID）
        perms_snapshot: 渲染好的当前权限状态快照文本

    Returns:
        裁决 dict（syntax_valid / targets_error_point / fixes_error_point /
        security_issue / explanation）；LLM 不可用或调用失败时返回 None，调用方据此降级。
    """
    if not _DEPS_OK:
        return None
    try:
        graph = _get_graph()
        if graph is None:
            return None
        result = graph.invoke({
            "sql": sql,
            "error_points": error_points,
            "perms_snapshot": perms_snapshot,
            "verdict": None,
            "retries_left": MAX_RETRIES,
            "last_error": "",
        })
        return result.get("verdict")
    except Exception:
        return None
