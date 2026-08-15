"""
数据库安全运维智能体 - Flask Web 应用入口
所有API路由、前端页面
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Flask, request, jsonify, render_template_string, send_file, Response, stream_with_context
from flask_cors import CORS
from config.settings import get_config
from core.database_connector import DatabaseConnector
from core.agent_orchestrator import get_orchestrator, STORY_BRANCHES
from core.ui_state import ui_button_states
from core.security_monitor import get_monitor
from modules.scenario.story_engine import StoryEngine
from modules.scenario.task_manager import TaskManager
from modules.scenario.terminal_simulator import TerminalSimulator
from modules.toolkit.baseline_checker import BaselineChecker
from modules.toolkit.permission_analyzer import PermissionAnalyzer
from modules.toolkit.recovery_simulator import RecoverySimulator
from modules.report.report_generator import ReportGenerator
from utils.logger import get_logger

config = get_config(); logger = get_logger("app")
app = Flask(__name__); app.secret_key = config.SECRET_KEY; CORS(app)
db = DatabaseConnector(config); db.init_sqlite_schema()
orch = get_orchestrator(db, config); monitor = get_monitor(config)
story_engine = StoryEngine(db); task_manager = TaskManager(db)
terminal_sim = TerminalSimulator(db)
baseline_checker = BaselineChecker(config)
perm_analyzer = PermissionAnalyzer()
recovery_sim = RecoverySimulator(config)
report_gen = ReportGenerator(db, config)
logger.info("Agent 1 init OK")

# API routes
@app.route("/api/story/intro", methods=["GET"])
def get_intro():
    return jsonify(story_engine.get_story_intro())

@app.route("/api/story/decision", methods=["POST"])
def make_decision():
    data = request.get_json() or {}
    decision_id = data.get("decision_id", 0)
    student_id = data.get("student_id", 1)
    result = story_engine.process_decision(decision_id, student_id)
    # 失败状态等错误直接返回，不做分支完成度计算
    if "error" in result:
        return jsonify(result)
    try:
        state = orch.get_story_state(student_id)
        curr = state.current_branch
        bi = STORY_BRANCHES.get(curr, {})
        bt = set(bi.get("tasks", []))
        cp = set(state.completed_tasks)
        perms = getattr(terminal_sim, '_permissions', {})

        # 统一检查：所有分支任务完成时显示"安全检查通过"
        is_done = bt and bt.issubset(cp)
        result["branch_complete"] = is_done
        if is_done:
            result["alert"] = {"title": "安全状态（实时）", "message": "安全检查通过！所有任务已完成，可继续下一阶段。", "severity": "low"}
        elif curr in ("start", "baseline"):
            # 基线分支动态检测权限问题
            issues = []
            if "''@localhost" in perms: issues.append("存在匿名用户")
            if "root@%" in perms: issues.append("root允许远程登录")
            for k, v in perms.items():
                p = v.get("global_privs", []); r = v.get("role", "")
                if ("DELETE" in p or "DROP" in p) and r in ("测试账号", "开发账号"): issues.append(f"{k}过度授权")
                if "FILE" in p and r not in ("管理员",): issues.append(f"{k}拥有FILE权限")
            if issues:
                result["alert"] = {"title": "安全告警（实时）", "message": f"检测到 {len(issues)} 个未修复问题: {'; '.join(issues[:5])}", "severity": "high"}
            else:
                result["alert"] = {"title": "安全状态（实时）", "message": "安全检查通过！请确认所有分支任务是否已完成。", "severity": "low"}

        if is_done:
            result["branch_title"] = bi.get("title", curr)
            if "success_next" in bi:
                nb = STORY_BRANCHES.get(bi["success_next"], {})
                result["next_branch"] = {"title": nb.get("title", "完成"), "description": nb.get("description", "")[:100], "tasks": nb.get("tasks", [])}
            else:
                result["next_branch"] = {"title": "完成", "description": "所有故事线已完成！"}
    except Exception:
        result["branch_complete"] = False
    return jsonify(result)

@app.route("/api/story/status", methods=["GET"])
def get_story_status():
    student_id = request.args.get("student_id", 1, type=int)
    result = orch.get_current_branch_info(student_id)
    # 按钮可用性矩阵: 由阶段派生, 前端按 data-ui 分组渲染 (见 core/ui_state.py)
    result["buttons"] = ui_button_states(result.get("phase", ""))
    # 失败状态时附加失败详情
    if result.get("phase") == "failed":
        result["failure_info"] = {
            "title": "运维事故升级",
            "message": (
                "核心交易系统停机超过30分钟，造成重大声誉损失。\n"
                "学员需回滚操作并重新接受培训。\n"
                "点击「重置故事线」可重新开始挑战。"
            ),
        }
    return jsonify(result)

@app.route("/api/story/advance", methods=["POST"])
def advance_story():
    return jsonify(story_engine.advance_branch(request.get_json().get("student_id", 1)))

@app.route("/api/story/completed-fixes", methods=["GET"])
def get_completed_fixes():
    """获取已完成的任务修复点列表（供前端浮动面板展示）"""
    student_id = request.args.get("student_id", 1, type=int)
    task_names = {
        "fix_root_remote": "禁止root远程登录",
        "fix_anonymous": "删除匿名用户",
        "fix_testuser_revoke": "撤销测试账号过度授权",
        "fix_devuser_revoke": "撤销开发账号过度授权",
        "fix_appuser_revoke": "撤销应用账号过度授权",
        "restore_full_backup": "全量备份恢复",
        "apply_binlog_pitr": "Binlog时间点恢复",
        "verify_data_integrity": "数据完整性校验",
        "analyze_slow_query_log": "分析慢查询日志",
        "fix_vulnerable_code": "修复SQL注入代码",
        "configure_waf": "配置WAF规则",
    }
    try:
        state = orch.get_story_state(student_id)
        completed_ids = state.completed_tasks if hasattr(state, 'completed_tasks') else []
    except Exception:
        completed_ids = []
    task_list = []
    for tid in completed_ids:
        name = task_names.get(tid, tid)
        task_list.append({"task_id": tid, "name": name, "type": "task", "status": "completed"})
    perms = getattr(terminal_sim, '_permissions', {})
    try:
        data_for_vulns = {
            "tasks": [{"task_id": tid, "status": "completed"} for tid in completed_ids],
            "terminal_state": {"permissions": perms},
        }
        all_vulns = report_gen._get_vulnerability_list(data_for_vulns)
    except Exception:
        all_vulns = []
    fixed_vulns, unfixed_vulns = [], []
    for v in all_vulns:
        item = {
            "name": v.get("vuln_type", ""), "endpoint": v.get("endpoint", ""),
            "severity": v.get("severity", "info"), "is_fixed": v.get("is_fixed", 0),
            "fixed_method": v.get("fixed_method", ""), "type": "vulnerability",
        }
        if v.get("is_fixed"): fixed_vulns.append(item)
        else: unfixed_vulns.append(item)
    return jsonify({
        "completed_tasks": task_list, "fixed_vulnerabilities": fixed_vulns,
        "unfixed_vulnerabilities": unfixed_vulns,
        "total_fixed": len(task_list) + len(fixed_vulns), "total_unfixed": len(unfixed_vulns),
    })

@app.route("/api/terminal/execute", methods=["POST"])
def execute_terminal():
    """执行终端命令（NDJSON 流式响应）

    先按 ADR-0001 D4 门槛（变更类命令 + 有待修复项）预检；若会触发 LLM 判定，
    在调用 execute **之前**先推送一条 hint 事件（"正在分析中..."），完成后推送 result。
    只读命令/无待修复项不触发 LLM，不推送 hint，避免假提示。

    注意: hint 必须先于 execute 刷出（预检在 execute 调用前 yield），否则 hint 与 result
    同批到达，前端同帧加删不渲染（ADR-0003 的历史 bug）。
    """
    d = request.get_json() or {}
    command = d.get("command", "")
    student_id = d.get("student_id", 1)

    def gen():
        if terminal_sim.will_trigger_llm(command):
            yield json.dumps({"type": "hint", "message": "正在分析中..."}, ensure_ascii=False) + "\n"
        try:
            out = terminal_sim.execute(command, student_id)
            ev = {"type": "result",
                  "output": out.get("output", ""),
                  "prompt": out.get("prompt", "")}
        except Exception as e:
            ev = {"type": "error", "message": str(e)}
        yield json.dumps(ev, ensure_ascii=False) + "\n"

    return Response(stream_with_context(gen()), mimetype="application/x-ndjson")

@app.route("/api/terminal/reset", methods=["POST"])
def reset_terminal():
    terminal_sim.reset(); return jsonify({"success": True})

@app.route("/api/toolkit/baseline/run", methods=["POST"])
def run_baseline():
    """运行基线检查（不再单独作为任务跟踪）"""
    import json as _json
    return _json.jsonify(baseline_checker.run_all_checks())

@app.route("/api/toolkit/perm-analyze", methods=["GET"])
def analyze_permissions():
    """权限分析（基于当前终端状态）"""
    perms = getattr(terminal_sim, '_permissions', {})
    users, issues = [], []
    for key, info in perms.items():
        u, h = (key.split("@") + ["%"])[:2] if "@" in key else [key, "%"]
        role = info.get("role", "自定义")
        gp = info.get("global_privs", [])
        iu = []
        if "DELETE" in gp and role in ("测试账号", "开发账号", "应用账号"): iu.append({"issue_type":"excessive_priv","severity":"high","description":f"'{role}'用户'{u}'拥有DELETE权限","revoke_suggestion":f"REVOKE DELETE ON *.* FROM '{u}'@'{h}';"})
        if "DROP" in gp and role in ("测试账号", "开发账号", "应用账号"): iu.append({"issue_type":"excessive_priv","severity":"high","description":f"'{role}'用户'{u}'拥有DROP权限","revoke_suggestion":f"REVOKE DROP ON *.* FROM '{u}'@'{h}';"})
        if "FILE" in gp and role not in ("管理员",): iu.append({"issue_type":"excessive_priv","severity":"high","description":f"用户'{u}'拥有FILE权限","revoke_suggestion":f"REVOKE FILE ON *.* FROM '{u}'@'{h}';"})
        if "ALL PRIVILEGES" in gp and role not in ("管理员",): iu.append({"issue_type":"excessive_priv","severity":"critical","description":f"非管理员'{u}'拥有ALL PRIVILEGES","revoke_suggestion":f"REVOKE ALL ON *.* FROM '{u}'@'{h}';"})
        if h == "%" and role in ("测试账号", "开发账号"): iu.append({"issue_type":"wrong_host","severity":"medium","description":f"'{role}'用户'{u}'允许任意IP访问","revoke_suggestion":"限制IP范围"})
        if u == "root" and h == "%": iu.append({"issue_type":"wrong_host","severity":"critical","description":"root允许远程登录","revoke_suggestion":"DELETE FROM mysql.user WHERE user='root' AND host='%';"})
        if key == "''@localhost": iu.append({"issue_type":"anonymous_user","severity":"high","description":"存在匿名用户(''@localhost)，建议立即删除","revoke_suggestion":"DROP USER ''@'localhost';"})
        users.append({"user":u,"host":h,"role":role,"global_privileges":gp,"is_active":True})
        issues.extend(iu)
    c = sum(1 for i in issues if i["severity"]=="critical")
    h = sum(1 for i in issues if i["severity"]=="high")
    m = sum(1 for i in issues if i["severity"]=="medium")
    l = sum(1 for i in issues if i["severity"]=="low")
    return jsonify({"summary":{"total_users":len(users),"total_issues":len(issues),"critical_count":c,"high_count":h,"medium_count":m,"low_count":l},"users":users,"issues":issues,"recommendations":["撤销非管理员的全局DELETE/DROP/FILE权限","禁止root远程登录","限制测试/开发账号的访问IP范围","删除匿名用户"] if issues else ["当前无权限问题"],"hints":["[信息] SSL已启用，无需额外配置 (have_ssl=YES)","[提示] 默认端口3306可在my.cnf中修改为非默认端口","[高危] 存在匿名用户(''@localhost)，建议执行 DROP USER ''@'localhost' 删除"]})

@app.route("/api/toolkit/recovery/execute", methods=["POST"])
def execute_recovery():
    d = request.get_json() or {}
    return jsonify(recovery_sim.execute_command(d.get("command", ""), d.get("student_id", 1)))

@app.route("/api/report/generate", methods=["POST"])
def generate_report():
    d = request.get_json() or {}
    perms = getattr(terminal_sim, '_permissions', {})
    db_changes = []
    try:
        rows = db.execute_sqlite("SELECT * FROM permission_changes WHERE student_id = ? ORDER BY changed_at", (d.get("student_id", 1),))
        db_changes = [dict(r) for r in rows]
    except Exception:
        pass
    ts = {"permissions": perms, "db_changes": db_changes}
    return jsonify(report_gen.export_report(d.get("student_id", 1), d.get("format", "html"), ts))


@app.route("/api/report/download", methods=["POST"])
def download_report():
    """生成报告并直接以文件流方式下载"""
    d = request.get_json() or {}
    fmt = d.get("format", "html")
    student_id = d.get("student_id", 1)
    perms = getattr(terminal_sim, '_permissions', {})
    db_changes = []
    try:
        rows = db.execute_sqlite("SELECT * FROM permission_changes WHERE student_id = ? ORDER BY changed_at", (student_id,))
        db_changes = [dict(r) for r in rows]
    except Exception:
        pass
    ts = {"permissions": perms, "db_changes": db_changes}
    result = report_gen.export_report(student_id, fmt, ts)
    if not result.get("success"):
        return jsonify(result), 500
    mimetypes = {"html": "text/html", "text": "text/plain", "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
    return send_file(result["filepath"], as_attachment=True, download_name=result["filename"],
                     mimetype=mimetypes.get(fmt, "application/octet-stream"))
    return jsonify(report_gen.export_report(d.get("student_id", 1), d.get("format", "html"), ts))

@app.route("/api/system/reset", methods=["POST"])
def reset_system():
    try:
        for t in ["command_history","task_records","vulnerability_records","permission_changes","baseline_results","audit_logs"]: db.execute_sqlite(f"DELETE FROM {t}")
        db.execute_sqlite("DELETE FROM student_state")
        terminal_sim.reset()
        orch._init_student(1)
        return jsonify({"success": True, "message": "故事线已重置"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/system/help", methods=["GET"])
def get_system_help():
    return jsonify({
        "overview": {"title": "数据库安全运维实训", "mission": "30分钟内完成安全体检、漏洞修复与数据恢复", "roles": ["DBA", "数据安全审计员"]},
        "branches": [
            {"id":1,"title":"安全基线扫描与权限管控","problem":"发现弱口令账号及过度授权的测试账号","objectives":["运行基线检查","修复弱口令(ALTER USER)","撤销过度授权(REVOKE)","删除匿名用户(DROP USER '')"],"key_sql":["SHOW GRANTS FOR 'test_user'@'%';","REVOKE DELETE,DROP ON *.* FROM 'user'@'host';","ALTER USER 'user'@'host' IDENTIFIED BY '新密码';","DROP USER ''@'localhost';"],"analysis":"遵循最小权限原则，每个用户只拥有完成工作所必需的最小权限。"},
            {"id":2,"title":"数据库备份恢复(PITR)","problem":"误操作导致1500条交易流水丢失","objectives":["确认全量备份文件","使用XtraBackup准备备份","使用mysqlbinlog实现时间点恢复","校验数据完整性"],"key_sql":["xtrabackup --prepare --apply-log-only --target-dir=/backup/full/","xtrabackup --copy-back --target-dir=/backup/full/ --datadir=/var/lib/mysql/","mysqlbinlog --stop-datetime='2024-01-17 17:53:21' /backup/binlog/mysql-bin.000012"],"analysis":"PITR利用全量备份+Binlog增量恢复到误操作前的任意时间点。"},
            {"id":3,"title":"SQL注入攻防","problem":"WAF检测到针对老旧接口的SQL注入攻击","objectives":["分析慢查询日志(cat /var/log/mysql/slow_query.log)","修复后端代码(参数化查询: edit /app/api/user/profile.py)","配置WAF规则(SecRule指令)"],"key_sql":["cat /var/log/mysql/slow_query.log","edit /app/api/user/profile.py","将 f-string 拼接改为 ? 占位符","SecRule ARGS \\\"(?:union(?:.+?)select)\\\" \\\"phase:2,deny,status:403\\\""],"analysis":"永远不要信任用户输入，始终使用参数化查询或预编译语句。"}
        ],
        "common_syntax": [
            {"cmd":"SHOW GRANTS FOR 'user'@'host'","desc":"查看用户权限"},{"cmd":"REVOKE priv ON *.* FROM 'user'@'host'","desc":"撤销全局权限"},
            {"cmd":"GRANT priv ON db.* TO 'user'@'host'","desc":"授予权限"},{"cmd":"ALTER USER 'u'@'h' IDENTIFIED BY 'pwd'","desc":"修改密码"},
            {"cmd":"DROP USER 'u'@'h'","desc":"删除用户"},{"cmd":"cat /path/to/file","desc":"查看文件内容"},
            {"cmd":"edit /path/to/file","desc":"编辑文件"},{"cmd":"mysqlbinlog ...","desc":"解析二进制日志"}
        ]
    })

@app.route("/")
def index():
    return render_template_string("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>数据库安全运维智能体</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body,html{height:100%;font-family:Microsoft YaHei,sans-serif;background:#0a0e27;color:#e0e0e0;overflow:hidden}
.app{display:flex;height:100vh}
.sidebar{width:280px;min-width:280px;background:linear-gradient(180deg,#0f1438,#141a3a);border-right:1px solid #2a3070;display:flex;flex-direction:column;overflow-y:auto}
.sidebar-header{padding:18px 16px;background:linear-gradient(135deg,#1a237e,#283593);text-align:center;border-bottom:1px solid #3a4090}
.sidebar-header h1{color:#fff;font-size:18px}
.sidebar-header p{color:#aeb6d8;font-size:11px}
.sidebar-section{padding:12px 14px;border-bottom:1px solid #1e2450}
.sidebar-section h3{color:#7c8cf0;font-size:13px;margin-bottom:10px}
.menu-btn{display:block;width:100%;padding:9px 12px;margin-bottom:6px;border:1px solid transparent;border-radius:6px;cursor:pointer;font-size:13px;text-align:left;transition:all .2s;background:#1a2050;color:#c0c8f0}
.menu-btn:hover{background:#2830a0;border-color:#4a50c0}
.sidebar-header h1,.sidebar-header p,.sidebar-section h3,.menu-btn{font-family:Microsoft YaHei,sans-serif}
.main{flex:1;display:flex;flex-direction:column;padding:16px 20px;overflow:hidden}
.story-bar{background:linear-gradient(135deg,#141a3a,#1a2050);border:1px solid #2a3070;border-radius:8px;padding:12px 16px;margin-bottom:12px;display:flex;align-items:center;flex-shrink:0}
.phase-badge{background:#3f51b5;color:#fff;font-size:11px;padding:3px 10px;border-radius:12px;white-space:nowrap}
.story-text{flex:1;font-size:13px;color:#b0b8e0;margin-left:14px}
.progress-wrap{display:flex;align-items:center;gap:10px;flex-shrink:0;margin-bottom:10px}
.progress-track{flex:1;height:6px;background:#1a2050;border-radius:3px;overflow:hidden}
.progress-fill{height:100%;width:0%;background:linear-gradient(90deg,#4caf50,#8bc34a);border-radius:3px;transition:width .5s ease}
.progress-label{font-size:12px;color:#8888bb;min-width:100px;text-align:right}
.terminal-wrap{flex:1;display:flex;flex-direction:column;background:#000c1a;border:1px solid #1a3060;border-radius:8px;overflow:hidden;min-height:0}
.terminal-header{background:#0a1a30;padding:6px 14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #1a3060;flex-shrink:0}
.terminal-dot{width:10px;height:10px;border-radius:50%}
.terminal-dot.red{background:#f44336}
.terminal-dot.yellow{background:#ff9800}
.terminal-dot.green{background:#4caf50}
.terminal-title{color:#5588bb;font-size:12px}
.terminal-body{flex:1;overflow-y:auto;padding:14px;font-family:Courier New,monospace;font-size:14px;line-height:1.5;color:#00e000;white-space:pre-wrap;word-break:break-all}
.terminal-input-row{display:flex;border-top:1px solid #1a3060;flex-shrink:0}
.terminal-prompt{background:#000c1a;color:#00e000;padding:10px 12px;font-family:Courier New,monospace;font-size:14px;border:none;flex-shrink:0}
.terminal-input-row input{flex:1;background:#000c1a;color:#00e000;padding:10px 12px 10px 0;font-family:Courier New,monospace;font-size:14px;border:none;outline:none}
.output-panel{position:fixed;right:20px;top:80px;width:380px;max-height:120px;background:#0f1438;border:1px solid #2a3070;border-radius:8px;padding:14px;overflow-y:auto;font-size:12px;line-height:1.6;z-index:100;display:none;box-shadow:0 4px 20px rgba(0,0,0,.5)}
.output-panel.show{display:block}

/* 浮动按钮 */
.floating-btn{position:fixed;bottom:100px;right:30px;width:56px;height:56px;border-radius:50%;background:linear-gradient(135deg,#3f51b5,#5c6bc0);color:#fff;border:2px solid #5c6bc0;cursor:grab;z-index:1000;font-size:26px;box-shadow:0 4px 15px rgba(63,81,181,.5);display:flex;align-items:center;justify-content:center;transition:transform .2s,box-shadow .2s;user-select:none}
.floating-btn:hover{transform:scale(1.1);box-shadow:0 6px 20px rgba(63,81,181,.7)}
.floating-btn:active{cursor:grabbing}
.floating-tooltip{position:fixed;right:96px;bottom:116px;background:rgba(15,20,56,.95);color:#c0c8f0;padding:7px 14px;border-radius:6px;font-size:12px;white-space:nowrap;pointer-events:none;opacity:0;transition:opacity .25s;z-index:999;border:1px solid #2a3070}
.floating-btn:hover+.floating-tooltip{opacity:1}
.drawer-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.55);z-index:999;display:none}
.drawer-overlay.show{display:block}
.drawer{position:fixed;top:0;right:-420px;width:400px;height:100vh;background:#0f1438;border-left:1px solid #2a3070;z-index:1001;transition:right .3s ease;display:flex;flex-direction:column;box-shadow:-4px 0 20px rgba(0,0,0,.5)}
.drawer.show{right:0}
.drawer-header{padding:16px 20px;background:linear-gradient(135deg,#1a237e,#283593);display:flex;justify-content:space-between;align-items:center;flex-shrink:0}
.drawer-header h2{color:#fff;font-size:15px;margin:0}
.drawer-close{background:none;border:none;color:#aeb6d8;font-size:18px;cursor:pointer;padding:4px 8px;border-radius:4px}
.drawer-close:hover{color:#fff;background:rgba(255,255,255,.1)}
.drawer-body{flex:1;overflow-y:auto;padding:14px 18px}
.drawer-section-title{color:#7c8cf0;font-size:12px;margin:12px 0 8px;padding-bottom:4px;border-bottom:1px solid #2a3070}
.fix-item{padding:10px 12px;margin-bottom:7px;background:#1a2050;border-radius:6px;border:1px solid #2a3070}
.fix-item .fix-name{color:#e0e0e0;font-size:13px;font-weight:500}
.fix-item .fix-status{font-size:11px;margin-top:3px}
.fix-item .fix-time{color:#666;font-size:10px;margin-top:2px}
.sev-critical{color:#f44336}
.sev-high{color:#ff9800}
.sev-medium{color:#ffeb3b}
.sev-info{color:#4caf50}
.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.65);z-index:2000;display:none;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal-box{background:#0f1438;border:1px solid #2a3070;border-radius:12px;padding:30px 36px;text-align:center;box-shadow:0 8px 30px rgba(0,0,0,.6);max-width:420px;width:90%}
.modal-box h3{color:#e0e0e0;font-size:18px;margin:0 0 6px}
.modal-box p{color:#8888bb;font-size:13px;margin:0 0 22px}
.modal-buttons{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.modal-btn{padding:12px 24px;border-radius:8px;border:1px solid transparent;cursor:pointer;font-size:14px;font-weight:500;transition:all .2s;min-width:100px}
.modal-btn:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.3)}
.modal-btn.docx{background:#2e7d32;color:#fff;border-color:#4caf50}
.modal-btn.docx:hover{background:#388e3c}
.modal-btn.html{background:#1565c0;color:#fff;border-color:#1976d2}
.modal-btn.html:hover{background:#1976d2}
.modal-btn.text{background:#6a1b9a;color:#fff;border-color:#8e24aa}
.modal-btn.text:hover{background:#7b1fa2}
.modal-cancel{background:none;border:1px solid #444;color:#888;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:12px;margin-top:14px;transition:all .2s}
.modal-cancel:hover{color:#ccc;border-color:#666}

</style>
</head>
<body>
<div class="app">
<div class="sidebar">
<div class="sidebar-header"><h1>安全运维智能体</h1><p>银行核心数据库 · 实战实训</p></div>
<div class="sidebar-section"><h3>故事线决策</h3>
<button class="menu-btn menu-btn-primary" data-ui="decision" onclick="makeDecision(1)">基线扫描与权限管控</button>
<button class="menu-btn menu-btn-warning" data-ui="decision" onclick="makeDecision(2)">数据库备份恢复</button>
<button class="menu-btn menu-btn-danger" data-ui="decision" onclick="makeDecision(3)">SQL注入攻防</button></div>
<div class="sidebar-section"><h3>运维工具箱</h3>

<button class="menu-btn menu-btn-info" data-ui="perm_analyze" onclick="analyzePerm()">权限分析</button>
<button class="menu-btn menu-btn-warning" data-ui="report" onclick="genReport()">生成审计报告</button></div>
<div class="sidebar-section"><h3>系统控制</h3>
<button class="menu-btn menu-btn-info" onclick="showHelpPanel()">题目解析与语法</button>
<button class="menu-btn" onclick="showTerminalHelp()">教学指南</button>
<button class="menu-btn menu-btn-danger" data-ui="reset" onclick="resetStory()">重置故事线</button></div>
</div>
<div class="main">
<div class="story-bar" id="storyBar"><span class="phase-badge" id="phaseBadge">待开始</span><span class="story-text" id="storyText">欢迎！请先选择故事线决策分支。</span></div>
<div class="progress-wrap"><div class="progress-track"><div class="progress-fill" id="progressFill"></div></div><span class="progress-label" id="progressLabel">进度 0% </span></div>
<div class="terminal-wrap">
<div class="terminal-header"><span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span><span class="terminal-title">安全运维终端</span></div>
<div class="terminal-body" id="terminalBody"><span>安全运维终端 模拟环境</span><span>输入 help 查看命令</span></div>
<div class="terminal-input-row"><span class="terminal-prompt" id="termPrompt">$</span><input id="cmdInput" type="text" placeholder="输入命令..." autofocus onkeydown="if(event.key==='Enter')executeCmd()"></div>
</div></div></div>
<div class="output-panel" id="outputPanel"><button class="close-panel" style="float:right;cursor:pointer;color:#666;background:none;border:none" onclick="this.parentElement.classList.remove('show')">x</button><div id="outputContent"><strong>结果</strong></div></div>
<script>
var studentId=1;
var currentBranch='start';
document.addEventListener('DOMContentLoaded',function(){loadStoryStatus();});
function loadStoryStatus(){fetch('/api/story/status?student_id='+studentId).then(function(r){return r.json();}).then(function(d){updateUI(d);var tb=document.getElementById('terminalBody');tb.innerHTML+='<span>系统就绪，等待你的决策...</span>\\n';});}
function updateUI(d){var pm={'intro':'故事开始','in_progress':'进行中','completed':'已完成','failed':'🚨事故'};var pb=document.getElementById('phaseBadge');pb.textContent=pm[d.phase]||d.phase||'等待';var st=document.getElementById('storyText');var sb=document.getElementById('storyBar');if(d.phase==='failed'){pb.style.background='#d32f2f';sb.style.background='linear-gradient(135deg,#3e0000,#5c0000)';sb.style.borderColor='#d32f2f';var fi=d.failure_info||{};st.innerHTML='<span style="color:#ff6b6b;font-weight:bold">🚨 '+fi.title+'</span><br><span style="color:#ffcccc">'+fi.message+'</span>';}else{pb.style.background='';sb.style.background='';sb.style.borderColor='';if(d.branch_info&&d.branch_info.description){st.innerHTML=d.branch_info.description;}}var allTasks=["fix_root_remote","fix_anonymous","fix_testuser_revoke","fix_devuser_revoke","fix_appuser_revoke","restore_full_backup","apply_binlog_pitr","verify_data_integrity","analyze_slow_query_log","fix_vulnerable_code","configure_waf"];var total=allTasks.length;var done=0;for(var i=0;i<total;i++){if((d.completed_tasks||[]).indexOf(allTasks[i])>=0){done++;}}var pct=Math.round(done/total*100);document.getElementById('progressFill').style.width=pct+'%';document.getElementById('progressLabel').textContent=pct+'% | '+done+'/'+total;currentBranch=d.branch||'start';applyButtonStates(d.buttons);}
function applyButtonStates(bt){if(!bt){return;}setBtnGroup('decision',bt.decision);setBtnGroup('reset',bt.reset);setBtnGroup('perm_analyze',bt.perm_analyze);setBtnGroup('report',bt.report);}
function setBtnGroup(group,on){var b=document.querySelectorAll('[data-ui="'+group+'"]');for(var i=0;i<b.length;i++){b[i].disabled=!on;b[i].style.opacity=on?'1':'0.4';b[i].style.cursor=on?'pointer':'not-allowed';}}
function refreshStatus(){fetch('/api/story/status?student_id='+studentId).then(function(r){return r.json();}).then(function(d){updateUI(d);});}
function makeDecision(id){var tb=document.getElementById('terminalBody');if(currentBranch==='failed'){tb.innerHTML+='<span style="color:#ff6b6b">\\n🚨 已处于失败状态，请点击「重置故事线」重新开始。</span>\\n';showOutput('error','失败状态下不可选择决策');return;}tb.innerHTML+='<span>\\n🔴提交决策 '+id+'...</span>\\n';tb.scrollTop=tb.scrollHeight;fetch('/api/story/decision',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({decision_id:id,student_id:studentId})}).then(function(r){return r.json();}).then(function(d){if(d.error){tb.innerHTML+='<span>'+d.error+'</span>\\n';showOutput('error',d.error);return;}var st=d.story_progress||d.story_text||(d.branch_info?d.branch_info.description:'')||'';var al=d.alert||{};tb.innerHTML+='<span>\\n ### 决策已确认 ### </span>\\n';if(st){tb.innerHTML+='<span>'+st+'</span>\\n';}if(al.message){var sc='#ff9800';if(al.severity==='critical'){sc='#f44336';}else if(al.severity==='low'){sc='#4caf50';}tb.innerHTML+='<span style=\\"color:'+sc+'\\">['+(al.title||'告警')+'] '+al.message+'</span>\\n';}if(d.branch_info&&d.branch_info.tasks){tb.innerHTML+='<span>待完成任务:</span>\\n';d.branch_info.tasks.forEach(function(x){tb.innerHTML+='  - '+x+'\\n';});}if(d.branch_complete){tb.innerHTML+='<span>\\n[安全状态(实时)] 安全检查通过! 请确认所有分支任务是否已完成.</span>\\n';if(d.next_branch){tb.innerHTML+='<span>下一阶段: '+d.next_branch.title+'</span>\\n';if(d.next_branch.tasks){tb.innerHTML+='<span>新任务:</span>\\n';d.next_branch.tasks.forEach(function(x){tb.innerHTML+='  - '+x+'\\n';});}}showOutput('success','分支全部修复成功!');}tb.scrollTop=tb.scrollHeight;refreshStatus();});}
function executeCmd(){var inp=document.getElementById('cmdInput');var tb=document.getElementById('terminalBody');var pr=document.getElementById('termPrompt');var cmd=inp.value.trim();if(!cmd){return;}var NL=String.fromCharCode(10);if(cmd.toLowerCase()==='clear'){tb.innerHTML='';inp.value='';return;}if(cmd.toLowerCase()==='help'){tb.innerHTML+='<span>$ '+cmd+'</span>'+NL;tb.innerHTML+='<span>命令: story, decision N, mysql, ls, cd, cat, run_baseline_check, show grants, generate_report, clear, exit</span>'+NL;inp.value='';tb.scrollTop=tb.scrollHeight;return;}tb.innerHTML+='<span>$ '+cmd+'</span>'+NL;inp.value='';tb.scrollTop=tb.scrollHeight;fetch('/api/terminal/execute',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command:cmd,student_id:studentId})}).then(function(r){return consumeTerminalStream(r,tb,pr);}).catch(function(e){tb.innerHTML+='<span>错误: '+e.message+'</span>'+NL;});}
function consumeTerminalStream(r,tb,pr){var NL=String.fromCharCode(10);if(!r.ok){return r.text().then(function(t){tb.innerHTML+='<span>错误: HTTP '+r.status+'</span>'+NL;tb.scrollTop=tb.scrollHeight;});}var reader=r.body.getReader();var dec=new TextDecoder();var buf='';var hint=null;function clearHint(){if(hint&&hint.parentNode){hint.parentNode.removeChild(hint);}hint=null;}function handle(ev){if(ev.type==='hint'){if(!hint){hint=document.createElement('span');hint.style.color='#ffb74d';hint.textContent='⏳ '+ev.message;tb.appendChild(hint);tb.appendChild(document.createElement('br'));tb.scrollTop=tb.scrollHeight;}}else if(ev.type==='result'){clearHint();tb.innerHTML+=(ev.output||'(无输出)')+NL;pr.textContent=ev.prompt||pr.textContent;tb.scrollTop=tb.scrollHeight;refreshStatus();}else if(ev.type==='error'){clearHint();tb.innerHTML+='<span>错误: '+ev.message+'</span>'+NL;tb.scrollTop=tb.scrollHeight;}}function pump(){return reader.read().then(function(res){if(res.done){clearHint();return;}buf+=dec.decode(res.value,{stream:true});var ls=buf.split(NL);buf=ls.pop();for(var i=0;i<ls.length;i++){var line=ls[i].trim();if(!line){continue;}try{handle(JSON.parse(line));}catch(e){}}return pump();});}return pump();}

function analyzePerm(){var tb=document.getElementById('terminalBody');tb.innerHTML+='<span>\\n🟠权限分析中...</span>\\n';fetch('/api/toolkit/perm-analyze').then(function(r){return r.json();}).then(function(d){var s=d.summary||{};tb.innerHTML+='<span>\\n ### 权限分析完成 ### </span>\\n';var lowStr=s.low_count>0?', 低危: '+s.low_count:'';tb.innerHTML+='<span>发现问题: '+s.total_issues+' 个 (严重: '+s.critical_count+', 高危: '+s.high_count+', 中危: '+s.medium_count+lowStr+')</span>\\n';

if(d.issues&&d.issues.length>0){var il='';d.issues.forEach(function(x){var ic='[中危]';if(x.severity==='critical'){ic='[严重]';}else if(x.severity==='high'){ic='[高危]';}il+=ic+' - '+(x.description||'').slice(0,60)+'\\n';});tb.innerHTML+='<span>问题列表:</span>\\n'+il;}if(d.hints&&d.hints.length>0){tb.innerHTML+='<span>\\n提示信息:</span>\\n';d.hints.forEach(function(h){tb.innerHTML+='  '+h+'\\n';});}tb.scrollTop=tb.scrollHeight;showOutput('success','权限分析完成');});}

function genReport(){document.getElementById('reportModal').classList.add('show');}
function showHelpPanel(){
var tb=document.getElementById('terminalBody');
tb.innerHTML+='<span>\\n🔵加载题目解析...</span>\\n';
fetch('/api/system/help').then(function(r){return r.json();}).then(function(d){tb.innerHTML+='<span>\\n ### 题目解析与语法 ### </span>\\n';
tb.innerHTML+='<span>任务: '+d.overview.mission+'</span>\\n';d.branches.forEach(function(b){tb.innerHTML+='<span>\\n=== '+b.id+': '+b.title+' ===</span>\\n';tb.innerHTML+='<span>问题: '+b.problem+'</span>\\n';b.objectives.forEach(function(o){tb.innerHTML+='  - '+o+'\\n';});tb.innerHTML+='<span>分析: '+b.analysis+'</span>\\n';tb.innerHTML+='<span>关键SQL:</span>\\n';b.key_sql.forEach(function(s){tb.innerHTML+='  '+s+'\\n';});});tb.innerHTML+='<span>\\n### 通用语法:</span>\\n';d.common_syntax.forEach(function(s){tb.innerHTML+='  '+s.cmd+' -> '+s.desc+'\\n';});tb.scrollTop=tb.scrollHeight;showOutput('success','题目解析已加载');});}
function showTerminalHelp(){var tb=document.getElementById('terminalBody');tb.innerHTML+='<span>\\n⚪教学指南: \\n点击故事线决策 -> 终端执行命令 -> 工具箱辅助 -> 生成报告</span>\\n';tb.scrollTop=tb.scrollHeight;showOutput('success','教学指南已显示');}
function resetStory(){if(!confirm('确定重置所有进度?')){return;}var tb=document.getElementById('terminalBody');tb.innerHTML='<span>重置中...</span>\\n';fetch('/api/system/reset',{method:'POST'}).then(function(r){return r.json();}).then(function(d){if(d.success){tb.innerHTML='<span>已重置</span>\\n';refreshStatus();showOutput('success','已重置');}else{tb.innerHTML+='<span>失败: '+d.error+'</span>\\n';}tb.scrollTop=tb.scrollHeight;});}
function showOutput(type,msg){var p=document.getElementById('outputPanel');var c=document.getElementById('outputContent');var icons={success:'OK',error:'X',info:'i'};c.innerHTML='<span>'+(icons[type]||'')+' '+msg+'</span>';p.classList.add('show');setTimeout(function(){p.classList.remove('show');},2500);}

// 切换抽屉面板
function toggleDrawer(){var d=document.getElementById('fixDrawer');var o=document.getElementById('drawerOverlay');d.classList.toggle('show');o.classList.toggle('show');if(d.classList.contains('show')){loadCompletedFixes();if(window.fixDrawerTimer)clearInterval(window.fixDrawerTimer);window.fixDrawerTimer=setInterval(loadCompletedFixes,3000);}else{if(window.fixDrawerTimer){clearInterval(window.fixDrawerTimer);window.fixDrawerTimer=null;}}}
// 加载已完成修复点
function loadCompletedFixes(){var b=document.getElementById('drawerBody');b.innerHTML='<div style=\"text-align:center;color:#666;padding:40px;font-size:13px\">加载中...</div>';fetch('/api/story/completed-fixes?student_id='+studentId).then(function(r){return r.json();}).then(function(d){var h='';if(d.completed_tasks&&d.completed_tasks.length){h+='<div class=\"drawer-section-title\">已完成故事线任务 ('+d.completed_tasks.length+')</div>';d.completed_tasks.forEach(function(t){h+='<div class=\"fix-item\"><div class=\"fix-name\">'+t.name+'</div><div class=\"fix-status\" style=\"color:#4caf50\">已完成</div></div>';});}else{h+='<div class=\"drawer-section-title\">已完成故事线任务</div><div style=\"color:#666;padding:12px;font-size:12px\">暂无已完成的任务</div>';}if(d.fixed_vulnerabilities&&d.fixed_vulnerabilities.length){h+='<div class=\"drawer-section-title\">已修复漏洞 ('+d.fixed_vulnerabilities.length+')</div>';d.fixed_vulnerabilities.forEach(function(v){h+='<div class=\"fix-item\"><div class=\"fix-name\">'+v.name+'</div><div class=\"fix-status\"><span class=\"sev-'+v.severity+'\">['+v.severity.toUpperCase()+']</span> '+v.endpoint+'</div></div>';});}if(d.unfixed_vulnerabilities&&d.unfixed_vulnerabilities.length){h+='<div class=\"drawer-section-title\">未修复漏洞 ('+d.unfixed_vulnerabilities.length+')</div>';d.unfixed_vulnerabilities.forEach(function(v){h+='<div class=\"fix-item\"><div class=\"fix-name\">'+v.name+'</div><div class=\"fix-status\"><span class=\"sev-'+v.severity+'\">['+v.severity.toUpperCase()+']</span> '+v.endpoint+'</div></div>';});}b.innerHTML=h;}).catch(function(e){b.innerHTML='<div style=\"text-align:center;color:#f44336;padding:40px\">加载失败: '+e.message+'</div>';});}
// 关闭报告格式弹窗
function closeReportModal(){document.getElementById('reportModal').classList.remove('show');}
// 下载报告
function downloadReport(format){closeReportModal();var fn='report.'+(format==='docx'?'docx':format);var tb=document.getElementById('terminalBody');var fmtNames={docx:'Word',html:'HTML',text:'Text'};tb.innerHTML+='<span>\\n'+fmtNames[format]+'\\u62a5\\u544a\\u4e0b\\u8f7d\\u4e2d...</span>\\n';tb.scrollTop=tb.scrollHeight;fetch('/api/report/download',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({student_id:studentId,format:format})}).then(function(r){if(!r.ok)throw new Error('\\u4e0b\\u8f7d\\u5931\\u8d25('+r.status+')');var cd=r.headers.get('Content-Disposition');if(cd){var m=cd.match(/filename[^;=\\n]*=((['"]).*?\\2|[^;\\n]*)/);if(m)fn=m[1].replace(/['"]/g,'');}return r.blob();}).then(function(blob){var url=URL.createObjectURL(blob);var a=document.createElement('a');a.href=url;a.download=fn;document.body.appendChild(a);a.click();document.body.removeChild(a);setTimeout(function(){URL.revokeObjectURL(url);},1000);tb.innerHTML+='<span>\\n### \\u62a5\\u544a\\u5df2\\u4e0b\\u8f7d: '+fn+'</span>\\n';showOutput('success','\\u62a5\\u544a\\u5df2\\u4e0b\\u8f7d');tb.scrollTop=tb.scrollHeight;}).catch(function(e){tb.innerHTML+='<span>\\u9519\\u8bef: '+e.message+'</span>\\n';showOutput('error','\\u62a5\\u544a\\u751f\\u6210\\u5931\\u8d25');tb.scrollTop=tb.scrollHeight;});}
</script>

<!-- 浮动按钮 + 拖拽 tooltip -->
<button class="floating-btn" id="floatBtn" onclick="toggleDrawer()">📋</button>
<div class="floating-tooltip">已完成故事线任务修复点</div>
<!-- 抽屉遮罩 -->
<div class="drawer-overlay" id="drawerOverlay" onclick="toggleDrawer()"></div>
<!-- 右侧抽屉面板 -->
<div class="drawer" id="fixDrawer">
  <div class="drawer-header">
    <h2>📋 已完成故事线任务修复点</h2>
    <button class="drawer-close" onclick="toggleDrawer()">X</button>
  </div>
  <div class="drawer-body" id="drawerBody">
    <div style="text-align:center;color:#666;padding:40px;font-size:13px">加载中...</div>
  </div>
</div>
<!-- 报告格式选择弹窗 -->
<div class="modal-overlay" id="reportModal">
  <div class="modal-box">
    <h3>📄 选择报告格式</h3>
    <p>请选择要导出的审计报告文件格式</p>
    <div class="modal-buttons">
      <button class="modal-btn docx" onclick="downloadReport('docx')">📄 Word</button>
      <button class="modal-btn html" onclick="downloadReport('html')">🌐 HTML</button>
      <button class="modal-btn text" onclick="downloadReport('text')">📝 Text</button>
    </div>
    <button class="modal-cancel" onclick="closeReportModal()">取消</button>
  </div>
</div>

</body></html>

""")

if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
