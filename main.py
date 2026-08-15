#!/usr/bin/env python3
"""
数据库安全运维智能体 - CLI 入口

提供命令行模式，支持：
- init: 初始化数据库
- cli: 进入交互式命令行（终端模拟）
- story: 查看故事线状态
- baseline: 运行基线检查
- report: 生成审计报告
- score: 查看综合评分
"""
import os
import sys
import json

# 将项目根目录添加到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import get_config, Config
from core.database_connector import DatabaseConnector
from core.agent_orchestrator import AgentOrchestrator, get_orchestrator
from core.security_monitor import SecurityMonitor, get_monitor

from modules.scenario.story_engine import StoryEngine
from modules.scenario.task_manager import TaskManager, PREDEFINED_TASKS
from modules.scenario.terminal_simulator import TerminalSimulator

from modules.shooting_range.vulnerable_app import VulnerableAppSimulator
from modules.shooting_range.attack_simulator import AttackSimulator
from modules.shooting_range.defense_validator import DefenseValidator

from modules.toolkit.baseline_checker import BaselineChecker
from modules.toolkit.permission_analyzer import PermissionAnalyzer
from modules.toolkit.recovery_simulator import RecoverySimulator

from modules.report.report_generator import ReportGenerator

from utils.logger import get_logger, LoggerMixin
from utils.helpers import colorize, parse_command_line


class Agent1CLI(LoggerMixin):
    """
    Agent 1 命令行交互界面

    提供完整的数据库安全运维智能体CLI操作体验。
    """

    def __init__(self):
        self.config = get_config()
        self._logger = get_logger("cli")

        # 初始化核心组件
        self.db = DatabaseConnector(self.config)
        self.db.init_sqlite_schema()

        self.orchestrator = get_orchestrator(self.db, self.config)
        self.monitor = get_monitor(self.config)

        # 初始化模块
        self.story_engine = StoryEngine(self.db)
        self.task_manager = TaskManager(self.db)
        self.terminal = TerminalSimulator(self.db)

        self.vuln_app = VulnerableAppSimulator()
        self.attack_sim = AttackSimulator(self.vuln_app)
        self.defense_val = DefenseValidator(self.vuln_app, self.attack_sim)

        self.baseline_checker = BaselineChecker(self.config)
        self.perm_analyzer = PermissionAnalyzer()
        self.recovery_sim = RecoverySimulator(self.config)

        self.report_gen = ReportGenerator(self.db, self.config)

        self.student_id = 1
        self.running = True

        self.log_info("Agent 1 初始化完成")

    # ──────────────────────────────────────────
    # 主循环
    # ──────────────────────────────────────────

    def run(self):
        """运行CLI主循环"""
        self._print_banner()
        while self.running:
            try:
                cmd = input(colorize("agent1> ", "cyan")).strip()
                if cmd:
                    self._handle_command(cmd)
            except KeyboardInterrupt:
                print("\n" + colorize("再见！", "yellow"))
                self.running = False
            except EOFError:
                print()
                self.running = False

    def _print_banner(self):
        """打印启动Banner"""
        banner = f"""
{colorize('=' * 60, 'blue')}
{colorize('  数据库安全运维智能体 (Agent 1)', 'green', bold=True)}
{colorize('  银行核心数据库安全运维实训平台', 'cyan')}
{colorize('  基于真实场景的多分支故事线', 'cyan')}
{colorize('=' * 60, 'blue')}
{colorize('  输入 help 查看可用命令', 'yellow')}
{colorize('  输入 story 开始故事线', 'yellow')}
{colorize('-' * 60, 'blue')}
"""
        print(banner)

    # ──────────────────────────────────────────
    # 命令处理
    # ──────────────────────────────────────────

    def _handle_command(self, cmd: str):
        """分发命令"""
        parsed = parse_command_line(cmd)

        # 失败状态时拦截大部分命令
        try:
            state = self.orchestrator.get_story_state(self.student_id)
            if state.story_phase == "failed":
                allowed_in_failed = {"help", "story", "status", "history", "exit", "quit"}
                if parsed["command"] not in allowed_in_failed:
                    print(f"\n{colorize('🚨 运维事故升级！系统已进入故障状态。', 'red', bold=True)}")
                    print(f"{colorize('使用 status 查看详情', 'yellow')}")
                    print(f"{colorize('使用 story 重新查看剧情', 'yellow')}")
                    return
        except Exception:
            pass

        command_map = {
            "help": self._show_help,
            "story": self._cmd_story,
            "decision": self._cmd_decision,
            "status": self._cmd_status,
            "terminal": self._cmd_terminal,
            "task": self._cmd_task,
            "baseline": self._cmd_baseline,
            "perm": self._cmd_perm,
            "recovery": self._cmd_recovery,
            "attack": self._cmd_attack,
            "fix": self._cmd_fix,
            "waf": self._cmd_waf,
            "report": self._cmd_report,
            "score": self._cmd_score,
            "history": self._cmd_history,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
        }

        handler = command_map.get(parsed["command"])
        if handler:
            handler(parsed)
        else:
            print(colorize(f"未知命令: {parsed['command']}", "red"))
            print("输入 help 查看可用命令")

    def _show_help(self, parsed=None):
        """显示帮助信息"""
        help_text = f"""
{colorize('可用命令:', 'green')}
  {colorize('story', 'yellow')}              - 查看故事开场/开始故事线
  {colorize('decision <1/2/3>', 'yellow')}   - 做出决策（1=基线扫描 2=备份恢复 3=SQL注入攻防）
  {colorize('status', 'yellow')}             - 查看当前故事状态
  {colorize('terminal', 'yellow')}           - 进入模拟终端
  {colorize('task list', 'yellow')}          - 查看任务列表
  {colorize('task start <id>', 'yellow')}    - 开始任务
  {colorize('baseline', 'yellow')}           - 运行基线安全检查
  {colorize('perm', 'yellow')}               - 分析用户权限
  {colorize('recovery <cmd>', 'yellow')}     - 执行恢复命令
  {colorize('attack <target>', 'yellow')}    - 攻击模拟
  {colorize('fix <path>', 'yellow')}         - 修复漏洞端点
  {colorize('waf <rules>', 'yellow')}        - 验证WAF规则
  {colorize('report', 'yellow')}             - 生成审计报告
  {colorize('score', 'yellow')}              - 查看综合评分
  {colorize('history', 'yellow')}            - 查看命令历史
  {colorize('exit', 'yellow')}               - 退出
"""
        print(help_text)

    # ──────────────────────────────────────────
    # 故事线命令
    # ──────────────────────────────────────────

    def _cmd_story(self, parsed=None):
        """查看故事开场"""
        intro = self.story_engine.get_story_intro()
        print(f"\n{colorize('=' * 60, 'blue')}")
        print(f"{colorize(intro['title'], 'green', bold=True)}")
        print(f"{colorize('=' * 60, 'blue')}")
        print(f"\n{colorize('背景:', 'yellow')} {intro['background']}")
        print(f"\n{colorize('可扮演角色:', 'cyan')}")
        for role in intro["roles"]:
            print(f"  • {role['name']}: {role['responsibility']}")
        print(f"\n{colorize('任务:', 'red')} {intro['mission']}")
        print(f"\n{colorize('请选择决策 (decision <1/2/3>):', 'green')}")
        for d in intro["decisions"]:
            print(f"  {colorize(f'{d["id"]}. {d["title"]}', 'yellow')}")
            print(f"     {d['description']}")

    def _cmd_decision(self, parsed):
        """处理决策"""
        args = parsed["args"]
        if not args:
            print(colorize("请指定决策ID: decision <1|2|3>", "red"))
            return

        try:
            decision_id = int(args[0])
            result = self.story_engine.process_decision(decision_id, self.student_id)
            if "error" in result:
                print(colorize(f"错误: {result['error']}", "red"))
                return

            print(f"\n{colorize('=' * 40, 'blue')}")
            print(f"{colorize('决策已确认:', 'green')} {result.get('decision', {}).get('title', '')}")

            # 显示告警弹窗
            alert = result.get("alert")
            if alert:
                sev_color = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(alert.get("severity", "medium"), "cyan")
                print(f"\n{colorize(f'⚠ {alert["title"]}', sev_color)}")
                print(f"  {alert['message']}")

            # 显示任务列表
            tasks = result.get("tasks", [])
            if tasks:
                print(f"\n{colorize('待完成任务:', 'yellow')}")
                for t in tasks:
                    task_info = PREDEFINED_TASKS.get(t)
                    if task_info:
                        print(f"  • {task_info.title} ({colorize(task_info.difficulty, 'cyan')})")

            print(f"\n{colorize('剧情推进:', 'cyan')} {result.get('story_progress', '')}")

        except ValueError:
            print(colorize("决策ID必须是数字: 1, 2, 或 3", "red"))

    def _cmd_status(self, parsed=None):
        """查看当前状态"""
        info = self.orchestrator.get_current_branch_info(self.student_id)
        print(f"\n{colorize('当前状态:', 'green')}")
        print(f"  {colorize('学员:', 'cyan')} {info['student_name']}")
        phase_color = {"intro": "cyan", "in_progress": "yellow", "completed": "green", "failed": "red"}

        if info.get("phase") == "failed":
            print(f"\n{colorize('=' * 60, 'red')}")
            print(f"{colorize('  🚨 运维事故升级！', 'red', bold=True)}")
            branch_info = info.get("branch_info", {})
            if branch_info:
                print(f"  {colorize(branch_info.get('description', '系统严重故障'), 'red')}")
            print(f"  {colorize('失败次数:', 'red')} {info['failed_count']}")
            print(f"{colorize('=' * 60, 'red')}")
            print(f"\n{colorize('💡 请使用 story 命令重新查看剧情，或重置系统。', 'yellow')}")
            return

        print(f"  {colorize('分支:', 'cyan')} {info['branch']}")
        print(f"  {colorize('评分:', 'cyan')} {info['score']}/100")
        print(f"  {colorize('失败次数:', 'cyan')} {info['failed_count']}")
        print(f"  {colorize('完成任务:', 'cyan')} {len(info['completed_tasks'])}")
        if info.get("pending_tasks"):
            print(f"  {colorize('待完成任务:', 'yellow')}")
            for t in info["pending_tasks"]:
                print(f"    • {t}")

    # ──────────────────────────────────────────
    # 终端命令
    # ──────────────────────────────────────────

    def _cmd_terminal(self, parsed=None):
        """进入模拟终端模式"""
        print(colorize("\n进入模拟终端 (输入 exit 返回主菜单)", "green"))
        print(colorize("=" * 50, "blue"))

        # 输出初始提示
        init_result = self.terminal.execute("", self.student_id)
        prompt = init_result.get("prompt", "mysql> ")

        while True:
            try:
                cmd = input(colorize(prompt, "green")).strip()
                if cmd.lower() == "exit":
                    result = self.terminal.execute("exit", self.student_id)
                    print(result["output"])
                    if "disconnected" in result["output"].lower():
                        prompt = "$ "
                    else:
                        break
                else:
                    result = self.terminal.execute(cmd, self.student_id)
                    if result["output"]:
                        print(result["output"])
                    prompt = result.get("prompt", prompt)
            except KeyboardInterrupt:
                print("\n" + colorize("返回主菜单", "yellow"))
                break

    # ──────────────────────────────────────────
    # 任务命令
    # ──────────────────────────────────────────

    def _cmd_task(self, parsed):
        """任务管理"""
        args = parsed["args"]
        if not args:
            print(colorize("用法: task list | task start <id>", "yellow"))
            return

        sub = args[0].lower()
        if sub == "list":
            tasks = self.task_manager.get_all_tasks_status(self.student_id)
            print(f"\n{colorize('任务列表:', 'green')}")
            for t in tasks:
                color = {"completed": "green", "in_progress": "yellow", "failed": "red", "pending": "cyan"}
                c = color.get(t.get("status", "pending"), "white")
                print(f"  [{colorize(t['status'], c)}] {t['task_name']}")
        elif sub == "start" and len(args) > 1:
            result = self.task_manager.start_task(args[1], self.student_id)
            if "error" in result:
                print(colorize(f"错误: {result['error']}", "red"))
            else:
                task = result.get("task", {})
                print(f"\n{colorize(f'开始任务: {task.get("title", "")}', 'green')}")
                print(f"  {colorize('描述:', 'cyan')} {task.get('description', '')}")
                print(f"  {colorize('难度:', 'cyan')} {task.get('difficulty', '')}")
                if task.get("hints"):
                    print(f"  {colorize('提示:', 'yellow')}")
                    for h in task["hints"]:
                        print(f"    • {h}")

    # ──────────────────────────────────────────
    # 工具箱命令
    # ──────────────────────────────────────────

    def _cmd_baseline(self, parsed=None):
        """运行基线检查"""
        print(colorize("\n正在运行 CIS MySQL Baseline 安全检查...", "cyan"))
        result = self.baseline_checker.run_all_checks()
        summary = result["summary"]

        print(f"\n{colorize('=' * 50, 'blue')}")
        print(f"{colorize('  基线检查完成', 'green')}")
        print(f"{colorize('=' * 50, 'blue')}")
        print(f"  总分: {colorize(str(summary['score']), 'yellow')}/100")
        print(f"  等级: {colorize(summary['grade'], 'cyan')}")
        print(f"  通过: {colorize(str(summary['passed']), 'green')} | 失败: {colorize(str(summary['failed']), 'red')}")

        for detail in result["details"]:
            if detail["status"] == "fail":
                c = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(detail["severity"], "white")
                print(f"  [{colorize('✗', c)}] {detail['check_name']}")
                print(f"     {detail['actual_value']}")

    def _cmd_perm(self, parsed=None):
        """权限分析"""
        print(colorize("\n正在分析数据库用户权限...", "cyan"))
        result = self.perm_analyzer.analyze_all()
        summary = result["summary"]

        print(f"\n{colorize('=' * 50, 'blue')}")
        print(f"{colorize('  权限分析完成', 'green')}")
        print(f"{colorize('=' * 50, 'blue')}")
        print(f"  总用户: {summary['total_users']} | 发现问题: {summary['total_issues']}")
        print(f"  严重: {colorize(str(summary['critical_count']), 'red')} | "
              f"高危: {colorize(str(summary['high_count']), 'yellow')} | "
              f"中危: {colorize(str(summary['medium_count']), 'cyan')}")

        for issue in result["issues"][:5]:
            sev_color = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(issue["severity"], "white")
            print(f"  [{colorize(issue['severity'].upper(), sev_color)}] {issue['user']}@{issue['host']}")
            print(f"    {issue['description']}")

    def _cmd_recovery(self, parsed):
        """恢复命令"""
        args = parsed["args"]
        if not args:
            print(colorize("用法: recovery <命令>", "yellow"))
            print(f"  例如: {colorize('recovery xtrabackup --prepare --apply-log-only --target-dir=/backup/full/', 'cyan')}")
            return

        command = " ".join(args)
        result = self.recovery_sim.execute_command(command, self.student_id)
        print(f"\n{result['output']}")

    # ──────────────────────────────────────────
    # 攻防命令
    # ──────────────────────────────────────────

    def _cmd_attack(self, parsed):
        """攻击模拟"""
        args = parsed["args"]
        target = args[0] if args else "/api/user/profile"
        payload = " ".join(args[1:]) if len(args) > 1 else "1 UNION SELECT 1,2,3,4"

        print(colorize(f"\n攻击目标: {target}", "red"))
        print(colorize(f"攻击载荷: {payload}", "red"))

        result = self.attack_sim.run_attack(target, payload)
        if result.get("success"):
            warning = result.get("response", {}).get("warning", "")
            print(colorize(f"\n✓ 攻击成功! {warning}", "red"))
        else:
            print(colorize("\n✗ 攻击未成功", "yellow"))

    def _cmd_fix(self, parsed):
        """修复漏洞"""
        args = parsed["args"]
        if not args:
            print(colorize("用法: fix <path>", "yellow"))
            print(f"  例如: {colorize('fix /api/user/profile', 'cyan')}")
            return

        path = args[0]
        result = self.vuln_app.fix_endpoint(path)
        print(colorize(f"\n{result.get('message', '')}", "green"))

    def _cmd_waf(self, parsed):
        """验证WAF规则"""
        args = parsed["args"]
        rules = " ".join(args) if args else ""
        if not rules:
            print(colorize("用法: waf <规则文本>", "yellow"))
            print(f"  例如: {colorize('waf SecRule ARGS \"(?:union(?:.+?)select)\" \"phase:2,deny,status:403\"', 'cyan')}")
            return

        result = self.defense_val.validate_waf_rule(rules)
        status_icon = "✓" if result.status == "pass" else "✗" if result.status == "fail" else "⚠"
        sev_color = {"pass": "green", "fail": "red", "partial": "yellow"}.get(result.status, "white")
        print(f"\n{colorize(f'[{status_icon}] WAF规则验证: {result.status}', sev_color)}")
        print(f"  评分: {result.score}/100")
        for detail in result.details:
            print(f"  {detail}")
        for suggestion in result.suggestions:
            print(f"  {colorize(f'建议: {suggestion}', 'cyan')}")

    # ──────────────────────────────────────────
    # 报告与评分
    # ──────────────────────────────────────────

    def _cmd_report(self, parsed=None):
        """生成审计报告"""
        print(colorize("\n正在生成《数据库安全运维与加固报告》...", "cyan"))
        result = self.report_gen.export_report(self.student_id, "html")
        if result.get("success"):
            print(colorize(f"\n✓ 报告已生成: {result['filepath']}", "green"))
        else:
            print(colorize(f"\n✗ 报告生成失败", "red"))

    def _cmd_score(self, parsed=None):
        """查看综合评分"""
        score = self.orchestrator.calculate_final_score(self.student_id)
        print(f"\n{colorize('=' * 40, 'blue')}")
        print(f"{colorize('  综合评分', 'green')}")
        print(f"{colorize('=' * 40, 'blue')}")
        print(f"  {colorize('学员:', 'cyan')} {score['student_name']}")
        print(f"  {colorize('基础分:', 'cyan')} {score['base_score']}")
        print(f"  {colorize('失败扣分:', 'red')} -{score['fail_penalty']}")
        print(f"  {colorize('重试扣分:', 'yellow')} -{score['retry_penalty']}")
        print(f"  {colorize('漏洞修复加分:', 'green')} +{score['vuln_bonus']}")
        print(f"  {colorize('最终得分:', 'bold')} {colorize(str(score['final_score']), 'yellow')}/100")
        print(f"  {colorize('等级:', 'cyan')} {score['grade']}")

    def _cmd_history(self, parsed=None):
        """查看命令历史"""
        commands = self.orchestrator.get_command_history(self.student_id)
        print(f"\n{colorize('最近命令历史:', 'green')}")
        for i, cmd in enumerate(commands[:20], 1):
            ts = cmd.get("executed_at", "")[:19] if cmd.get("executed_at") else ""
            print(f"  {i:3d}. [{ts}] {cmd['command'][:80]}")

    def _cmd_exit(self, parsed=None):
        """退出程序"""
        print(colorize("\n感谢使用数据库安全运维智能体！", "green"))
        self.running = False
        self.db.close_all()


# ══════════════════════════════════════════
# 入口
# ══════════════════════════════════════════

def main():
    """主入口"""
    if len(sys.argv) < 2:
        print("用法: python main.py <command>")
        print("  命令: init  - 初始化数据库")
        print("         cli   - 进入命令行交互模式")
        print("         web   - 启动 Web 服务")
        return

    command = sys.argv[1].lower()
    config = get_config()

    if command == "init":
        db = DatabaseConnector(config)
        db.init_sqlite_schema()
        print(colorize("✓ 数据库初始化完成", "green"))
        print(f"  SQLite: {config.SQLITE_DB_PATH}")
        db.close_all()

    elif command == "cli":
        cli = Agent1CLI()
        cli.run()

    elif command == "web":
        # 启动 Flask Web 服务
        from app import app
        logger = get_logger("main")
        logger.info(f"启动 Web 服务: http://{config.HOST}:{config.PORT}")
        app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)

    else:
        print(colorize(f"未知命令: {command}", "red"))
        print("可用命令: init, cli, web")


if __name__ == "__main__":
    main()