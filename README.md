# 数据库安全运维智能体 (Agent 1)

## 项目简介
基于真实银行场景的数据库安全运维实训平台，提供高仿真终端环境、攻防演练靶场、运维工具箱和审计报告生成四大核心功能。

## 技术栈
- **后端**: Python 3.8+ / Flask
- **数据库**: SQLite (状态记录) + Redis (缓存/会话)
- **前端**: xterm.js (伪终端) + HTML/CSS/JS
- **报告**: Jinja2 + WeasyPrint (PDF)

## 项目结构
```
agent_1/
├── README.md                         # 项目说明
├── requirements.txt                  # 依赖清单
├── app.py                            # Flask Web 应用入口 (含前端页面)
├── main.py                           # CLI 命令行入口 (含完整交互界面)
│
├── config/
│   ├── __init__.py
│   └── settings.py                   # 配置管理 (SQLite+Redis)
│
├── core/
│   ├── __init__.py
│   ├── database_connector.py         # SQLite + Redis 连接管理
│   ├── security_monitor.py           # 安全监控 (SQL注入检测/基线/告警)
│   └── agent_orchestrator.py         # 智能体编排器 (故事状态机/评分系统)
│
├── modules/
│   ├── scenario/                     # 场景模拟引导模块
│   │   ├── story_engine.py           #   故事引擎 (3分支决策/告警弹窗/工单)
│   │   ├── task_manager.py           #   任务管理器 (10个预定义任务)
│   │   └── terminal_simulator.py     #   终端模拟器 (CLI/mysql/文件系统)
│   │
│   ├── shooting_range/               # 攻防演练靶场模块
│   │   ├── vulnerable_app.py         #   漏洞应用模拟器 (3端点/模拟DB)
│   │   ├── attack_simulator.py       #   攻击模拟器 (SQLMap/Burp风格日志)
│   │   └── defense_validator.py      #   防御验证器 (代码修复/WAF规则)
│   │
│   ├── toolkit/                      # 运维工具箱模块
│   │   ├── baseline_checker.py       #   基线检查器 (12项CIS检查)
│   │   ├── permission_analyzer.py    #   权限分析器 (8用户/过度授权检测)
│   │   └── recovery_simulator.py     #   数据恢复模拟器 (PITR/SOP校验)
│   │
│   └── report/                       # 审计报告生成模块
│       └── report_generator.py       #   报告生成器 (HTML/Text/JSON)
│
└── utils/
    ├── __init__.py
    ├── logger.py                     # 日志记录器
    └── helpers.py                    # 通用工具函数

```

## 安装与运行
```bash
# 安装依赖
pip install -r requirements.txt

# 初始化数据库
python main.py init

# 启动 Web 服务
python app.py

# 命令行模式
python main.py cli
```

## 核心功能
1. **场景模拟引导** - 银行核心数据库运维场景，多分支故事线
2. **攻防演练靶场** - SQL注入漏洞复现与防御（Union注入、盲注）
3. **运维工具箱** - 基线检查、权限分析、数据恢复模拟
4. **审计报告生成** - 自动生成符合银行业标准的PDF报告