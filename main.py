# -*- coding: utf-8 -*-
"""入口：check / status / chat / gui / selftest

用法（在 conda workenv 中）：
    python main.py check       # 只读查询各平台余额/免费额度
    python main.py status      # 查看模型启用、额度、冷却状态
    python main.py chat        # 命令行对话（自动切换模型）
    python main.py gui         # 启动本地 Gradio 界面（仅本机可访问）
    python main.py selftest    # 用本地 Mock 服务验证调度逻辑
"""
import sys
import os
import argparse

from config import load_config, resolve_paths, load_providers
from logger import UsageLogger
from scheduler import Scheduler, AllExhausted
from balance_checker import check_all_balances, format_balance_report


def build(cfg_path: str | None = None):
    try:
        cfg = load_config(cfg_path)
        paths = resolve_paths(cfg)
        providers = load_providers(paths["secrets_path"])
    except (FileNotFoundError, ValueError) as e:
        print(f"❌ 启动前置条件未满足：\n{e}\n")
        sys.exit(1)
    logger = UsageLogger(paths["log_dir"])
    sched = Scheduler(providers, paths["state_path"], cfg, logger)
    return cfg, paths, providers, logger, sched


def cmd_check(cfg_path=None):
    _, _, providers, logger, _ = build(cfg_path)
    print("== 各平台余额/免费额度只读检查 ==")
    results = check_all_balances(providers)
    print(format_balance_report(results))
    logger.log("INFO", "执行余额检查", {"n": len(results)})


def cmd_status(cfg_path=None):
    _, _, providers, logger, sched = build(cfg_path)
    print("== 模型调度状态 ==")
    rows = sched.status_rows()
    if not rows:
        print("(无模型配置)")
        return
    w = {"平台": 12, "模型": 24, "免费专用": 6, "任务类型": 20, "启用": 4, "Key 状态": 8, "工具": 4,
         "今日tokens/上限": 20, "今日次数/上限": 12, "状态": 26, "说明": 30}
    header = "  ".join(f"{k.ljust(v)}" for k, v in w.items())
    print(header)
    print("-" * len(header))
    for r in rows:
        print("  ".join(f"{str(r[k]).ljust(v)}" for k, v in w.items()))


def cmd_chat(cfg_path=None, task_type=None):
    cfg, _, _, logger, sched = build(cfg_path)
    print("本地多模型免费额度调度器 - 命令行对话（Ctrl+C 退出）")
    print(f"任务类型: {task_type or '默认'}；仅调度 free_only 模型；全部额度用尽时不会调用任何付费模型。\n")
    print("特殊命令: /plan <任务> 拆解并执行计划 | /plans 列出计划 | /plan-run <id> 继续执行 | /plan-approve <id> [步骤]")
    from planner import Planner
    planner = Planner(sched, logger, os.path.join(cfg.get("private_dir", ""), "plans.json"))
    history = []
    try:
        while True:
            try:
                prompt = input("你: ").strip()
            except EOFError:
                break
            if not prompt:
                continue
            if prompt.lower() in ("quit", "exit", "退出"):
                break
            if prompt.startswith("/plan ") and len(prompt) > 6:
                try:
                    plan = planner.make_plan(prompt[6:].strip())
                    print(f"\n[计划 {plan.id}] 已生成 {len(plan.steps)} 步：")
                    print(planner.summary(plan.id))
                    logs = planner.run_all(plan)
                    print("\n".join(logs))
                except Exception as e:
                    print(f"\n[计划失败] {e}")
                continue
            if prompt.strip() == "/plans":
                for p in planner.list_plans():
                    print(planner.summary(p.id))
                    print()
                continue
            if prompt.startswith("/plan-run "):
                pid = prompt.split()[1].strip()
                plan = planner.get(pid)
                if not plan:
                    print(f"\n[计划 {pid} 不存在]")
                    continue
                print("\n".join(planner.run_all(plan)))
                continue
            if prompt.startswith("/plan-approve "):
                parts = prompt.split()
                pid = parts[1].strip()
                step_id = parts[2] if len(parts) > 2 else None
                r = planner.approve_step(pid, step_id)
                print(f"\n[{r['message']}] {r.get('content', '')[:300]}")
                continue
            history.append({"role": "user", "content": prompt})
            try:
                res = sched.chat(history, task_type=task_type)
                print(f"\n[{res.provider}] (消耗 {res.tokens} tokens"
                      + (", 自动切换过模型" if res.switched else "") + "):")
                print(res.reply)
                history.append({"role": "assistant", "content": res.reply})
            except AllExhausted as e:
                print(f"\n[提醒] {e}\n")
    except KeyboardInterrupt:
        print("\n再见。")


def cmd_gui(cfg_path=None):
    from gui import launch
    launch(cfg_path)


def cmd_selftest():
    from tests import test_scheduler, test_tools, test_extra, test_extra2, test_extra3
    ok1 = test_scheduler.run_all()
    ok2 = test_tools.run_all()
    ok3 = test_extra.run_all()
    ok4 = test_extra2.run_all()
    ok5 = test_extra3.run_all()
    sys.exit(0 if (ok1 and ok2 and ok3 and ok4 and ok5) else 1)


def main():
    parser = argparse.ArgumentParser(description="本地多模型免费额度调度器")
    parser.add_argument("cmd", nargs="?", default="help",
                        choices=["check", "status", "chat", "gui", "selftest", "help"])
    parser.add_argument("--config", default=None, help="自定义 config.json 路径")
    parser.add_argument("--task", default=None,
                        help="任务类型（chat/summary/code/reasoning/vision/planning），仅chat命令生效")
    args = parser.parse_args()

    if args.cmd == "help":
        parser.print_help()
        return
    if args.cmd == "selftest":
        cmd_selftest()
        return
    if args.cmd == "chat":
        cmd_chat(args.config, task_type=args.task)
        return
    fn = {"check": cmd_check, "status": cmd_status, "gui": cmd_gui}[args.cmd]
    fn(args.config)


if __name__ == "__main__":
    main()
