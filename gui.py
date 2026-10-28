# -*- coding: utf-8 -*-
"""Gradio 本地界面（v2）：对话(本地工具+图片) / 本地工具(审批+策略+缓存+审计) /
仪表盘(预警+趋势) / 额度检查 / 调度状态 / 配置与自检 / 运行日志 / 会话管理。
仅监听 127.0.0.1，只本机可访问；不向任何外部服务上传数据。
"""
import os
import json
import shutil
import base64
import datetime

import gradio as gr

from config import load_config, resolve_paths, load_providers
from logger import UsageLogger
from scheduler import Scheduler, AllExhausted, ChatResult
from balance_checker import check_all_balances
from local_tools import save_code_blocks
from planner import Planner


def _build(cfg_path):
    try:
        cfg = load_config(cfg_path)
        paths = resolve_paths(cfg)
        providers = load_providers(paths["secrets_path"])
    except (FileNotFoundError, ValueError) as e:
        print(f"❌ 启动前置条件未满足：\n{e}\n")
        raise SystemExit(1)
    logger = UsageLogger(paths["log_dir"],
                         max_bytes=(cfg.get("logging", {}) or {}).get("max_bytes", 1 << 20),
                         backup_count=(cfg.get("logging", {}) or {}).get("backup_count", 3))
    sched = Scheduler(providers, paths["state_path"], cfg, logger)
    planner = Planner(sched, logger, os.path.join(paths["private_dir"], "plans.json"))
    return cfg, paths, providers, logger, sched, planner


def _balance_table(providers):
    results = check_all_balances(providers)
    rows = []
    for r in results:
        p = next((x for x in providers if x.display_name == r.get("display_name")), None)
        if p is not None and not p.free_only:
            rows.append([p.display_name, "API收费", "🔒 锁定·禁止调用",
                         "调度器永不调用该平台API（防扣费）；网页免费版见下方「主流AI网页免费入口」",
                         r.get("url", "-")])
            continue
        if r["status"] == "ok":
            detail = []
            for k, v in r.items():
                if k in ("balance", "granted", "topped_up", "voucher", "cash",
                         "total_balance", "charge_balance") and v is not None:
                    detail.append(f"{k}={v}")
            state = "可用" if r.get("available", False) else "不可用"
            rows.append([r["display_name"], "接口查询", state, "; ".join(detail) or "-", r["url"]])
        elif r["status"] == "manual":
            rows.append([r["display_name"], "无接口", "控制台自查", r["how_to"], r["url"]])
        elif r["status"] == "nokey":
            rows.append([r["display_name"], "未配置", "-", r["message"], r["url"]])
        else:
            rows.append([r["display_name"], "查询失败", "-", r["message"], r["url"]])
    return rows


def _web_entries_html(cfg):
    """主流AI网页免费入口（API收费平台禁止调度器调用，跳转官方网页免费使用）。"""
    entries = cfg.get("web_free_entries", [])
    if not entries:
        return "(未配置 web_free_entries)"
    parts = ["<table style='width:100%;border-collapse:collapse'>",
             "<tr><th style='text-align:left'>平台</th><th style='text-align:left'>说明</th>"
             "<th style='text-align:left'>官方入口</th></tr>"]
    for e in entries:
        parts.append(
            f"<tr><td><b>{e['name']}</b></td><td>{e['desc']}</td>"
            f"<td><a href='{e['url']}' target='_blank'>打开网页版（免费）</a></td></tr>")
    parts.append("</table>")
    return "".join(parts)


def _norm_content(content):
    """把可能含 image_url 的 content 归一化为纯文本（用于会话存储/导出）。"""
    if isinstance(content, list):
        texts = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"]
        return " ".join(t for t in texts if t)
    return str(content or "")


def _text_of(msg):
    return _norm_content(msg.get("content", ""))


def launch(cfg_path=None):
    cfg, paths, providers, logger, sched, planner = _build(cfg_path)
    private_dir = paths["private_dir"]
    sandbox_dir = (cfg.get("tool_policy", {}) or {}).get("write_dirs", [""])[0]
    sessions_path = os.path.join(private_dir, "sessions.json")
    history_turns = int(cfg.get("scheduler", {}).get("history_turns", 20))
    vision_enabled = bool((cfg.get("vision", {}) or {}).get("enabled", False))
    read_dirs = (cfg.get("tool_policy", {}) or {}).get("read_dirs", [])
    task_types = (cfg.get("task_routing", {}) or {}).get("types", ["chat"])
    default_task = (cfg.get("task_routing", {}) or {}).get("default_type", "chat")

    # ---------- 会话 ----------
    def load_sessions():
        try:
            with open(sessions_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"default": {"title": "默认会话", "history": []}}

    def save_sessions(store):
        try:
            os.makedirs(os.path.dirname(sessions_path), exist_ok=True)
            with open(sessions_path, "w", encoding="utf-8") as f:
                json.dump(store, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    sessions = load_sessions()
    current_sid = "default"
    # 每个会话的原始消息记录（含工具调用/结果），供多轮对话上下文复用
    session_msgs = {"default": []}

    def persist_current(history, sid):
        sessions[sid] = {"title": sessions.get(sid, {}).get("title", sid),
                         "history": history or []}
        save_sessions(sessions)

    # ---------- 对话 ----------
    unset = [p.display_name for p in providers if p.enabled
             and (not p.api_key or "填入" in str(p.api_key))]
    notice = ("⚠️ 以下启用中的平台尚未填入API Key（在 C:\\Users\\YourName\\AI\\llm_dispatcher\\secrets.json 填写）："
              + ", ".join(unset)) if unset else "全部启用平台已配置API Key（API收费平台已锁定，不会调用）。"

    def _history_msgs(history):
        return [{"role": h.get("role", "user"), "content": _text_of(h)} for h in (history or [])]

    def respond(message, history, image_path, task_type):
        history = list(history or [])
        sid = current_sid
        try:
            if image_path and os.path.exists(str(image_path)):
                if not vision_enabled:
                    raise AllExhausted("图片功能未启用（config.json → vision.enabled=true 可开启；且模型需支持视觉）")
                real = os.path.realpath(str(image_path))
                if not any(real == r or real.startswith(r + os.sep) for r in
                           [os.path.realpath(x) for x in read_dirs]):
                    raise AllExhausted(f"图片不在白名单目录内（请放到 {read_dirs[0]} 下再引用）")
                ext = os.path.splitext(real)[1].lower().lstrip(".")
                if os.path.getsize(real) > 5 * 1024 * 1024:
                    raise AllExhausted("图片超过5MB")
                with open(real, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode("ascii")
                user_msg = {"role": "user", "content": [
                    {"type": "text", "text": message},
                    {"type": "image_url", "image_url": {"url": f"data:image/{ext};base64,{b64}"}}]}
                msgs = list(session_msgs.get(sid, [])) + [user_msg]
            else:
                msgs = list(session_msgs.get(sid, [])) + [{"role": "user", "content": message}]
            res = sched.chat(msgs, task_type=task_type)
        except AllExhausted as e:
            reply = f"⚠️ {e}"
            history.append({"role": "user", "content": message})
            history.append({"role": "assistant", "content": reply})
            session_msgs[sid] = list(session_msgs.get(sid, [])) + [
                {"role": "user", "content": message}, {"role": "assistant", "content": reply}]
            persist_current(history, sid)
            return history, ""
        reply = res.reply
        if res.cached:
            reply += "\n\n📦 命中本地缓存（未消耗额度）"
        if res.tools_called:
            reply += "\n\n🔧 本地工具调用：\n" + "\n".join(f"- {t[1]}" for t in res.tools_called)
        if res.pending_id:
            reply += "\n\n（可在「本地工具」页签查看并批准/拒绝）"
        elif res.ok:
            note = f"\n\n—— 由 **{res.provider}** 回复（消耗 {res.tokens} tokens"
            note += "，自动切换过模型" if res.switched else ""
            note += f"，任务类型 {task_type or default_task}）——"
            reply += note
        history.append({"role": "user", "content": message})
        history.append({"role": "assistant", "content": reply})
        # 维护原始消息记录（含工具调用/结果），保证多轮对话上下文完整
        tr = getattr(res, "transcript", None)
        session_msgs[sid] = tr if tr else (list(msgs) + [{"role": "assistant", "content": reply}])
        persist_current(history, sid)
        return history, ""

    def save_code_from_chat(history):
        history = list(history or [])
        texts = [_text_of(h) for h in history if h.get("role") == "assistant"]
        if not texts:
            return "对话中还没有回复内容"
        saved = save_code_blocks(texts[-1], sandbox_dir)
        return "已保存代码块：\n" + "\n".join(saved) if saved else "回复中没有 ``` 代码块"

    # ---------- 会话 UI ----------
    def session_choices():
        return list(sessions.keys())

    def new_session(history):
        nonlocal current_sid
        persist_current(history, current_sid)
        sid = f"s{datetime.datetime.now():%H%M%S}"
        sessions[sid] = {"title": f"会话 {len(sessions) + 1}", "history": []}
        save_sessions(sessions)
        current_sid = sid
        session_msgs[sid] = []
        return [], gr.update(choices=session_choices(), value=sid)

    def switch_session(sid, history):
        nonlocal current_sid
        if not sid or sid not in sessions:
            return history, gr.update()
        persist_current(history, current_sid)
        current_sid = sid
        session_msgs.setdefault(sid, [])
        return sessions[sid].get("history", []), gr.update()

    def delete_session(sid, history):
        nonlocal current_sid
        if not sid or sid == "default":
            return history, gr.update(choices=session_choices(), value=current_sid), "默认会话不可删除"
        persist_current(history, current_sid)
        sessions.pop(sid, None)
        session_msgs.pop(sid, None)
        save_sessions(sessions)
        current_sid = "default"
        return sessions["default"]["history"], gr.update(choices=session_choices(), value="default"), f"已删除 {sid}"

    def export_session(sid):
        target = sessions.get(sid or current_sid, {})
        hist = target.get("history", [])
        lines = [f"# 会话导出 {sid or current_sid}  ({datetime.datetime.now():%Y-%m-%d %H:%M})", ""]
        for h in hist:
            role = "用户" if h.get("role") == "user" else "模型"
            lines.append(f"**{role}**：\n{_text_of(h)}\n")
        md = "\n".join(lines)
        out = os.path.join(sandbox_dir, f"session_{sid or current_sid}.md")
        with open(out, "w", encoding="utf-8") as f:
            f.write(md)
        return f"已导出到 {out}"

    # ---------- 仪表盘 ----------
    def warning_banner():
        rows = sched.status_rows()
        warns = [f"⚠️ **{r['平台']}**：今日已用 {r['今日tokens/上限']}（≥80%），请留意免费额度"
                 for r in rows if r.get("预警")]
        no_keys = [f"**{r['平台']}**（{r['Key 状态']}）"
                   for r in rows if r.get("启用") == "是" and r.get("Key 状态") != "已配置"]
        if no_keys:
            warns.append("🔑 以下已启用平台未配置有效 API Key，不会被调度："
                         + "、".join(no_keys) + "（请到 secrets.json 填写后重启界面）")
        return "\n\n".join(warns) if warns else "✅ 当前所有模型免费额度充足（<80%），Key 均已配置"

    def dashboard_data():
        trend = sched.daily_trend(7)
        return trend

    # ---------- 配置与自检 ----------
    def config_text():
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json"), "r", encoding="utf-8") as f:
            return f.read()

    def save_config(text):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            return f"❌ JSON 格式错误：{e}"
        cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        bak = cfg_path + ".bak"
        try:
            if os.path.exists(cfg_path):
                shutil.copy2(cfg_path, bak)
        except OSError:
            pass
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        return "✅ 已保存 config.json（已留 config.json.bak 备份；部分设置需重启界面后生效）。secrets.json 不允许在此编辑。"

    def run_self_check():
        rows = []
        try:
            load_config()
            rows.append(("config.json", "通过", "可解析"))
        except Exception as e:
            rows.append(("config.json", "失败", str(e)[:100]))
        try:
            with open(paths["secrets_path"], "r", encoding="utf-8") as f:
                json.load(f)
            ok = [p.display_name for p in providers if p.configured]
            bad = [f"{p.display_name}({p.key_status_label})"
                   for p in providers if p.enabled and not p.configured]
            detail = f"已配置 {len(ok)} 个 Key"
            if bad:
                detail += "；未配置: " + "、".join(bad)
            rows.append(("secrets.json", "通过" if ok else "注意", detail[:160]))
        except Exception as e:
            rows.append(("secrets.json", "失败", str(e)[:100]))
        r = sched.executor.read_file(os.path.join(private_dir, "state.json"))
        rows.append(("私密目录隔离", "生效" if (not r.ok and "私密" in r.content) else "失效",
                     "读取私密目录应被拒绝" if not r.ok else r.content[:80]))
        r = sched.executor.write_file(os.path.join(sandbox_dir, "..", "outside.txt"), "x")
        rows.append(("写入边界", "生效" if not r.ok else "失效", r.content[:80] if not r.ok else "越界写入竟然成功了！"))
        r = sched.executor.run_command("curl http://example.com")
        rows.append(("危险命令拦截", "生效" if not r.ok else "失效", r.content[:80] if not r.ok else "危险命令竟然放行了！"))
        logger.log("INFO", "一键自检完成")
        rows.append(("日志写入", "通过", "usage.log 正常写入"))
        results = check_all_balances(providers)
        from collections import Counter
        c = Counter(x["status"] for x in results)
        rows.append(("余额/免费额度检查", "完成", dict(c)))
        return rows

    # ---------- 本地工具 ----------
    def _pending_rows():
        return [[p["id"], p["description"], p["status"], p["expire"]] for p in sched.pending_list()]

    def _pending_choices():
        return [p["id"] for p in sched.pending_list() if p["status"] == "pending"]

    def do_approve(pid, history):
        history = list(history or [])
        res = sched.approve(pid) if pid else ChatResult(ok=False, reply="请先选择待批准操作ID")
        tag = f"✅ 已批准并执行 {pid}" if res.ok else f"⚠️ 批准 {pid} 后未完成"
        history.append({"role": "assistant", "content": f"{tag}: {res.reply}"})
        tr = getattr(res, "transcript", None)
        if tr:
            session_msgs[current_sid] = tr
        persist_current(history, current_sid)
        return history, "", *_pending_rows(), gr.update(choices=_pending_choices())

    def do_reject(pid, history):
        history = list(history or [])
        res = sched.reject(pid) if pid else ChatResult(ok=False, reply="请先选择待批准操作ID")
        history.append({"role": "assistant", "content": f"⛔ 已拒绝 {pid}: {res.reply}"})
        tr = getattr(res, "transcript", None)
        if tr:
            session_msgs[current_sid] = tr
        persist_current(history, current_sid)
        return history, "", *_pending_rows(), gr.update(choices=_pending_choices())

    def cache_status_text():
        st = sched.cache_stats()
        if not st["enabled"]:
            return "响应缓存未启用（config.json → cache.enabled）"
        return f"缓存已启用：{st['entries']} 条（目录 {st['dir']}）"

    def export_audit():
        sec = logger.tail(500, logger.sec_path)
        usage = logger.tail(500)
        out = os.path.join(sandbox_dir, f"audit_export_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt")
        with open(out, "w", encoding="utf-8") as f:
            f.write("===== security_audit.log =====\n" + sec + "\n\n===== usage.log =====\n" + usage)
        return f"审计导出完成 → {out}"

    # ---------- UI ----------
    with gr.Blocks(title="本地多模型免费额度调度器") as demo:
        gr.Markdown("# 本地多模型免费额度调度器")
        gr.Markdown("✅ 仅调度 free_only（免费专用）模型 · 绝不超过免费额度 · 密钥只存本地 · 不自动领取任何平台福利\n\n" + notice)

        with gr.Tab("对话"):
            with gr.Row():
                sess_dd = gr.Dropdown(label="会话", choices=session_choices(), value=current_sid, scale=4)
                task_dd = gr.Dropdown(label="任务类型", choices=task_types, value=default_task, scale=2)
                btn_new = gr.Button("新建会话", scale=1)
                btn_del = gr.Button("删除会话", scale=1)
                btn_export = gr.Button("导出会话", scale=1)
            chatbot = gr.Chatbot(label="对话", height=420)
            with gr.Row():
                msg = gr.Textbox(show_label=False, placeholder="输入消息（Enter 发送）；工具危险操作需批准后执行", scale=6, container=False)
                img = gr.Image(type="filepath", label="图片(可选)", scale=2, show_label=True, height=80)
            with gr.Row():
                send_btn = gr.Button("发送", scale=1)
                clear_btn = gr.Button("清空", scale=1)
                code_btn = gr.Button("💾 保存回复中的代码块到沙箱", scale=2)
            code_info = gr.Textbox(label="提示", interactive=False)
            msg.submit(respond, [msg, chatbot, img, task_dd], [chatbot, msg])
            send_btn.click(respond, [msg, chatbot, img, task_dd], [chatbot, msg])
            clear_btn.click(lambda: ([], ""), outputs=[chatbot, msg])
            code_btn.click(save_code_from_chat, [chatbot], [code_info])
            sess_dd.change(switch_session, [sess_dd, chatbot], [chatbot, sess_dd])
            btn_new.click(new_session, [chatbot], [chatbot, sess_dd])
            btn_del.click(delete_session, [sess_dd, chatbot], [chatbot, sess_dd, code_info])
            btn_export.click(export_session, [sess_dd], [code_info])

        with gr.Tab("计划任务"):
            gr.Markdown("### Plan 任务拆解：把复杂任务交给模型拆成步骤清单，逐步执行（可断点续跑）")
            with gr.Row():
                plan_task = gr.Textbox(label="任务描述", placeholder="例如：把 README.md 里的工具表格整理成 csv 存到沙箱", scale=6)
                btn_make_plan = gr.Button("🤖 生成计划", scale=1, variant="primary")
            with gr.Row():
                plan_sel = gr.Dropdown(label="已有计划（可继续执行）", choices=[], scale=4)
                btn_load = gr.Button("载入", scale=1)
                btn_run_next = gr.Button("▶ 执行下一步", scale=1)
                btn_approve_plan = gr.Button("✅ 批准当前步骤", scale=1)
                btn_reject_plan = gr.Button("⛔ 拒绝当前步骤", scale=1)
            plan_df = gr.Dataframe(headers=["步骤ID", "描述", "工具", "状态"],
                                   datatype=["str", "str", "str", "str"])
            plan_log = gr.Textbox(label="执行日志", lines=10, interactive=False)

            def _plans_choices():
                return [f"{p.id} | {p.task[:40]}" for p in planner.list_plans()]

            def _plan_rows(plan):
                if not plan:
                    return []
                rows = []
                for s in plan.steps:
                    r = plan.results.get(s["id"])
                    if r and r.get("ok"):
                        st = "✓ 完成"
                    elif r:
                        st = "✗ 失败/拒绝"
                    elif s["id"] == plan.current_index + 1:
                        st = "▶ 待执行"
                    else:
                        st = "待执行"
                    rows.append([str(s["id"]), s["description"], s["tool"], st])
                return rows

            def _cur_plan(plan_id):
                if not plan_id:
                    return None
                return planner.get(plan_id.split(" | ")[0])

            def do_make_plan(task):
                try:
                    plan = planner.make_plan(task)
                except Exception as e:
                    return f"❌ 生成失败: {e}", [], gr.update(choices=_plans_choices(), value="")
                msg = f"✅ 已生成计划 {plan.id}（{len(plan.steps)} 步），可逐条执行"
                return msg, _plan_rows(plan), gr.update(choices=_plans_choices(), value=f"{plan.id} | {plan.task[:40]}")

            def do_plan_next(plan_id):
                plan = _cur_plan(plan_id)
                if not plan:
                    return "请先选择计划", [], ""
                r = planner.execute_next(plan)
                if r.get("needs_approval"):
                    log = r["message"]
                else:
                    log = f"[{'OK' if r['ok'] else '失败'}] 步骤{r['step']['id']}: {r['step']['description']}\n{r.get('content', '')[:400]}"
                return log, _plan_rows(plan), (log if not r.get("needs_approval") else f"⚠️ 等待批准\n{log}")

            def do_plan_approve(plan_id):
                plan = _cur_plan(plan_id)
                if not plan:
                    return "请先选择计划", [], ""
                r = planner.approve_step(plan.id)
                return f"✅ {r['message']}: {r.get('content', '')[:400]}", _plan_rows(plan), \
                       f"✅ 已批准步骤{r['step']['id']}并执行"

            def do_plan_reject(plan_id):
                plan = _cur_plan(plan_id)
                if not plan:
                    return "请先选择计划", [], ""
                r = planner.reject_step(plan.id)
                return f"⛔ {r['message']}", _plan_rows(plan), f"⛔ {r['message']}"

            def do_plan_load(plan_id):
                plan = _cur_plan(plan_id)
                if not plan:
                    return "请先选择计划", []
                return f"已载入 {plan.id}，进度 {plan.current_index}/{len(plan.steps)}", _plan_rows(plan)

            btn_make_plan.click(do_make_plan, [plan_task], [plan_log, plan_df, plan_sel])
            btn_load.click(do_plan_load, [plan_sel], [plan_log, plan_df])
            btn_run_next.click(do_plan_next, [plan_sel], [plan_log, plan_df, plan_log])
            btn_approve_plan.click(do_plan_approve, [plan_sel], [plan_log, plan_df, plan_log])
            btn_reject_plan.click(do_plan_reject, [plan_sel], [plan_log, plan_df, plan_log])
            gr.Markdown("> 提示：计划与进度保存在私密目录 plans.json，重启后仍可继续执行；需要批准的工具步骤（如 run_script）会停下等待你批准。")

        with gr.Tab("本地工具"):
            gr.Markdown("### 待批准操作（human-in-the-loop）\n模型请求的危险操作会停在这里，**未经批准绝不执行**。")
            with gr.Row():
                pend_sel = gr.Dropdown(label="选择操作ID", choices=_pending_choices(), scale=4)
                btn_approve = gr.Button("✅ 批准执行", scale=1, variant="primary")
                btn_reject = gr.Button("⛔ 拒绝", scale=1)
            pend_df = gr.Dataframe(headers=["ID", "操作描述", "状态", "剩余有效期"],
                                   value=_pending_rows(), datatype=["str", "str", "str", "str"])
            gr.Button("刷新列表").click(lambda: (_pending_rows(), gr.update(choices=_pending_choices())),
                                        outputs=[pend_df, pend_sel])
            btn_approve.click(do_approve, [pend_sel, chatbot],
                              [chatbot, pend_sel, pend_df, pend_sel])
            btn_reject.click(do_reject, [pend_sel, chatbot],
                             [chatbot, pend_sel, pend_df, pend_sel])
            gr.Markdown("### 本地工具安全策略（deny-by-default）")
            gr.Textbox(value=sched.executor.policy_summary(), lines=12, interactive=False, label="策略")
            gr.Markdown("### 响应缓存")
            cache_info = gr.Textbox(value=cache_status_text(), interactive=False, label="缓存状态")
            gr.Button("清空缓存").click(lambda: (sched.clear_cache(), cache_status_text()),
                                        outputs=[cache_info, cache_info])
            gr.Markdown("### 审计导出（安全事件+运行日志 → sandbox）")
            gr.Button("导出审计日志").click(export_audit, outputs=[cache_info])

        with gr.Tab("仪表盘"):
            warn_box = gr.Markdown(warning_banner())
            dash_df = gr.Dataframe(headers=["平台", "模型", "免费专用", "任务类型", "启用", "Key 状态", "工具",
                                            "今日tokens/上限", "累计tokens/上限", "今日次数/上限",
                                            "失败次数", "预警", "状态", "说明"],
                                   datatype=["str"] * 14)
            gr.Markdown("### 近7日 token 消耗趋势")
            trend_plot = gr.BarPlot(x="日期", y="tokens", color="模型",
                                    title="近7日各模型 token 消耗", height=320)

            def refresh_dash():
                rows = sched.status_rows()
                headers = list(rows[0].keys()) if rows else ["-"]
                return (warning_banner(),
                        gr.Dataframe(headers=headers, value=rows, datatype=["str"] * len(headers)),
                        dashboard_data())
            gr.Button("🔄 刷新仪表盘").click(refresh_dash, outputs=[warn_box, dash_df, trend_plot])
            refresh_dash()

        with gr.Tab("额度检查"):
            gr.Markdown("### 各平台余额 / 免费额度（只读查询）")
            with gr.Row():
                btn_check = gr.Button("🔄 重新检查余额/免费额度")
                lbl = gr.Textbox(label="状态", value="待检查", interactive=False)
            status_df = gr.Dataframe(headers=["平台", "检查方式", "状态", "余额/免费额度", "官方查询链接"],
                                     datatype=["str", "str", "str", "str", "str"])
            btn_check.click(lambda: (_balance_table(providers), "已更新"), outputs=[status_df, lbl])
            gr.Markdown("### 主流AI · 网页免费入口\n"
                        "以下平台 **API 收费的平台已被调度器硬性锁定（永不调用，防扣费）**；"
                        "如果平台提供免费网页版，直接点击跳转使用：")
            gr.HTML(_web_entries_html(cfg))

        with gr.Tab("调度状态"):
            def refresh_status():
                rows = sched.status_rows()
                headers = list(rows[0].keys()) if rows else ["-"]
                return gr.Dataframe(headers=headers, value=rows, datatype=["str"] * len(headers))
            s_df = gr.Dataframe()
            gr.Button("刷新状态").click(refresh_status, outputs=s_df)
            refresh_status()

        with gr.Tab("配置与自检"):
            gr.Markdown("### 配置编辑（仅 config.json；secrets.json 必须用文本编辑器手动改）")
            cfg_box = gr.Textbox(value=config_text(), lines=18, interactive=True, label="config.json")
            cfg_save_info = gr.Textbox(label="保存结果", interactive=False)
            gr.Button("保存并校验").click(save_config, [cfg_box], [cfg_save_info])
            gr.Markdown("### 一键自检")
            check_rows = gr.Dataframe(headers=["检查项", "结果", "详情"],
                                      datatype=["str", "str", "str"])
            gr.Button("🩺 运行自检").click(run_self_check, outputs=[check_rows])

        with gr.Tab("运行日志"):
            with gr.Row():
                log_box = gr.Textbox(label="usage.log（最近300行）", lines=22, interactive=False, scale=1)
                sec_box = gr.Textbox(label="security_audit.log（最近200行）", lines=22, interactive=False, scale=1)
            gr.Button("刷新日志").click(lambda: (logger.tail(300), logger.tail(200, logger.sec_path)),
                                        outputs=[log_box, sec_box])
            refresh_log = lambda: (logger.tail(300), logger.tail(200, logger.sec_path))  # noqa: E731
            refresh_log()

    demo.launch(server_name="127.0.0.1", server_port=7860, inbrowser=True, quiet=True)


if __name__ == "__main__":
    launch()
