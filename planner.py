# -*- coding: utf-8 -*-
"""Plan 任务拆解：复杂任务 → 步骤清单 → 顺序执行（支持断点续跑）。

- make_plan(task)：让模型把任务拆成 JSON 步骤（容错解析，仅保留合法工具）
- execute_next(plan)：执行下一步；approval 策略的工具会停下等待批准
- approve_step / reject_step：人工批准/拒绝某步骤（经 execute_approved，重跑全部安全校验）
- 持久化 plans.json（私密目录），最多保留20个计划，支持跨重启续跑
"""
import os
import json
import re
import time

from scheduler import TOOL_SCHEMAS

PLAN_SYSTEM = (
    "你是本地任务规划器。把用户的任务拆成可执行的本地工具步骤。\n"
    "可用工具: list_directory, read_file, search_local_text, preview_csv, lint_code, "
    "scan_project, diff_preview, write_file, run_command, run_script\n"
    "规则: 1) 只输出一个 JSON 数组，不要任何额外解释；"
    "2) 每步格式 {\"description\": \"做什么\", \"tool\": \"工具名\", \"args\": {参数}}；"
    "3) 参数必须与工具要求一致；4) 步骤数 1-8，串行且相互独立；"
    "5) 不要包含删除/移动/重命名等本系统不提供的操作。"
)


class Plan:
    def __init__(self, plan_id, task, steps, created=None):
        self.id = plan_id
        self.task = task
        self.steps = steps or []
        self.results = {}
        self.status = "pending"  # pending / running / done / failed / rejected
        self.created = created or time.time()

    @property
    def current_index(self):
        for i, s in enumerate(self.steps):
            if s["id"] not in self.results:
                return i
        return len(self.steps)

    @property
    def done(self):
        return self.current_index >= len(self.steps)

    def to_dict(self):
        return {"id": self.id, "task": self.task, "steps": self.steps,
                "results": self.results, "status": self.status, "created": self.created}

    @classmethod
    def from_dict(cls, d):
        p = cls(d["id"], d["task"], d.get("steps", []), d.get("created"))
        p.results = {int(k): v for k, v in (d.get("results") or {}).items()}
        p.status = d.get("status", "pending")
        return p


class Planner:
    def __init__(self, scheduler, logger, plans_path, executor=None, task_type="planning"):
        self.sched = scheduler
        self.logger = logger
        self.plans_path = plans_path
        self.executor = executor or scheduler.executor
        self.task_type = task_type
        self._tool_names = {s["function"]["name"] for s in TOOL_SCHEMAS}

    # ---------- 持久化 ----------
    def _load_all(self):
        try:
            with open(self.plans_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_all(self, store):
        os.makedirs(os.path.dirname(self.plans_path), exist_ok=True)
        tmp = self.plans_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(store, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.plans_path)

    def list_plans(self):
        return [Plan.from_dict(d) for d in self._load_all().values()]

    def get(self, plan_id):
        d = self._load_all().get(plan_id)
        return Plan.from_dict(d) if d else None

    def _put(self, plan):
        store = self._load_all()
        store[plan.id] = plan.to_dict()
        if len(store) > 20:
            for k in list(store.keys())[:-20]:
                store.pop(k, None)
        self._save_all(store)

    # ---------- 生成 ----------
    @staticmethod
    def _extract_steps(text):
        text = (text or "").strip()
        m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if m:
            text = m.group(1).strip()
        if not text.startswith("["):
            start, end = text.find("["), text.rfind("]")
            if start >= 0 and end > start:
                text = text[start:end + 1]
            else:
                start, end = text.find("{"), text.rfind("}")
                if start >= 0 and end > start:
                    text = "[" + text[start:end + 1] + "]"
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = []
            for m in re.finditer(r"\{[^{}]*\}", text):
                try:
                    data.append(json.loads(m.group(0)))
                except json.JSONDecodeError:
                    continue
        if not isinstance(data, list):
            data = [data]
        return data

    def make_plan(self, task: str) -> Plan:
        prompt = f"请把下面的任务拆成步骤清单（只输出 JSON 数组）:\n\n{task}"
        res = self.sched.ask([{"role": "user", "content": prompt}],
                             task_type=self.task_type, system=PLAN_SYSTEM)
        raw = self._extract_steps(res.reply)
        steps = []
        for i, item in enumerate(raw, 1):
            if not isinstance(item, dict):
                continue
            tool = str(item.get("tool", "")).strip()
            if tool not in self._tool_names:
                continue
            args = item.get("args")
            if not isinstance(args, dict):
                args = {}
            desc = str(item.get("description") or item.get("desc") or f"步骤{i}: {tool}")
            steps.append({"id": i, "description": desc, "tool": tool, "args": args})
        if not steps:
            raise ValueError(f"无法解析出有效步骤（模型回复: {res.reply[:200]}）")
        plan = Plan(f"plan-{int(time.time() * 1000) % 1000000:06d}", task, steps)
        self._put(plan)
        self.logger.log("INFO", f"生成计划 {plan.id} ({len(steps)}步): {task[:60]}")
        return plan

    # ---------- 执行 ----------
    def execute_next(self, plan: Plan) -> dict:
        if plan.done:
            plan.status = "done"
            self._put(plan)
            return {"done": True, "message": "计划已完成"}
        idx = plan.current_index
        step = plan.steps[idx]
        plan.status = "running"
        self._put(plan)
        result = self.executor.execute(step["tool"], step["args"])
        if result.needs_approval:
            return {"step": step, "needs_approval": True,
                    "message": f"步骤{step['id']}需要批准: {step['description']}\n{result.content}\n"
                               f"（在GUI「计划任务」页签点「✅ 批准当前步骤」，或命令行使用 /plan-approve {plan.id} {step['id']}）"}
        plan.results[step["id"]] = {
            "ok": result.ok, "content": result.content[:2000],
            "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}
        if not result.ok:
            plan.status = "failed"
        self._put(plan)
        return {"step": step, "ok": result.ok, "content": result.content,
                "done": plan.done, "message": f"步骤{step['id']}执行完成"}

    def approve_step(self, plan_id, step_id=None) -> dict:
        plan = self.get(plan_id)
        if not plan:
            return {"ok": False, "message": f"计划 {plan_id} 不存在"}
        if step_id is None:
            step_id = plan.current_index + 1
        step = next((s for s in plan.steps if s["id"] == int(step_id)), None)
        if not step:
            return {"ok": False, "message": f"步骤{step_id}不存在"}
        result = self.executor.execute_approved(step["tool"], step["args"])
        plan.results[step["id"]] = {
            "ok": result.ok, "content": result.content[:2000],
            "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}
        if not result.ok:
            plan.status = "failed"
        self._put(plan)
        self.logger.log("INFO", f"计划 {plan_id} 步骤{step_id} 已批准执行")
        return {"ok": result.ok, "step": step, "content": result.content,
                "message": f"步骤{step_id}已执行"}

    def reject_step(self, plan_id, step_id=None) -> dict:
        plan = self.get(plan_id)
        if not plan:
            return {"ok": False, "message": f"计划 {plan_id} 不存在"}
        if step_id is None:
            step_id = plan.current_index + 1
        step = next((s for s in plan.steps if s["id"] == int(step_id)), None)
        if not step:
            return {"ok": False, "message": f"步骤{step_id}不存在"}
        plan.results[step["id"]] = {"ok": False, "content": "[用户拒绝执行此步骤]",
                                    "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}
        plan.status = "rejected"
        self._put(plan)
        self.logger.log("INFO", f"计划 {plan_id} 步骤{step_id} 被拒绝")
        return {"ok": True, "message": f"步骤{step_id}已标记为拒绝，计划中止"}

    def run_all(self, plan: Plan) -> list:
        logs = []
        while not plan.done:
            r = self.execute_next(plan)
            if r.get("needs_approval"):
                logs.append(r["message"])
                break
            logs.append(f"[{'OK' if r['ok'] else '失败'}] 步骤{r['step']['id']}: "
                        f"{r['step']['description']}\n{r.get('content', '')[:500]}")
            if not r.get("ok"):
                logs.append(f"步骤{r['step']['id']}未成功，计划中止，不再执行后续步骤。")
                break
            if r.get("done"):
                break
        if plan.done:
            plan.status = "done"
            self._put(plan)
        return logs

    def summary(self, plan_id) -> str:
        plan = self.get(plan_id)
        if not plan:
            return "计划不存在"
        lines = [f"计划 {plan.id}: {plan.task}",
                 f"状态: {plan.status} | 进度: {plan.current_index}/{len(plan.steps)}"]
        for s in plan.steps:
            r = plan.results.get(s["id"])
            if r and r.get("ok"):
                mark = "✓"
            elif r:
                mark = "✗"
            elif s["id"] == plan.current_index + 1:
                mark = "▶"
            else:
                mark = "·"
            lines.append(f"  {mark} [{s['id']}] {s['description']}")
        return "\n".join(lines)
