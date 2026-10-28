# -*- coding: utf-8 -*-
"""第二轮新增功能测试：
 R1 任务类型路由（code 任务选支持者）
 R2 任务类型无匹配 → AllExhausted
 R3 ask() 单次纯文本调用
 P1 make_plan 拆解步骤（mock plan JSON）
 P2 plan 顺序执行完成（写文件）
 P3 plan 断点续跑（重载 plans.json 继续）
 C1 scan_project 项目扫描工具
 C2 diff_preview 文件对比工具
 M1 MCP initialize + tools/list
 M2 MCP tools/call 过安全层（越权拒绝）
 S1 受限脚本禁网络/危险导入
 S2 受限脚本正常执行
 S3 受限脚本禁 subprocess
"""
import os
import sys
import json
import tempfile
import subprocess
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mock_server import MockServer  # noqa: E402
from logger import UsageLogger  # noqa: E402
from scheduler import Scheduler, AllExhausted  # noqa: E402
from planner import Planner  # noqa: E402
from test_extra import _provider, _use, _env, _ex, _sched  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _sched_with_tasktypes(tmpdir, providers, cfg_extra=None):
    """构造调度器并在 Provider 上直接指定 task_types。"""
    cfg = {"scheduler": {"strategy": "weighted", "strict_free_only": True,
                         "pre_check_balance": True}, "tool_policy": _env(tmpdir)[2]}
    cfg.update(cfg_extra or {})
    return Scheduler(providers, os.path.join(tmpdir, "state.json"), cfg,
                     UsageLogger(os.path.join(tmpdir, "logs")))


def test_r1_task_routing(mock, tmpdir):
    _use(mock, {"mock-a": {"kind": "ok"}, "mock-b": {"kind": "ok"}})
    pa = _provider("a", "mock-a", task_types=["chat"])
    pb = _provider("b", "mock-b", task_types=["chat", "code"])
    pa.base_url = pb.base_url = mock.base_url
    s = _sched_with_tasktypes(tmpdir, [pa, pb])
    r = s.chat([{"role": "user", "content": "帮我写代码"}], task_type="code")
    assert r.ok and r.provider == "b", f"R1 fail: 应选支持code的b: {r.provider}"
    print("R1 任务类型路由 OK")


def test_r2_no_match(mock, tmpdir):
    _use(mock, {"mock-a": {"kind": "ok"}})
    pa = _provider("a", "mock-a", task_types=["chat"])
    pa.base_url = mock.base_url
    s = _sched_with_tasktypes(tmpdir, [pa])
    try:
        s.chat([{"role": "user", "content": "看图"}], task_type="vision")
        assert False, "R2 fail: 应抛出 AllExhausted"
    except AllExhausted as e:
        assert "不支持任务类型" in str(e), f"R2 fail: {e}"
    print("R2 无匹配任务类型 OK")


def test_r3_ask(mock, tmpdir):
    _use(mock, {"mock-a": {"kind": "ok"}})
    pa = _provider("a", "mock-a", task_types=["chat", "planning"])
    pa.base_url = mock.base_url
    s = _sched_with_tasktypes(tmpdir, [pa])
    r = s.ask([{"role": "user", "content": "只问一句"}], task_type="planning", system="你只需回复OK")
    assert r.ok and r.reply, f"R3 fail: {r}"
    print("R3 ask 单次调用 OK")


def _plan_provider(mock, tmpdir, steps):
    sandbox = _env(tmpdir)[1]
    steps = json.loads(json.dumps(steps).replace("SANDBOX_PLACEHOLDER", sandbox.replace("\\", "/")))
    _use(mock, {"mock-p": {"kind": "plan", "steps": steps}})
    p = _provider("p", "mock-p", task_types=["chat", "planning"])
    p.base_url = mock.base_url
    s = _sched_with_tasktypes(tmpdir, [p])
    pl = Planner(s, UsageLogger(os.path.join(tmpdir, "logs")),
                 os.path.join(tmpdir, "plans.json"), executor=s.executor)
    return s, pl, sandbox


def test_p1_make_plan(mock, tmpdir):
    steps = [
        {"description": "创建输出文件", "tool": "write_file",
         "args": {"path": "SANDBOX_PLACEHOLDER/plan_out.txt", "content": "plan done"}},
        {"description": "创建第二个文件", "tool": "write_file",
         "args": {"path": "SANDBOX_PLACEHOLDER/plan_second.txt", "content": "second"}},
        {"description": "非法工具会被过滤", "tool": "delete_everything", "args": {}}]
    _, pl, _ = _plan_provider(mock, tmpdir, steps)
    plan = pl.make_plan("测试计划")
    assert len(plan.steps) == 2, f"P1 fail: 非法工具应被过滤: {plan.steps}"
    assert plan.steps[0]["tool"] == "write_file", f"P1 fail: {plan.steps}"
    print("P1 make_plan 拆解 OK")


def test_p2_plan_run(mock, tmpdir):
    steps = [
        {"description": "创建输出文件", "tool": "write_file",
         "args": {"path": "SANDBOX_PLACEHOLDER/plan_out.txt", "content": "plan done"}},
        {"description": "创建第二个文件", "tool": "write_file",
         "args": {"path": "SANDBOX_PLACEHOLDER/plan_second.txt", "content": "second"}}]
    _, pl, sandbox = _plan_provider(mock, tmpdir, steps)
    plan = pl.make_plan("执行测试")
    logs = pl.run_all(plan)
    target = os.path.join(sandbox, "plan_out.txt")
    assert os.path.exists(target), "P2 fail: 文件未生成"
    with open(target, "r", encoding="utf-8") as f:
        assert f.read() == "plan done", "P2 fail: 文件内容不对"
    assert os.path.exists(os.path.join(sandbox, "plan_second.txt")), "P2 fail: 第二步未执行"
    assert plan.done, f"P2 fail: 计划未完成: {logs}"
    print("P2 plan 顺序执行 OK")


def test_p3_plan_resume(mock, tmpdir):
    steps = [
        {"description": "第一步", "tool": "write_file",
         "args": {"path": "SANDBOX_PLACEHOLDER/step1.txt", "content": "one"}},
        {"description": "第二步", "tool": "write_file",
         "args": {"path": "SANDBOX_PLACEHOLDER/step2.txt", "content": "two"}}]
    _, pl, sandbox = _plan_provider(mock, tmpdir, steps)
    plan = pl.make_plan("断点续跑测试")
    r1 = pl.execute_next(plan)
    assert os.path.exists(os.path.join(sandbox, "step1.txt")), "P3 fail: 第一步未执行"
    assert not plan.done
    # 模拟重启：新调度器+新Planner（同一 plans_path）
    from config import Provider
    p = _provider("p", "mock-p", task_types=["chat", "planning"])
    p.base_url = mock.base_url
    s2 = _sched_with_tasktypes(tmpdir, [p])
    pl2 = Planner(s2, UsageLogger(os.path.join(tmpdir, "logs")),
                  os.path.join(tmpdir, "plans.json"), executor=s2.executor)
    plan2 = pl2.get(plan.id)
    assert plan2 is not None and plan2.current_index == 1, f"P3 fail: 重载后进度丢失: {plan2}"
    logs = pl2.run_all(plan2)
    assert os.path.exists(os.path.join(sandbox, "step2.txt")), "P3 fail: 续跑第二步未执行"
    assert plan2.done, f"P3 fail: {logs}"
    print("P3 plan 断点续跑 OK")


def test_c1_scan_project(mock, tmpdir):
    ex = _ex(tmpdir)
    read_dir, _, _ = _env(tmpdir)
    os.makedirs(os.path.join(read_dir, "pkg"), exist_ok=True)
    with open(os.path.join(read_dir, "a.py"), "w", encoding="utf-8") as f:
        f.write("def foo():\n    pass\nclass Bar:\n    pass\nimport os\n")
    with open(os.path.join(read_dir, "pkg", "b.md"), "w", encoding="utf-8") as f:
        f.write("hi")
    r = ex.scan_project(read_dir)
    assert r.ok, f"C1 fail: {r.content}"
    assert "a.py" in r.content and "function:1" in r.content and "class:1" in r.content, f"C1 fail: {r.content[:300]}"
    r2 = ex.scan_project(os.path.join(tmpdir, "elsewhere"))
    assert not r2.ok, "C1 fail: 越界扫描应拒绝"
    print("C1 scan_project OK")


def test_c2_diff_preview(mock, tmpdir):
    ex = _ex(tmpdir)
    read_dir, _, _ = _env(tmpdir)
    a = os.path.join(read_dir, "a.txt")
    b = os.path.join(read_dir, "b.txt")
    with open(a, "w", encoding="utf-8") as f:
        f.write("line1\nline2\nline3\n")
    with open(b, "w", encoding="utf-8") as f:
        f.write("line1\nline3\nline4\n")
    r = ex.diff_preview(a, b)
    assert r.ok, f"C2 fail: {r.content}"
    assert "-line2" in r.content and "+line4" in r.content, f"C2 fail: {r.content}"
    print("C2 diff_preview OK")


def _mcp_proc(tmpdir):
    read_dir, sandbox, _ = _env(tmpdir)
    pdir = os.path.join(tmpdir, "private")
    os.makedirs(pdir, exist_ok=True)
    with open(os.path.join(pdir, "state.json"), "w", encoding="utf-8") as f:
        f.write("{}")
    cfg_path = os.path.join(tmpdir, "mcp_cfg.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump({"private_dir": pdir, "log_dir": os.path.join(tmpdir, "logs"),
                   "tool_policy": {"read_dirs": [read_dir], "write_dirs": [sandbox],
                                   "script_dirs": [sandbox], "cwd": read_dir}}, f)
    proc = subprocess.Popen(
        [sys.executable, "-X", "utf8", "-u", os.path.join(BASE_DIR, "mcp_server.py"),
         "--config", cfg_path],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", cwd=BASE_DIR)
    return proc, read_dir, pdir


def test_m1_mcp_list(mock, tmpdir):
    proc, _, _ = _mcp_proc(tmpdir)
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                 "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                            "clientInfo": {"name": "test", "version": "0"}}}) + "\n")
    proc.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
    proc.stdin.write('{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')
    proc.stdin.close()
    out = proc.stdout.read()
    proc.wait(timeout=30)
    init = json.loads(out.splitlines()[0])
    assert init.get("result", {}).get("protocolVersion") == "2024-11-05", f"M1 fail: {out[:200]}"
    for line in out.splitlines():
        msg = json.loads(line)
        if msg.get("id") == 2:
            names = [t["name"] for t in msg["result"]["tools"]]
            assert "read_file" in names and "scan_project" in names and "diff_preview" in names, f"M1 fail: {names}"
    print("M1 MCP initialize/tools/list OK")


def test_m2_mcp_call(mock, tmpdir):
    proc, read_dir, pdir = _mcp_proc(tmpdir)
    a_txt = os.path.join(read_dir, "hello.txt")
    with open(a_txt, "w", encoding="utf-8") as f:
        f.write("mcp 内容 hello")
    proc.stdin.write('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
    proc.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                 "params": {"name": "read_file",
                                            "arguments": {"path": a_txt}}}) + "\n")
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                 "params": {"name": "read_file",
                                            "arguments": {"path": os.path.join(pdir, "state.json")}}}) + "\n")
    proc.stdin.close()
    out = proc.stdout.read()
    proc.wait(timeout=30)
    got = {}
    for line in out.splitlines():
        msg = json.loads(line)
        if msg.get("id") in (3, 4):
            got[msg["id"]] = msg["result"]
    r3 = got.get(3, {})
    assert not r3.get("isError") and "mcp 内容 hello" in r3["content"][0]["text"], f"M2 fail: {r3}"
    r4 = got.get(4, {})
    assert r4.get("isError") and "拒绝" in r4["content"][0]["text"], f"M2 fail: 越权应被拒: {r4}"
    print("M2 MCP tools/call 安全层 OK")


def _script_ex(tmpdir, policy_extra=None):
    read_dir, write_dir, pol = _env(tmpdir)
    pol.update({"tool_policies": {"run_script": "auto"}})
    pol.update(policy_extra or {})
    return ToolExecutor(pol, UsageLogger(os.path.join(tmpdir, "logs")))


from local_tools import ToolExecutor  # noqa: E402


def test_s1_restrict_network(mock, tmpdir):
    ex = _script_ex(tmpdir)
    _, sandbox, _ = _env(tmpdir)
    p = os.path.join(sandbox, "net.py")
    with open(p, "w", encoding="utf-8") as f:
        f.write("import socket\ns = socket.socket()\nprint('reachable')\n")
    r = ex.run_script(p)
    assert not r.ok and "sandbox" in r.content, f"S1 fail: {r.content[:300]}"
    print("S1 受限脚本禁网络 OK")


def test_s2_restrict_ok(mock, tmpdir):
    ex = _script_ex(tmpdir)
    _, sandbox, _ = _env(tmpdir)
    p = os.path.join(sandbox, "ok.py")
    with open(p, "w", encoding="utf-8") as f:
        f.write("import math\nprint('hello 沙箱', math.sqrt(4))\n")
    r = ex.run_script(p)
    assert r.ok and "hello 沙箱" in r.content, f"S2 fail: {r.content[:300]}"
    print("S2 受限脚本正常执行 OK")


def test_s3_restrict_subprocess(mock, tmpdir):
    ex = _script_ex(tmpdir)
    _, sandbox, _ = _env(tmpdir)
    p = os.path.join(sandbox, "sub.py")
    with open(p, "w", encoding="utf-8") as f:
        f.write("import subprocess\nsubprocess.run(['dir'])\nprint('done')\n")
    r = ex.run_script(p)
    assert not r.ok and "sandbox" in r.content, f"S3 fail: {r.content[:300]}"
    print("S3 受限脚本禁 subprocess OK")


def test_s4_restrict_os(mock, tmpdir):
    ex = _script_ex(tmpdir)
    _, sandbox, _ = _env(tmpdir)
    p = os.path.join(sandbox, "osexec.py")
    with open(p, "w", encoding="utf-8") as f:
        f.write("import os\nos.system('echo pwned')\nprint('should not reach')\n")
    r = ex.run_script(p)
    assert not r.ok and "sandbox" in r.content, f"S4 fail: {r.content[:300]}"
    p2 = os.path.join(sandbox, "osrm.py")
    with open(p2, "w", encoding="utf-8") as f:
        f.write("import os\nos.remove('somefile.txt')\nprint('should not reach')\n")
    r2 = ex.run_script(p2)
    assert not r2.ok and "sandbox" in r2.content, f"S4 fail: {r2.content[:300]}"
    print("S4 受限脚本禁危险OS操作 OK")


def run_all():
    mock = MockServer()
    mock.start()
    passed = True
    tests = [test_r1_task_routing, test_r2_no_match, test_r3_ask,
             test_p1_make_plan, test_p2_plan_run, test_p3_plan_resume,
             test_c1_scan_project, test_c2_diff_preview,
             test_m1_mcp_list, test_m2_mcp_call,
             test_s1_restrict_network, test_s2_restrict_ok, test_s3_restrict_subprocess,
             test_s4_restrict_os]
    for t in tests:
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                t(mock, tmpdir)
            except Exception:
                passed = False
                print(f"✗ {t.__name__} 失败:")
                traceback.print_exc()
    mock.stop()
    print("\n" + ("✅ 第二轮新增功能测试全部通过" if passed else "❌ 第二轮新增功能测试存在失败"))
    return passed


if __name__ == "__main__":
    run_all()
