# -*- coding: utf-8 -*-
"""新增功能测试：
 E1 文件类型黑名单（.zip/.exe 拒绝，.txt 通过）
 E2 工具策略 deny（write_file=deny 拒绝）
 E3 工具策略 approval（write_file=approval 需批准，execute_approved 可执行）
 E4 search_local_text（白名单内检索；越界拒绝）
 E5 preview_csv（预览行数控制）
 E6 lint_code（语法错误报告；合法文件通过）
 E7 软额度预警（≥80% 状态标记）
 E8 累计token硬上限
 E9 加权策略 + 失败惩罚排序
 E10 响应缓存（二次请求命中，不重复调用API）
 E11 daily_log 用量日志
 E12 安全审计日志（越权访问写入 security_audit.log）
 E13 run_command 审批模式（批准后执行）
"""
import os
import sys
import json
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mock_server import MockServer
from logger import UsageLogger
from scheduler import Scheduler, AllExhausted
from config import Provider
from local_tools import ToolExecutor


def _provider(name, model, free_only=True, **kw):
    d = {
        "name": name, "display_name": name, "enabled": kw.pop("enabled", True),
        "free_only": free_only, "api_key": "test-key", "base_url": "PLACEHOLDER",
        "model": model, "context_window": kw.pop("context_window", 32768),
        "max_output_tokens": kw.pop("max_output_tokens", 2048),
        "caps": kw.pop("caps", {"max_daily_tokens": 1000000, "max_calls_per_day": 10000,
                                "max_total_tokens": 1 << 60}),
        "balance_check": kw.pop("balance_check", {"type": "manual"}),
        "cooldown_seconds": kw.pop("cooldown_seconds", 30),
        "priority": kw.pop("priority", 1),
        "tools": kw.pop("tools", True),
    }
    d.update(kw)
    return Provider(d)


def _use(mock, behaviors: dict):
    mock.behaviors.clear()
    mock.behaviors.update(behaviors)
    mock.counts.clear()


def _env(tmpdir):
    read_dir = os.path.join(tmpdir, "read")
    write_dir = os.path.join(tmpdir, "sandbox")
    os.makedirs(read_dir, exist_ok=True)
    os.makedirs(write_dir, exist_ok=True)
    policy = {"read_dirs": [read_dir], "write_dirs": [write_dir], "script_dirs": [write_dir],
              "cwd": read_dir, "max_tool_iterations": 3}
    return read_dir, write_dir, policy


def _ex(tmpdir, policy=None, private=None):
    read_dir, write_dir, pol = _env(tmpdir)
    pol.update(policy or {})
    return ToolExecutor(pol, UsageLogger(os.path.join(tmpdir, "logs")), private_dirs=private)


def _sched(tmpdir, providers, cfg_extra=None, state_seed=None):
    cfg = {"scheduler": {"strategy": "weighted", "strict_free_only": True,
                         "pre_check_balance": True}, "tool_policy": _env(tmpdir)[2]}
    cfg.update(cfg_extra or {})
    s = Scheduler(providers, os.path.join(tmpdir, "state.json"), cfg,
                  UsageLogger(os.path.join(tmpdir, "logs")))
    if state_seed:
        s.state.update(state_seed)
        s._save_state()
    return s


def test_e1_ext_blacklist(mock, tmpdir):
    ex = _ex(tmpdir)
    read_dir, _, _ = _env(tmpdir)
    for name, content in (("a.zip", b"PK\x03\x04"), ("b.exe", b"MZ"), ("c.txt", "文本")):
        p = os.path.join(read_dir, name)
        with open(p, "wb" if isinstance(content, bytes) else "w",
                  encoding=None if isinstance(content, bytes) else "utf-8") as f:
            f.write(content)
    assert not ex.read_file(os.path.join(read_dir, "a.zip")).ok, "E1: .zip 应拒绝"
    assert not ex.read_file(os.path.join(read_dir, "b.exe")).ok, "E1: .exe 应拒绝"
    r = ex.read_file(os.path.join(read_dir, "c.txt"))
    assert r.ok and "文本" in r.content, f"E1: .txt 应通过: {r.content}"
    print("E1 文件类型黑名单 OK")


def test_e2_policy_deny(mock, tmpdir):
    ex = _ex(tmpdir, {"tool_policies": {"write_file": "deny"}})
    _, write_dir, _ = _env(tmpdir)
    r = ex.write_file(os.path.join(write_dir, "x.txt"), "hi")
    assert not r.ok and "deny" in r.reason, f"E2 fail: {r.content}"
    print("E2 工具策略 deny OK")


def test_e3_policy_approval(mock, tmpdir):
    ex = _ex(tmpdir, {"tool_policies": {"write_file": "approval"}})
    _, write_dir, _ = _env(tmpdir)
    target = os.path.join(write_dir, "x.txt")
    r = ex.write_file(target, "hi")
    assert r.needs_approval, "E3 fail: 应进入待批准"
    r2 = ex.execute_approved("write_file", {"path": target, "content": "hi"})
    assert r2.ok and os.path.exists(target), f"E3 fail: 批准后应写入: {r2.content}"
    print("E3 工具策略 approval OK")


def test_e4_search(mock, tmpdir):
    ex = _ex(tmpdir)
    read_dir, _, _ = _env(tmpdir)
    with open(os.path.join(read_dir, "a.txt"), "w", encoding="utf-8") as f:
        f.write("第一行 hello keyword\n第二行 x")
    with open(os.path.join(read_dir, "b.md"), "w", encoding="utf-8") as f:
        f.write("keyword 在这里")
    r = ex.search_local_text("keyword")
    assert r.ok and "a.txt:1" in r.content and "b.md" in r.content, f"E4 fail: {r.content}"
    r2 = ex.search_local_text("hello", os.path.join(tmpdir, "elsewhere"))
    assert not r2.ok, "E4 fail: 越界搜索应拒绝"
    r3 = ex.search_local_text("")
    assert not r3.ok, "E4 fail: 空关键词应拒绝"
    print("E4 本地文本检索 OK")


def test_e5_preview_csv(mock, tmpdir):
    ex = _ex(tmpdir)
    read_dir, _, _ = _env(tmpdir)
    csv_path = os.path.join(read_dir, "data.csv")
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("name,age\nA,1\nB,2\nC,3\n")
    r = ex.preview_csv(csv_path, rows=2)
    assert r.ok and "name" in r.content and "A" in r.content and "仅预览前2行" in r.content, f"E5 fail: {r.content}"
    print("E5 CSV 预览 OK")


def test_e6_lint(mock, tmpdir):
    ex = _ex(tmpdir)
    read_dir, _, _ = _env(tmpdir)
    bad = os.path.join(read_dir, "bad.py")
    with open(bad, "w", encoding="utf-8") as f:
        f.write("def f(:\n    pass")
    good = os.path.join(read_dir, "good.py")
    with open(good, "w", encoding="utf-8") as f:
        f.write("x = 1\nprint(x)")
    r1 = ex.lint_code(bad)
    assert not r1.ok and "语法错误" in r1.content, f"E6 fail: {r1.content}"
    r2 = ex.lint_code(good)
    assert r2.ok and "语法检查通过" in r2.content, f"E6 fail: {r2.content}"
    print("E6 静态语法检查 OK")


def test_e7_soft_warning(mock, tmpdir):
    p = _provider("a", "mock-a", caps={"max_daily_tokens": 1000, "max_calls_per_day": 100,
                                       "max_total_tokens": 1 << 60})
    p.base_url = mock.base_url
    s = _sched(tmpdir, [p], cfg_extra={"scheduler": {"warn_threshold_percent": 0.8}})
    s.state["usage"]["a"] = {"date": s._today(), "daily_tokens": 850, "calls": 1, "total_tokens": 850}
    rows = s.status_rows()
    assert rows[0]["预警"] == "⚠️ ≥80%", f"E7 fail: {rows[0]}"
    assert s._warn_crossed(p)
    print("E7 软额度预警 OK")


def test_e8_cumulative_cap(mock, tmpdir):
    _use(mock, {"mock-a": {"kind": "ok"}})
    p = _provider("a", "mock-a", caps={"max_daily_tokens": 1 << 60, "max_calls_per_day": 100,
                                       "max_total_tokens": 20})
    p.base_url = mock.base_url
    s = _sched(tmpdir, [p])
    r1 = s.chat([{"role": "user", "content": "第一次"}])
    assert r1.ok, f"E8 fail: {r1}"
    try:
        s.chat([{"role": "user", "content": "第二次"}])
        assert False, "E8 fail: 累计上限应阻断"
    except AllExhausted as e:
        assert "累计" in str(e), f"E8 fail: {e}"
    print("E8 累计token硬上限 OK")


def test_e9_weighted_penalty(mock, tmpdir):
    _use(mock, {"mock-a": {"kind": "ok"}, "mock-b": {"kind": "ok"}})
    pa = _provider("a", "mock-a", priority=1)
    pb = _provider("b", "mock-b", priority=2)
    pa.base_url = pb.base_url = mock.base_url
    s = _sched(tmpdir, [pa, pb])
    s.state["health"]["a"] = {"fails": 5, "last": "rate"}
    s._save_state()
    r = s.chat([{"role": "user", "content": "测试加权"}])
    assert r.ok and r.provider == "b", f"E9 fail: 失败多的模型应被降权: {r.provider}"
    print("E9 加权策略+失败惩罚 OK")


def test_e10_cache(mock, tmpdir):
    _use(mock, {"mock-c": {"kind": "ok"}})
    p = _provider("c", "mock-c", tools=False)
    p.base_url = mock.base_url
    s = _sched(tmpdir, [p], cfg_extra={"cache": {"enabled": True, "dir": os.path.join(tmpdir, "cache")}})
    r1 = s.chat([{"role": "user", "content": "缓存测试"}])
    assert r1.ok and not r1.cached and mock.counts.get("mock-c", 0) == 1
    r2 = s.chat([{"role": "user", "content": "缓存测试"}])
    assert r2.ok and r2.cached, f"E10 fail: 应命中缓存: {r2.cached}"
    assert mock.counts.get("mock-c", 0) == 1, "E10 fail: 缓存命中不应再调API"
    # daily_log 记录
    today = s._today()
    assert s.state["daily_log"].get(today, {}).get("c", 0) == 15, "E11 fail: daily_log 应记录"
    print("E10 响应缓存 OK / E11 daily_log OK")


def test_e12_security_log(mock, tmpdir):
    ex = _ex(tmpdir, private=[os.path.join(tmpdir, "private")])
    logger = ex.logger
    private_f = os.path.join(tmpdir, "private", "secrets.json")
    os.makedirs(os.path.dirname(private_f), exist_ok=True)
    with open(private_f, "w", encoding="utf-8") as f:
        f.write("{}")
    ex.read_file(private_f)
    ex.run_command("curl http://x")
    sec = ""
    try:
        with open(logger.sec_path, "r", encoding="utf-8") as f:
            sec = f.read()
    except OSError:
        pass
    assert "read_file" in sec and "curl" in sec, f"E12 fail: 安全审计日志应记录拦截事件: {sec[:200]}"
    print("E12 安全审计日志 OK")


def test_e13_command_approval(mock, tmpdir):
    ex = _ex(tmpdir, {"tool_policies": {"run_command": "approval"}})
    r = ex.run_command("python --version")
    assert r.needs_approval, "E13 fail: 应进入待批准"
    r2 = ex.execute_approved("run_command", {"command": "python --version"})
    assert r2.ok and "Python" in r2.content, f"E13 fail: {r2.content}"
    print("E13 run_command 审批模式 OK")


def run_all():
    mock = MockServer()
    mock.start()
    passed = True
    tests = [test_e1_ext_blacklist, test_e2_policy_deny, test_e3_policy_approval,
             test_e4_search, test_e5_preview_csv, test_e6_lint, test_e7_soft_warning,
             test_e8_cumulative_cap, test_e9_weighted_penalty, test_e10_cache,
             test_e12_security_log, test_e13_command_approval]
    for t in tests:
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                t(mock, tmpdir)
            except Exception:
                passed = False
                print(f"✗ {t.__name__} 失败:")
                traceback.print_exc()
    mock.stop()
    print("\n" + ("✅ 新增功能测试全部通过" if passed else "❌ 新增功能测试存在失败"))
    return passed


if __name__ == "__main__":
    run_all()
