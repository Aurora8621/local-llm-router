# -*- coding: utf-8 -*-
"""调度逻辑验证（本地Mock，无需真实API Key）。

覆盖：
 T1 正常调用：命中可用模型并返回
 T2 额度不足自动切换：A额度不足(429 insufficient_quota) → 自动切B成功
 T3 限流冷却：A持续限流 → 冷却期内不再尝试A，切B
 T4 全部不可用：全部额度不足 → AllExhausted，且明确未调用付费模型
 T5 本地硬上限：今日token上限用尽后不再调用该模型（即使API仍可用）
 T6 free_only 硬锁：free_only=false 的模型绝不被调度
 T7 鉴权失败停用：401 → 该模型被停用并切换
 T8 上下文超窗拒绝：输入超窗口时跳过该模型
 T9 余额接口解析：deepseek/moonshot/siliconflow 三类接口解析
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
from balance_checker import check_provider_balance


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
    }
    d.update(kw)
    return Provider(d)


def _use(mock, behaviors: dict):
    """切换 Mock 行为并清零调用计数（保证用例隔离）。"""
    mock.behaviors.clear()
    mock.behaviors.update(behaviors)
    mock.counts.clear()


def _make_sched(tmpdir, providers, strategy="balance_first"):
    state_path = os.path.join(tmpdir, "state.json")
    log_dir = os.path.join(tmpdir, "logs")
    cfg = {"scheduler": {"strategy": strategy, "strict_free_only": True,
                         "pre_check_balance": True, "max_attempts_per_request": 6}}
    return Scheduler(providers, state_path, cfg, UsageLogger(log_dir))


def _msg(text="你好"):
    return [{"role": "user", "content": text}]


def test_t1_basic(mock, tmpdir):
    _use(mock, {"mock-a": {"kind": "ok"}})
    p = _provider("a", "mock-a")
    p.base_url = mock.base_url
    s = _make_sched(tmpdir, [p])
    r = s.chat(_msg("测试"))
    assert r.ok and r.provider == "a" and "mock-a" in r.reply, f"T1 fail: {r}"
    assert r.tokens == 15
    print("T1 正常调用 OK")


def test_t2_switch(mock, tmpdir):
    _use(mock, {"mock-a": {"kind": "quota"}, "mock-b": {"kind": "ok"}})
    pa = _provider("a", "mock-a", priority=1)
    pb = _provider("b", "mock-b", priority=2)
    pa.base_url = pb.base_url = mock.base_url
    s = _make_sched(tmpdir, [pa, pb])
    r = s.chat(_msg("切换测试"))
    assert r.ok and r.provider == "b" and r.switched, f"T2 fail: {r}"
    assert "mock-b" in r.reply
    assert mock.counts.get("mock-a", 0) == 1
    print("T2 额度不足自动切换 OK")


def test_t3_cooldown(mock, tmpdir):
    _use(mock, {"mock-a": {"kind": "rate"}, "mock-b": {"kind": "ok"}})
    pa = _provider("a", "mock-a", cooldown_seconds=3600)
    pb = _provider("b", "mock-b", priority=2)
    pa.base_url = pb.base_url = mock.base_url
    s = _make_sched(tmpdir, [pa, pb])
    r = s.chat(_msg("限流"))
    assert r.ok and r.provider == "b"
    # 冷却期内 a 被排除；即使把 b 也停用，绝不应再次调用 a
    s.providers[1].enabled = False
    try:
        s.chat(_msg("再试"))
        assert False, "T3 fail: 应抛 AllExhausted"
    except AllExhausted:
        pass
    assert mock.counts.get("mock-a", 0) == 1, "冷却期内不应再次调用 a"
    print("T3 限流冷却 OK")


def test_t4_all_exhausted(mock, tmpdir):
    _use(mock, {"mock-a": {"kind": "quota"}, "mock-b": {"kind": "quota"}})
    pa = _provider("a", "mock-a", priority=1)
    pb = _provider("b", "mock-b", priority=2)
    pa.base_url = pb.base_url = mock.base_url
    s = _make_sched(tmpdir, [pa, pb])
    try:
        s.chat(_msg("全部额度不足"))
        assert False, "T4 fail: 应抛 AllExhausted"
    except AllExhausted as e:
        msg = str(e)
        assert "未调用任何付费模型" in msg, f"T4 fail: {msg}"
    print("T4 全部不可用→明确失败 OK")


def test_t5_hard_cap(mock, tmpdir):
    _use(mock, {"mock-a": {"kind": "ok"}})
    # 上限=20：首次估算约16可通过（mock每次回传15），累计后第二次必被本地拦截
    p = _provider("a", "mock-a", caps={"max_daily_tokens": 20, "max_calls_per_day": 10000})
    p.base_url = mock.base_url
    s = _make_sched(tmpdir, [p])
    r1 = s.chat(_msg("第一次"))
    assert r1.ok
    try:
        s.chat(_msg("第二次"))
        assert False, "T5 fail: 本地上限应阻断第二次调用"
    except AllExhausted as e:
        assert "上限" in str(e)
    assert mock.counts.get("mock-a", 0) == 1, "超本地上限后不应再发出请求"
    print("T5 本地token硬上限 OK")


def test_t6_free_only_lock(mock, tmpdir):
    _use(mock, {"mock-paid": {"kind": "ok"}})
    p = _provider("paid", "mock-paid", free_only=False)
    p.base_url = mock.base_url
    s = _make_sched(tmpdir, [p])
    try:
        s.chat(_msg("付费模型"))
        assert False, "T6 fail: free_only=false 不应被调用"
    except AllExhausted:
        pass
    assert mock.counts.get("mock-paid", 0) == 0, "付费模型不应收到任何请求"
    print("T6 free_only 硬锁 OK")


def test_t7_auth_disable(mock, tmpdir):
    _use(mock, {"mock-a": {"kind": "auth"}, "mock-b": {"kind": "ok"}})
    pa = _provider("a", "mock-a", priority=1)
    pb = _provider("b", "mock-b", priority=2)
    pa.base_url = pb.base_url = mock.base_url
    s = _make_sched(tmpdir, [pa, pb])
    r = s.chat(_msg("鉴权失败"))
    assert r.ok and r.provider == "b"
    assert s.state["disabled"].get("a"), "a 应被停用"
    s.providers[1].enabled = False
    try:
        s.chat(_msg("再试"))
        assert False, "T7 fail"
    except AllExhausted:
        pass
    assert mock.counts.get("mock-a", 0) == 1, "停用后不应再调用 a"
    print("T7 鉴权失败停用并切换 OK")


def test_t8_context_window(mock, tmpdir):
    _use(mock, {"mock-a": {"kind": "ok"}})
    p = _provider("a", "mock-a", context_window=64)
    p.base_url = mock.base_url
    s = _make_sched(tmpdir, [p])
    try:
        s.chat(_msg("长" * 1000))
        assert False, "T8 fail: 超窗口应被拒绝"
    except AllExhausted:
        pass
    assert mock.counts.get("mock-a", 0) == 0, "超窗口不应发出请求"
    print("T8 上下文超窗拒绝 OK")


def test_t9_balance_parsers(mock, tmpdir):
    _use(mock, {})
    pd = _provider("deepseek", "x", balance_check={"type": "deepseek", "require_positive": True})
    pd.base_url = mock.base_url
    pm = _provider("moonshot", "x", balance_check={"type": "moonshot", "require_positive": True})
    pm.base_url = mock.base_url
    ps = _provider("siliconflow", "x", balance_check={"type": "siliconflow", "require_positive": False})
    ps.base_url = mock.base_url
    rd = check_provider_balance(pd)
    rm = check_provider_balance(pm)
    rs = check_provider_balance(ps)
    assert rd["status"] == "ok" and rd["granted"] == 9.9, f"deepseek: {rd}"
    assert rm["status"] == "ok" and abs(rm["balance"] - 8.8) < 1e-6, f"moonshot: {rm}"
    assert rs["status"] == "ok" and abs(rs["total_balance"] - 88.88) < 1e-6, f"siliconflow: {rs}"
    print("T9 三类余额接口解析 OK")


def run_all():
    mock = MockServer()
    mock.start()
    passed = True
    tests = [test_t1_basic, test_t2_switch, test_t3_cooldown, test_t4_all_exhausted,
             test_t5_hard_cap, test_t6_free_only_lock, test_t7_auth_disable,
             test_t8_context_window, test_t9_balance_parsers]
    for t in tests:
        with tempfile.TemporaryDirectory() as tmpdir:  # 每个用例独立状态文件
            try:
                t(mock, tmpdir)
            except Exception:
                passed = False
                print(f"✗ {t.__name__} 失败:")
                traceback.print_exc()
    mock.stop()
    print("\n" + ("✅ 全部测试通过" if passed else "❌ 存在失败用例"))
    return passed


if __name__ == "__main__":
    run_all()
