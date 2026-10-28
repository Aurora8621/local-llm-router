# -*- coding: utf-8 -*-
"""第三轮加固测试：API Key 状态校验 + 错误码分类/冷却细化
 K1 Key 状态分类（已配置/未填写/模板占位/含非ASCII）
 K2 候选只保留已配置平台（空/占位/非ASCII 不入选）
 K3 全部未配置 → AllExhausted 明确提示，且未配置平台不计失败次数
 K4 仅已配置平台发起真实请求，占位平台不被调用
 K5 状态行含 Key 状态列，未配置平台状态文案正确
 K6 429 子码分类：limit_requests/RateQuota→rate，insufficient_quota/FreeTierOnly→quota，401→auth
 K7 chat 路径：速率限流走短冷却（默认 60s）
 K8 ask 路径：额度不足走长冷却（provider.cooldown_seconds）
 K9 错误摘要保留 code/type/message，不被整体截断丢失定性子码
"""
import os
import sys
import time
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mock_server import MockServer  # noqa: E402
from scheduler import Scheduler, AllExhausted  # noqa: E402
from config import Provider  # noqa: E402
from test_extra import _provider, _use, _sched  # noqa: E402


class _FakeExc(Exception):
    """模拟 openai SDK 异常：带 status_code / body / code 结构化字段。"""

    def __init__(self, status=None, body=None, code=None, message=""):
        super().__init__(message)
        self.status_code = status
        self.body = body
        self.code = code


def test_k1_key_status(mock, tmpdir):
    cases = {
        "": "empty",
        "   ": "empty",
        "sk-abc123XYZ": "configured",
        "填入智谱API Key": "placeholder",
        "填入百炼API Key": "placeholder",
        "your-api-key": "placeholder",
        "YOUR_KEY_HERE": "placeholder",
        "abc密钥中文": "non_ascii",
    }
    for key, expect in cases.items():
        p = Provider({"name": "x", "enabled": True, "free_only": True,
                      "api_key": key, "base_url": "x", "model": "m"})
        assert p.key_status == expect, f"K1 fail: {key!r} -> {p.key_status}，期望 {expect}"
    print("K1 Key 状态分类 OK")


def test_k2_eligible_only_configured(mock, tmpdir):
    _use(mock, {"mock-ok": {"kind": "ok"}})
    ok = _provider("ok", "mock-ok")
    ok.base_url = mock.base_url
    empty = _provider("e1", "mock-e1", api_key="")
    ph = _provider("e2", "mock-e2", api_key="填入智谱API Key")
    na = _provider("e3", "mock-e3", api_key="abc密钥")
    s = _sched(tmpdir, [ok, empty, ph, na])
    names = [p.name for p in s._eligible(0, "chat")]
    assert names == ["ok"], f"K2 fail: 候选应只含已配置平台: {names}"
    print("K2 候选过滤未配置 Key OK")


def test_k3_all_unconfigured(mock, tmpdir):
    ps = [_provider("e1", "m1", api_key=""),
          _provider("e2", "m2", api_key="填入X"),
          _provider("e3", "m3", api_key="abc密钥")]
    s = _sched(tmpdir, ps)
    try:
        s.chat([{"role": "user", "content": "你好"}], task_type="chat")
        assert False, "K3 fail: 应抛出 AllExhausted"
    except AllExhausted as e:
        assert "未配置 API Key" in str(e), f"K3 fail: {e}"
    for p in ps:
        assert s._health(p.name)["fails"] == 0, "K3 fail: 未配置平台不应累计失败次数"
    print("K3 全未配置提示 + 不计失败 OK")


def test_k4_only_configured_called(mock, tmpdir):
    _use(mock, {"mock-ok": {"kind": "ok"}})
    ok = _provider("ok", "mock-ok")
    ok.base_url = mock.base_url
    ph = _provider("e2", "mock-ph", api_key="填入X")
    s = _sched(tmpdir, [ok, ph])
    r = s.chat([{"role": "user", "content": "hi"}], task_type="chat")
    assert r.ok and r.provider == "ok", f"K4 fail: {r}"
    assert mock.counts.get("mock-ok", 0) == 1, f"K4 fail: {mock.counts}"
    assert "mock-ph" not in mock.counts, "K4 fail: 占位平台不应被发起请求"
    print("K4 仅已配置平台发起请求 OK")


def test_k5_status_rows(mock, tmpdir):
    ok = _provider("ok", "mock-ok")
    ph = _provider("e2", "mock-ph", api_key="填入X")
    s = _sched(tmpdir, [ok, ph])
    rows = s.status_rows()
    assert "Key 状态" in rows[0], "K5 fail: 状态行缺少 Key 状态列"
    by = {r["平台"]: r for r in rows}
    assert by["ok"]["Key 状态"] == "已配置"
    assert by["e2"]["Key 状态"] == "模板占位"
    assert "未配置" in by["e2"]["状态"], f"K5 fail: 未配置状态文案: {by['e2']['状态']}"
    print("K5 状态行 Key 状态列 OK")


def test_k6_classify_subcodes(mock, tmpdir):
    cases = [
        (429, {"error": {"type": "limit_requests", "code": "limit_requests",
                         "message": "You have exceeded your current request limit."}}, "rate"),
        (429, {"error": {"type": "Throttling.RateQuota", "code": "Throttling.RateQuota",
                         "message": "Requests rate limit exceeded."}}, "rate"),
        (429, {"error": {"type": "insufficient_quota", "code": "insufficient_quota",
                         "message": "Insufficient Quota"}}, "quota"),
        (429, {"error": {"code": "AllocationQuota.FreeTierOnly",
                         "message": "The free tier of the model has been exhausted."}}, "quota"),
        (401, {"error": {"code": "invalid_api_key", "message": "Invalid API key"}}, "auth"),
        (500, {"error": {"message": "server boom"}}, "other"),
    ]
    for status, body, expect in cases:
        exc = _FakeExc(status, body, None, body.get("error", {}).get("message", ""))
        got = Scheduler._classify_error(exc)
        assert got == expect, f"K6 fail: status={status} body={body} -> {got}，期望 {expect}"
    print("K6 429 子错误码分类 OK")


def test_k7_chat_rate_short_cooldown(mock, tmpdir):
    _use(mock, {"mock-rate": {"kind": "rate"}})
    rp = _provider("rate", "mock-rate")
    rp.base_url = mock.base_url
    sr = _sched(tmpdir, [rp])
    try:
        sr.chat([{"role": "user", "content": "hi"}], task_type="chat")
        assert False, "K7 fail: rate 平台应失败并抛 AllExhausted"
    except AllExhausted:
        pass
    remain = sr.state["cooldowns"]["rate"] - time.time()
    assert 50 <= remain <= 65, f"K7 fail: 速率限流冷却应≈60s，实际剩余 {remain:.0f}s"
    print("K7 chat 速率限流短冷却 OK")


def test_k8_ask_quota_long_cooldown(mock, tmpdir):
    _use(mock, {"mock-quota": {"kind": "quota"}})
    qp = _provider("quota", "mock-quota")
    qp.base_url = mock.base_url
    sq = _sched(tmpdir, [qp])
    try:
        sq.ask([{"role": "user", "content": "hi"}], task_type="chat")
        assert False, "K8 fail: quota 平台应失败并抛 AllExhausted"
    except AllExhausted:
        pass
    remain = sq.state["cooldowns"]["quota"] - time.time()
    # provider.cooldown_seconds 测试默认 30s，明显短于全局默认 300s，验证额度类走长冷却配置
    assert 20 <= remain <= 35, f"K8 fail: 额度不足冷却应≈{qp.cooldown_seconds}s，实际剩余 {remain:.0f}s"
    print("K8 ask 额度不足长冷却 OK")


def test_k9_error_brief_keeps_codes(mock, tmpdir):
    exc = _FakeExc(429, {"error": {"type": "limit_requests", "code": "limit_requests",
                                   "message": "You have exceeded your current request limit."}},
                   None, "You have exceeded your current request limit. For details, see: https://help.al")
    brief = Scheduler._error_brief(exc)
    assert "code=limit_requests" in brief, f"K9 fail: 丢失 code: {brief}"
    assert "type=limit_requests" in brief, f"K9 fail: 丢失 type: {brief}"
    assert "message=" in brief, f"K9 fail: 丢失 message: {brief}"
    exc2 = _FakeExc(500, None, None, "server boom 服务端异常")
    brief2 = Scheduler._error_brief(exc2)
    assert "server boom" in brief2, f"K9 fail: 无结构化 body 时应兜底异常字符串: {brief2}"
    print("K9 错误摘要保留子错误码 OK")


def run_all():
    mock = MockServer()
    mock.start()
    passed = True
    tests = [test_k1_key_status, test_k2_eligible_only_configured,
             test_k3_all_unconfigured, test_k4_only_configured_called,
             test_k5_status_rows, test_k6_classify_subcodes,
             test_k7_chat_rate_short_cooldown, test_k8_ask_quota_long_cooldown,
             test_k9_error_brief_keeps_codes]
    for t in tests:
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                t(mock, tmpdir)
            except Exception:
                passed = False
                print(f"✗ {t.__name__} 失败:")
                traceback.print_exc()
    mock.stop()
    print("\n" + ("✅ 第三轮 Key 状态校验测试全部通过" if passed else "❌ 第三轮 Key 状态校验测试存在失败"))
    return passed


if __name__ == "__main__":
    run_all()
