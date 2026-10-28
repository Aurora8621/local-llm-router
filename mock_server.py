# -*- coding: utf-8 -*-
"""本地 Mock 服务：模拟 OpenAI 兼容接口 + 三类余额接口，用于无真实Key时验证调度逻辑。

- POST /v1/chat/completions : 按 model 返回 成功 / 429额度不足 / 429限流 / 401鉴权失败 / 前N次成功后再失败
- GET  /user/balance          : DeepSeek 格式
- GET  /v1/users/me/balance   : Moonshot 格式
- GET  /v1/user/info          : SiliconFlow 格式
用法：
    from mock_server import MockServer
    srv = MockServer(behaviors={...})
    srv.start()   # 自动选空闲端口
    base_url = srv.base_url   # http://127.0.0.1:PORT/v1
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # 静默
        pass

    def _send(self, code: int, obj: dict):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/user/balance":
            self._send(200, {"is_available": True, "balance_infos": [
                {"currency": "CNY", "total_balance": "9.90",
                 "granted_balance": "9.90", "topped_up_balance": "0.00"}]})
        elif path == "/v1/users/me/balance":
            self._send(200, {"data": {"available_balance": 8.8,
                                      "voucher_balance": 8.8, "cash_balance": 0.0}})
        elif path == "/v1/user/info":
            self._send(200, {"code": 20000, "message": "OK", "status": True, "data": {
                "id": "mock", "name": "mock", "balance": "0.88",
                "totalBalance": "88.88", "chargeBalance": "88.00"}})
        else:
            self._send(404, {"error": {"message": "not found", "type": "invalid_request_error"}})

    def do_POST(self):  # noqa: N802
        path = self.path.split("?")[0]
        if not path.endswith("/chat/completions"):
            self._send(404, {"error": {"message": "not found", "type": "invalid_request_error"}})
            return
        try:
            body = self._read_json()
        except Exception:
            body = {}
        model = body.get("model", "unknown")
        behaviors = self.server.behaviors  # type: ignore[attr-defined]
        counts = self.server.counts  # type: ignore[attr-defined]
        counts[model] = counts.get(model, 0) + 1
        b = behaviors.get(model, {})
        kind = b.get("kind", "ok")
        if kind == "fail_after":
            n = int(b.get("n", 0))
            if counts[model] > n:
                kind = b.get("after", "quota")
            else:
                kind = "ok"
        if kind == "tool_read":
            # 模拟：第一次请求返回 read_file 工具调用，有 tool 结果后返回最终文本
            path = b.get("path", "F:/AI/local-llm-router/README.md")
            last = (body.get("messages") or [{}])[-1]
            if last.get("role") == "tool":
                content = str(last.get("content", ""))[:120]
                self._send(200, {
                    "id": f"chatcmpl-tools-{counts[model]}", "object": "chat.completion",
                    "model": model, "choices": [{"index": 0, "message": {
                        "role": "assistant", "content": f"[工具结果OK] 已收到: {content}"},
                        "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 8, "total_tokens": 28},
                })
            else:
                self._send(200, {
                    "id": f"chatcmpl-tools-{counts[model]}", "object": "chat.completion",
                    "model": model, "choices": [{"index": 0, "message": {
                        "role": "assistant", "content": "", "tool_calls": [
                            {"id": f"call_read_{counts[model]}", "type": "function",
                             "function": {"name": "read_file",
                                          "arguments": json.dumps({"path": path})}}]},
                        "finish_reason": "tool_calls"}],
                    "usage": {"prompt_tokens": 15, "completion_tokens": 5, "total_tokens": 20},
                })
        elif kind == "tool_loop":
            # 每次都返回工具调用（用于验证迭代上限）
            self._send(200, {
                "id": f"chatcmpl-loop-{counts[model]}", "object": "chat.completion",
                "model": model, "choices": [{"index": 0, "message": {
                    "role": "assistant", "content": "", "tool_calls": [
                        {"id": f"call_loop_{counts[model]}", "type": "function",
                         "function": {"name": "list_directory",
                                      "arguments": json.dumps({"path": "F:/AI"})}}]},
                    "finish_reason": "tool_calls"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            })
        elif kind == "tool_script":
            # 第一次调用 run_script（待批准），后续有 tool 结果则返回最终文本
            path = b.get("path", "F:/AI/local-llm-router/sandbox/demo.py")
            last = (body.get("messages") or [{}])[-1]
            if last.get("role") == "tool":
                content = str(last.get("content", ""))[:120]
                self._send(200, {
                    "id": f"chatcmpl-script-{counts[model]}", "object": "chat.completion",
                    "model": model, "choices": [{"index": 0, "message": {
                        "role": "assistant", "content": f"[脚本审批后结果] {content}"},
                        "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 8, "total_tokens": 28},
                })
            else:
                self._send(200, {
                    "id": f"chatcmpl-script-{counts[model]}", "object": "chat.completion",
                    "model": model, "choices": [{"index": 0, "message": {
                        "role": "assistant", "content": "", "tool_calls": [
                            {"id": f"call_script_{counts[model]}", "type": "function",
                             "function": {"name": "run_script",
                                          "arguments": json.dumps(
                                              {"path": path, "args": ""})}}]},
                        "finish_reason": "tool_calls"}],
                    "usage": {"prompt_tokens": 15, "completion_tokens": 5, "total_tokens": 20},
                })
        elif kind == "plan":
            # 返回纯 JSON 步骤数组（供 Planner 解析）
            steps = b.get("steps", [
                {"description": "创建计划输出文件", "tool": "write_file",
                 "args": {"path": "SANDBOX_PLACEHOLDER/plan_out.txt", "content": "plan done"}},
                {"description": "列出沙箱目录", "tool": "list_directory",
                 "args": {"path": "SANDBOX_PLACEHOLDER"}}])
            self._send(200, {
                "id": f"chatcmpl-plan-{counts[model]}", "object": "chat.completion",
                "model": model, "choices": [{"index": 0, "message": {
                    "role": "assistant", "content": json.dumps(steps, ensure_ascii=False)},
                    "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 30, "completion_tokens": 10, "total_tokens": 40},
            })
        elif kind == "ok":
            prompt = ""
            msgs = body.get("messages", [])
            if msgs:
                prompt = str(msgs[-1].get("content", ""))[:120]
            self._send(200, {
                "id": f"chatcmpl-mock-{counts[model]}", "object": "chat.completion",
                "model": model, "choices": [{"index": 0, "message": {
                    "role": "assistant", "content": f"[{model}](第{counts[model]}次) 回复: {prompt}"},
                    "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            })
        elif kind == "quota":
            self._send(429, {"error": {"message": "Insufficient Quota",
                                       "type": "insufficient_quota", "code": "insufficient_quota"}})
        elif kind == "rate":
            self._send(429, {"error": {"message": "Rate limit reached",
                                       "type": "rate_limit", "code": "rate_limit"}})
        elif kind == "auth":
            self._send(401, {"error": {"message": "Invalid API key",
                                       "type": "authentication_error", "code": "invalid_api_key"}})
        else:
            self._send(500, {"error": {"message": "server boom", "type": "server_error"}})


class MockServer:
    def __init__(self, behaviors: dict | None = None):
        self.behaviors = behaviors or {}
        self.counts = {}
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.behaviors = self.behaviors  # type: ignore[attr-defined]
        self._httpd.counts = self.counts  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        port = self._httpd.server_address[1]
        return f"http://127.0.0.1:{port}/v1"

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()
