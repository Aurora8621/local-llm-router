# -*- coding: utf-8 -*-
"""MCP (Model Context Protocol) 本地服务器：stdio JSON-RPC。

让外部 MCP 客户端（Claude Desktop / CodeBuddy 等）以标准协议调用本工具集。
所有工具调用仍经过 ToolExecutor 安全层（目录白名单 / 私密目录硬排除 / 内容脱敏 / 审批策略）。

用法: python mcp_server.py [--config config.json]
协议: newline-delimited JSON over stdio
  → {"jsonrpc":"2.0","id":1,"method":"initialize",...}
  → {"jsonrpc":"2.0","method":"notifications/initialized"}
  → {"jsonrpc":"2.0","id":2,"method":"tools/list"}
  → {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{...}}}
"""
import json
import sys
import argparse

from config import load_config, resolve_paths
from logger import UsageLogger
from local_tools import ToolExecutor
from scheduler import TOOL_SCHEMAS

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "local-llm-scheduler-tools"
SERVER_VERSION = "2.0"


class McpServer:
    def __init__(self, cfg_path=None):
        cfg = load_config(cfg_path)
        paths = resolve_paths(cfg)
        self.logger = UsageLogger(paths["log_dir"])
        self.executor = ToolExecutor(
            cfg.get("tool_policy", {}) or {}, self.logger,
            private_dirs=[cfg.get("private_dir", "")] if cfg.get("private_dir") else None)
        self.tools = []
        for s in TOOL_SCHEMAS:
            f = s["function"]
            self.tools.append({"name": f["name"], "description": f["description"],
                               "inputSchema": f["parameters"]})

    def handle(self, msg: dict) -> list[str]:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return []
        method = msg.get("method")
        msg_id = msg.get("id")
        if method == "initialize":
            return [self._result(msg_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}})]
        if method in ("notifications/initialized", "initialized"):
            return []
        if method == "ping":
            return [self._result(msg_id, {})]
        if method == "tools/list":
            return [self._result(msg_id, {"tools": self.tools})]
        if method == "tools/call":
            params = msg.get("params", {}) or {}
            name = params.get("name", "")
            arguments = params.get("arguments", {}) or {}
            try:
                res = self.executor.execute(name, arguments)
            except Exception as e:  # noqa: BLE001
                self.logger.security(f"MCP tools/call 异常 {name}", {"err": str(e)[:160]})
                return [self._result(msg_id, {
                    "content": [{"type": "text", "text": f"执行异常: {e}"}], "isError": True})]
            if res.needs_approval:
                text = f"[需要人工批准] {res.content}"
            else:
                text = res.content
            return [self._result(msg_id, {
                "content": [{"type": "text", "text": text}], "isError": not res.ok})]
        return [self._result(msg_id, {
            "content": [{"type": "text", "text": f"未知方法 {method}"}], "isError": True})]

    @staticmethod
    def _result(msg_id, result) -> str:
        return json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result},
                          ensure_ascii=False)

    def run(self):
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            for out in self.handle(msg):
                sys.stdout.write(out + "\n")
                sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(description="本地MCP服务器（复用调度器安全工具层）")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    McpServer(args.config).run()


if __name__ == "__main__":
    main()
