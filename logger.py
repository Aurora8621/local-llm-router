# -*- coding: utf-8 -*-
"""本地日志模块：分级日志 + 安全审计日志 + 按大小轮转。只写本地文件，不对外上报。
- usage.log          : 常规运行日志（INFO/WARN/ERROR/TOOL）
- security_audit.log : 安全事件专档（越权访问/危险命令/敏感文件拦截等），供审计导出
"""
import os
import json
import datetime
import threading


class UsageLogger:
    def __init__(self, log_dir: str, max_bytes: int = 1 << 20, backup_count: int = 3):
        self.log_dir = log_dir
        self.max_bytes = int(max_bytes)
        self.backup_count = int(backup_count)
        self.path = os.path.join(log_dir, "usage.log")
        self.sec_path = os.path.join(log_dir, "security_audit.log")
        self._lock = threading.Lock()
        os.makedirs(log_dir, exist_ok=True)

    def _rotate(self, path: str) -> None:
        try:
            if not os.path.exists(path):
                return
            for i in range(self.backup_count, 0, -1):
                src = f"{path}.{i - 1}" if i - 1 > 0 else path
                dst = f"{path}.{i}"
                if os.path.exists(src):
                    os.replace(src, dst)
        except OSError:
            pass

    def _write(self, path: str, line: str) -> None:
        with self._lock:
            try:
                if os.path.exists(path) and os.path.getsize(path) > self.max_bytes:
                    self._rotate(path)
                with open(path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError:
                pass  # 日志失败不影响主流程

    def log(self, level: str, message: str, extra: dict | None = None) -> None:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{ts} | {level.upper():6s} | {message}"
        if extra:
            line += " | " + json.dumps(extra, ensure_ascii=False)
        self._write(self.path, line)

    def security(self, message: str, extra: dict | None = None) -> None:
        """安全事件：同时写入常规日志与安全审计专档。"""
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{ts} | SECURITY | {message}"
        if extra:
            line += " | " + json.dumps(extra, ensure_ascii=False)
        self._write(self.path, line)
        self._write(self.sec_path, line)

    def tail(self, n: int = 200, path: str | None = None) -> str:
        try:
            target = path or self.path
            with open(target, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            return "".join(lines[-n:])
        except OSError:
            return "(暂无日志)"
