# -*- coding: utf-8 -*-
"""本地工具安全执行器：模型通过 function calling 调用的安全封装。

安全设计（数据安全优先，deny-by-default）：
1. 目录白名单：仅 read_dirs 可读、write_dirs 可写、script_dirs 可运行脚本
2. 私密目录硬排除：C:\\Users\\YourName\\AI 等一律拒绝，即使被加进白名单也拒绝
3. 路径安全：realpath 解析防 .. 穿越与符号链接；敏感文件名（secrets.json/.env/私钥）拒绝
4. 文件类型控制：仅允许文本类扩展名；exe/dll/zip/图片/PDF 等一律拒绝
5. 内容安全：文件内容与命令输出先脱敏（API Key/私钥等）再回传模型；内容视为不可信输入
6. 执行安全：subprocess list 形式（无 shell 注入）、超时自动终止、输出截断、隐藏控制台窗口
7. 按工具策略：每个工具可为 auto（自动）/ approval（需人工批准）/ deny（禁用）；默认运行脚本需批准
8. 全程审计：常规调用进 usage.log；越权/拦截/危险命令等安全事件进 security_audit.log
"""
import os
import re
import sys
import csv
import ast
import io
import shlex
import shutil
import subprocess
import fnmatch
import datetime
import codebase

_MAX_ENTRIES = 200
_DEFAULT_READ_MAX_BYTES = 262144   # 256 KB
_DEFAULT_MAX_OUTPUT_CHARS = 20000

_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{16,}"),
    re.compile(r"(?i)api[_-]?key[\"'\s:=]+[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(?i)token[\"'\s:=]+[A-Za-z0-9_\-]{16,}"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----"),
]

_BLOCKED_NAME_PATTERNS = [
    "secrets.json", ".env", ".env.*", "id_rsa", "id_rsa.*", "id_ed25519", "id_ed25519.*",
    "*.pem", "*.key", "*.pfx", "*.p12", "*.crt", "*.jks", "credentials", "*.kdbx",
    "state.json", "usage.log", "security_audit.log", "sessions.json",
]

_DEFAULT_TEXT_EXT = {
    ".txt", ".md", ".py", ".json", ".csv", ".log", ".html", ".htm", ".xml", ".yaml",
    ".yml", ".ini", ".cfg", ".conf", ".toml", ".rst", ".sql", ".js", ".ts", ".css",
    ".c", ".cpp", ".h", ".java", ".go", ".rs", ".ipynb", ".bat", ".cmd", ".sh",
}

_DEFAULT_BLOCKED_EXT = {
    ".exe", ".dll", ".so", ".dylib", ".zip", ".rar", ".7z", ".gz", ".tar",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".pdf",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".mp4", ".mp3", ".avi", ".wav",
}

# 无扩展名但允许读取的已知文本文件名（白名单之外的无扩展名文件一律拒绝，防改名二进制）
_ALLOWED_NOEXT = {
    "README", "README.md", "LICENSE", "COPYING", "AUTHORS", "CHANGELOG", "NOTICE",
    "Makefile", "Dockerfile", "CMakeLists.txt", ".gitignore", ".gitattributes",
    ".dockerignore", ".editorconfig",
}

# 命令白名单：(命令, 参数前缀元组, 可执行文件覆盖)。不匹配即拒绝。
_ALLOWED_COMMANDS = [
    ("git", ("status",), None),
    ("git", ("log", "-5"), None),
    ("git", ("diff",), None),
    ("python", ("--version",), "sys.executable"),
    ("pip", ("list",), None),
    ("conda", ("env", "list"), None),
]

# 危险命令关键词（第二道防线，命中即拒绝）
_DENY_SUBSTRINGS = [
    "rm -rf", "rm -fr", "del /s", "del /f", "rd /s", "format ", "shutdown", "reboot",
    "taskkill", "reg ", "regedit", "icacls", "takeown", "net user", "net localgroup",
    "netsh", "curl ", "wget ", "invoke-webrequest", "certutil", "diskpart", "chkdsk",
    "mkfs", "> nul", "cmd /c", "powershell", "pip install", "conda install",
    "easy_install", "os.remove", "os.rmdir", "shutil.rmtree", "eval(", "exec(",
    "os.system", "subprocess", "socket", "requests.get", "urllib", "telnet ", "ssh ",
    "attrib +", "cacls",
]

_REDACTED = "[已脱敏]"

# 受限脚本执行引导代码：-I 隔离模式下禁用网络/子进程/动态库/危险OS操作/白名单外模块
_RESTRICT_BOOT = r'''
import sys as _s
try:
    _s.stdout.reconfigure(encoding="utf-8", errors="replace")
    _s.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
def _deny(*_a, **_k):
    raise RuntimeError("[sandbox] blocked operation: network/subprocess/dynamic-lib/dangerous-module")
try:
    _so = __import__("socket")
    _so.socket = _so.create_connection = _so.getaddrinfo = _deny
except Exception:
    pass
try:
    _sp = __import__("subprocess")
    _sp.Popen = _sp.run = _sp.call = _sp.check_output = _sp.check_call = _deny
except Exception:
    pass
try:
    _ct = __import__("ctypes")
    _ct.CDLL = _ct.WinDLL = _ct.PyDLL = _deny
except Exception:
    pass
# 加固 os 模块：即使脚本 import os，也禁用可造成命令执行/文件破坏的危险函数
# （os.path/os.listdir/os.makedirs 等安全函数仍可用；仅封禁 system/popen/exec*/spawn*/remove/rmdir 等）
try:
    _os = __import__("os")
    _OS_DANGER = ("system", "popen", "execv", "execve", "execvp", "execvpe", "execl",
                  "execlp", "execlpe", "spawnv", "spawnve", "spawnl", "spawnle",
                  "spawnlp", "spawnlpe", "spawnvpe", "remove", "unlink", "rmdir",
                  "removedirs", "rename", "replace", "truncate", "kill", "killpg",
                  "chmod", "chown", "lchown", "fchmod", "fchown", "setuid", "setgid",
                  "seteuid", "setegid", "fork", "forkpty", "startfile", "putenv",
                  "unsetenv", "chroot", "nice")
    for _fn in _OS_DANGER:
        if hasattr(_os, _fn):
            setattr(_os, _fn, _deny)
except Exception:
    pass
_WHITELIST = {"os","sys","builtins","math","json","re","pathlib","datetime","time",
              "collections","string","itertools","functools","random","statistics",
              "csv","io","difflib","textwrap","unicodedata","typing","dataclasses",
              "abc","enum","decimal","fractions","copy","hashlib","base64","binascii",
              "struct","tempfile","uuid","heapq","bisect","queue","threading"}
_b = __import__("builtins")
_orig_import = _b.__import__
_il = __import__("importlib")
_orig_module = _il.import_module
def _guarded_import(name, globals=None, locals=None, fromlist=None, level=0):
    if name.split(".")[0] not in _WHITELIST:
        raise RuntimeError("[sandbox] import blocked: " + name)
    return _orig_import(name, globals, locals, fromlist, level)
def _guarded_module(name, package=None):
    if name.split(".")[0] not in _WHITELIST:
        raise RuntimeError("[sandbox] import blocked: " + name)
    return _orig_module(name, package)
_b.__import__ = _guarded_import
_il.import_module = _guarded_module
del _b, _il, _s
'''

_DEFAULT_TOOL_POLICY = {
    "list_directory": "auto",
    "read_file": "auto",
    "search_local_text": "auto",
    "preview_csv": "auto",
    "lint_code": "auto",
    "scan_project": "auto",
    "diff_preview": "auto",
    "write_file": "auto",
    "run_command": "auto",
    "run_script": "approval",
}


def redact(text: str) -> str:
    if not text:
        return text
    out = text
    for pat in _SECRET_PATTERNS:
        out = pat.sub(_REDACTED, out)
    return out


_CODE_FENCE_RE = re.compile(r"```\s*([^\n]*)\n(.*?)```", re.DOTALL)


def save_code_blocks(text: str, out_dir: str) -> list[str]:
    """从文本中提取 ``` 代码块并保存到目录，返回保存的文件路径列表。"""
    saved = []
    os.makedirs(out_dir, exist_ok=True)
    for i, m in enumerate(_CODE_FENCE_RE.finditer(text or ""), start=1):
        lang = re.sub(r"[^A-Za-z0-9_+\-]", "", (m.group(1) or "txt").strip()) or "txt"
        code = m.group(2)
        if not code.strip():
            continue
        name = f"code_{i}.{lang}"
        path = os.path.join(out_dir, name)
        # 二次防护：净化后仍需确认路径未逃出 out_dir
        real_out = os.path.realpath(out_dir)
        real_path = os.path.realpath(path)
        if not (real_path == real_out or real_path.startswith(real_out + os.sep)):
            continue
        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(code)
            saved.append(path)
        except OSError:
            continue
    return saved


class ToolResult:
    def __init__(self, ok: bool, content: str = "", needs_approval: bool = False,
                 pending_op: dict | None = None, reason: str = ""):
        self.ok = ok
        self.content = content
        self.needs_approval = needs_approval
        self.pending_op = pending_op or {}
        self.reason = reason


class ToolExecutor:
    def __init__(self, policy: dict, logger, private_dirs: list[str] | None = None):
        self.policy = policy or {}
        self.logger = logger
        self.private_dirs = [self._real(p) for p in (private_dirs or []) if p]
        self.read_dirs = [self._real(p) for p in self.policy.get("read_dirs", [])]
        self.write_dirs = [self._real(p) for p in self.policy.get("write_dirs", [])]
        self.script_dirs = [self._real(p) for p in self.policy.get("script_dirs", [])]
        self.cwd = (self._real(self.policy.get("cwd", "")) or (self.read_dirs[0] if self.read_dirs else os.getcwd()))
        self.read_max_bytes = int(self.policy.get("read_file_max_bytes", _DEFAULT_READ_MAX_BYTES))
        self.max_output_chars = int(self.policy.get("max_output_chars", _DEFAULT_MAX_OUTPUT_CHARS))
        self.exec_timeout = int(self.policy.get("exec_timeout", 15))
        self.script_timeout = int(self.policy.get("script_timeout", 30))
        self.allowed_ext = set(self.policy.get("allowed_text_extensions") or _DEFAULT_TEXT_EXT)
        self.blocked_ext = set(self.policy.get("blocked_extensions") or _DEFAULT_BLOCKED_EXT)
        tool_policies = dict(self.policy.get("tool_policies") or {})
        tool_policies.setdefault("run_script", self.policy.get("run_script_policy", "approval"))
        self.tool_policies = tool_policies
        self.max_search_results = int(self.policy.get("max_search_results", 30))
        self.max_csv_rows = int(self.policy.get("max_csv_preview_rows", 20))
        self._create_dirs()

    # ---------- 路径/类型安全 ----------
    @staticmethod
    def _real(p: str) -> str:
        return os.path.realpath(os.path.abspath(os.path.expandvars(os.path.expanduser(str(p)))))

    def _within(self, p: str, roots: list[str]) -> bool:
        return any(p == r or p.startswith(r + os.sep) for r in roots)

    def _is_blocked_name(self, p: str) -> bool:
        base = os.path.basename(p)
        return any(fnmatch.fnmatch(base, pat) for pat in _BLOCKED_NAME_PATTERNS)

    def _ext_check(self, p: str) -> str | None:
        ext = os.path.splitext(p)[1].lower()
        if ext in self.blocked_ext:
            return f"禁止访问该文件类型({ext or '无扩展名'})"
        if ext:
            if ext not in self.allowed_ext:
                return f"仅允许文本类型文件，{ext} 已拒绝"
            return None
        # 无扩展名：默认拒绝（防改名后的二进制被读取），仅放行已知文本文件名与目录
        base = os.path.basename(p)
        if base in _ALLOWED_NOEXT:
            return None
        if os.path.isdir(p):
            return None
        return "拒绝无扩展名文件（仅允许已知文本文件名，如 README/Makefile；如需读取请改名加 .txt）"

    def _mode(self, tool: str) -> str:
        m = self.tool_policies.get(tool, _DEFAULT_TOOL_POLICY.get(tool, "auto"))
        return m if m in ("auto", "approval", "deny") else "auto"

    def _create_dirs(self):
        for d in self.write_dirs + self.script_dirs:
            try:
                os.makedirs(d, exist_ok=True)
            except OSError:
                pass

    def _guard_path(self, p: str, roots: list[str], need_exist: bool = True) -> str | None:
        real = self._real(p)
        if self._within(real, self.private_dirs):
            return "路径位于私密目录（API Key等敏感文件存放处），已拒绝访问"
        if not self._within(real, roots):
            return "路径不在白名单目录内，已拒绝访问"
        if self._is_blocked_name(real):
            return "敏感文件名（密钥/凭据类），已拒绝访问"
        ext_err = self._ext_check(real)
        if ext_err:
            return ext_err
        if need_exist and not os.path.exists(real):
            return "文件或目录不存在"
        return None

    def _log(self, tool: str, ok: bool, detail: str, extra=None):
        self.logger.log("TOOL", f"{'OK' if ok else 'DENY/FAIL'} {tool} {detail}",
                        {**(extra or {}), "tool": tool})

    def _security(self, tool: str, detail: str, extra=None):
        self.logger.security(f"拦截 {tool}: {detail}", {**(extra or {}), "tool": tool})

    # ---------- 工具实现 ----------
    def _list_impl(self, real: str) -> ToolResult:
        try:
            entries = os.listdir(real)
        except OSError as e:
            return ToolResult(False, f"列目录失败: {e}")
        entries.sort()
        lines = []
        for name in entries[:_MAX_ENTRIES]:
            full = os.path.join(real, name)
            try:
                st = os.stat(full)
                kind = "DIR " if os.path.isdir(full) else "FILE"
                size = st.st_size if os.path.isfile(full) else 0
                lines.append(f"{kind} {name}  {size}B")
            except OSError:
                lines.append(f"???? {name}")
        if len(entries) > _MAX_ENTRIES:
            lines.append(f"...(共{len(entries)}项，仅显示前{_MAX_ENTRIES}项)")
        return ToolResult(True, "\n".join(lines) or "(空目录)")

    def list_directory(self, path: str) -> ToolResult:
        err = self._guard_path(path, self.read_dirs, need_exist=True)
        if err:
            self._security("list_directory", path, {"err": err})
            return ToolResult(False, f"list_directory 被拒绝: {err}", reason=err)
        res = self._list_impl(self._real(path))
        if res.ok:
            self._log("list_directory", True, path)
        return res

    def _read_impl(self, real: str) -> ToolResult:
        if os.path.isdir(real):
            return ToolResult(False, "目标是一个目录，请用 list_directory")
        try:
            if os.path.getsize(real) > self.read_max_bytes:
                return ToolResult(False, f"文件过大({os.path.getsize(real)}B > {self.read_max_bytes}B)，已拒绝读取")
        except OSError as e:
            return ToolResult(False, f"读取失败: {e}")
        try:
            with open(real, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read(self.read_max_bytes + 1)
        except OSError as e:
            return ToolResult(False, f"读取失败: {e}")
        if "\x00" in raw[:8192]:
            return ToolResult(False, "疑似二进制文件，已拒绝读取（只支持文本）")
        if len(raw) > self.read_max_bytes:
            raw = raw[: self.read_max_bytes] + "\n...(文件过大已截断)"
        content = redact(raw)
        if len(content) > self.max_output_chars:
            content = content[: self.max_output_chars] + "\n...(内容过长已截断)"
        return ToolResult(True, content)

    def read_file(self, path: str) -> ToolResult:
        err = self._guard_path(path, self.read_dirs, need_exist=True)
        if err:
            self._security("read_file", path, {"err": err})
            return ToolResult(False, f"read_file 被拒绝: {err}", reason=err)
        res = self._read_impl(self._real(path))
        if res.ok:
            self._log("read_file", True, path, {"bytes": min(os.path.getsize(self._real(path)), self.read_max_bytes)})
        return res

    def _write_impl(self, real: str, content: str) -> ToolResult:
        if len(content.encode("utf-8", errors="replace")) > 1_048_576:
            return ToolResult(False, "写入内容过大(>1MB)，已拒绝")
        try:
            os.makedirs(os.path.dirname(real), exist_ok=True)
            with open(real, "w", encoding="utf-8", newline="") as f:
                f.write(content)
        except OSError as e:
            return ToolResult(False, f"写入失败: {e}")
        return ToolResult(True, f"已写入 {real}（{len(content)} 字符）")

    def write_file(self, path: str, content: str) -> ToolResult:
        err = self._guard_path(path, self.write_dirs, need_exist=False)
        if err:
            self._security("write_file", path, {"err": err})
            return ToolResult(False, f"write_file 被拒绝: {err}", reason=err)
        real = self._real(path)
        mode = self._mode("write_file")
        if mode == "deny":
            self._security("write_file", f"{real} 策略禁用")
            return ToolResult(False, "write_file 被策略禁用(deny)", reason="policy_deny")
        if mode == "approval":
            return ToolResult(True, f"写入待批准: {real}", needs_approval=True,
                              pending_op={"name": "write_file",
                                          "args": {"path": real, "content": content},
                                          "description": f"写入文件 {real}（{len(content)} 字符）"})
        res = self._write_impl(real, content)
        if res.ok:
            self._log("write_file", True, real, {"bytes": len(content.encode("utf-8", errors="replace"))})
        return res

    def _run(self, cmd_list: list[str], timeout: int) -> ToolResult:
        kwargs = {"capture_output": True, "text": True, "timeout": timeout,
                  "encoding": "utf-8", "errors": "replace", "cwd": self.cwd}
        if os.name == "nt":
            kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        try:
            proc = subprocess.run(cmd_list, **kwargs)
        except subprocess.TimeoutExpired:
            self._security("run_command", str(cmd_list), {"err": f"timeout>{timeout}s"})
            return ToolResult(False, f"命令执行超时({timeout}s)，已终止")
        except OSError as e:
            return ToolResult(False, f"命令执行失败: {e}")
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        out = redact(out)
        if len(out) > self.max_output_chars:
            out = out[: self.max_output_chars] + "\n...(输出过长已截断)"
        ok = proc.returncode == 0
        self._log("run_command", ok, str(cmd_list), {"code": proc.returncode, "out_len": len(out)})
        return ToolResult(ok, f"(退出码 {proc.returncode})\n{out}" if not ok else out)

    def _command_ok(self, command: str) -> tuple[bool, str, list[str] | None]:
        """返回 (是否允许, 拒绝原因, 可执行列表)。"""
        low = (command or "").lower()
        for d in _DENY_SUBSTRINGS:
            if d in low:
                return False, f"命令含危险关键词({d.strip()})", None
        try:
            parts = shlex.split(command or "")
        except ValueError as e:
            return False, f"命令解析失败: {e}", None
        if not parts:
            return False, "空命令", None
        cmd, args = parts[0], tuple(parts[1:])
        for allowed_cmd, prefix, exe_override in _ALLOWED_COMMANDS:
            if cmd == allowed_cmd and args[: len(prefix)] == prefix:
                exe = sys.executable if exe_override == "sys.executable" else shutil.which(cmd)
                if not exe:
                    return False, f"未找到可执行文件: {cmd}", None
                return True, "", [exe, *args]
        return False, f"命令不在白名单内 ({cmd} {args})", None

    def run_command(self, command: str) -> ToolResult:
        ok, reason, cmd_list = self._command_ok(command)
        if not ok:
            self._security("run_command", (command or "")[:120], {"err": reason})
            return ToolResult(False, f"run_command 被拒绝: {reason}", reason=reason)
        mode = self._mode("run_command")
        if mode == "deny":
            self._security("run_command", "策略禁用")
            return ToolResult(False, "run_command 被策略禁用(deny)", reason="policy_deny")
        if mode == "approval":
            return ToolResult(True, f"命令待批准: {command}", needs_approval=True,
                              pending_op={"name": "run_command", "args": {"command": command},
                                          "description": f"运行命令 {command}"})
        return self._run(cmd_list, self.exec_timeout)

    def _run_script_impl(self, real: str, extra: str) -> ToolResult:
        """受限执行：-I 隔离模式 + 引导代码禁用网络/子进程/动态库/危险模块。"""
        target = ("exec(compile(open(%r,'r',encoding='utf-8').read(), %r, 'exec'), "
                  "{'__name__':'__main__','__file__':%r})" % (real, real, real))
        code = _RESTRICT_BOOT + "\n" + target
        cmd = [sys.executable, "-I", "-B", "-c", code]
        if extra:
            cmd += shlex.split(extra)
        return self._run(cmd, self.script_timeout)

    def run_script(self, path: str, args: str = "") -> ToolResult:
        err = self._guard_path(path, self.script_dirs, need_exist=True)
        if err:
            self._security("run_script", path, {"err": err})
            return ToolResult(False, f"run_script 被拒绝: {err}", reason=err)
        real = self._real(path)
        if not real.endswith(".py"):
            return ToolResult(False, "仅允许运行 .py 脚本")
        args = (args or "").strip()
        if args and any(d in args.lower() for d in _DENY_SUBSTRINGS):
            self._security("run_script", f"{real} 参数含危险关键词")
            return ToolResult(False, "run_script 被拒绝: 参数含危险关键词", reason="dangerous_args")
        extra = ""
        if args:
            try:
                extra = " ".join(shlex.split(args))
            except ValueError as e:
                return ToolResult(False, f"参数解析失败: {e}")
        mode = self._mode("run_script")
        if mode == "deny":
            return ToolResult(False, "run_script 被策略禁用(deny)", reason="policy_deny")
        if mode == "approval":
            return ToolResult(True, f"脚本已就绪待批准: {real}", needs_approval=True,
                              pending_op={"name": "run_script",
                                          "args": {"path": real, "args": extra},
                                          "description": f"运行 Python 脚本 {real} 参数: {extra or '(无)'}"})
        return self._run_script_impl(real, extra)

    def execute_script_approved(self, path: str, args: str = "") -> ToolResult:
        err = self._guard_path(path, self.script_dirs, need_exist=True)
        if err:
            self._security("run_script", f"{path} 批准后仍越权", {"err": err})
            return ToolResult(False, f"run_script 被拒绝: {err}", reason=err)
        real = self._real(path)
        if not real.endswith(".py"):
            return ToolResult(False, "仅允许运行 .py 脚本")
        extra = (args or "").strip()
        if extra and any(d in extra.lower() for d in _DENY_SUBSTRINGS):
            return ToolResult(False, "run_script 被拒绝: 参数含危险关键词", reason="dangerous_args")
        return self._run_script_impl(real, extra)

    # ---------- 新增工具 ----------
    def search_local_text(self, query: str, path: str = "") -> ToolResult:
        query = (query or "").strip()
        if not query or len(query) > 200 or "\x00" in query:
            return ToolResult(False, "搜索关键词为空或非法")
        roots = [self._real(path)] if path else list(self.read_dirs)
        if path:
            err = self._guard_path(path, self.read_dirs, need_exist=True)
            if err:
                self._security("search_local_text", path, {"err": err})
                return ToolResult(False, f"search_local_text 被拒绝: {err}", reason=err)
        hits = []
        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames
                               if not self._within(self._real(os.path.join(dirpath, d)), self.private_dirs)]
                depth = len(os.path.relpath(dirpath, root).split(os.sep)) if os.path.relpath(dirpath, root) != "." else 0
                if depth > 4:
                    dirnames[:] = []
                    continue
                for name in sorted(filenames):
                    full = os.path.join(dirpath, name)
                    if self._guard_path(full, [root], need_exist=True):
                        continue
                    try:
                        if os.path.getsize(full) > 1_048_576:
                            continue
                        with open(full, "r", encoding="utf-8", errors="replace") as f:
                            for i, line in enumerate(f, 1):
                                if query.lower() in line.lower():
                                    rel = os.path.relpath(full, root)
                                    hits.append(f"{rel}:{i}: {line.strip()[:160]}")
                                    if len(hits) >= self.max_search_results:
                                        break
                    except OSError:
                        continue
                if len(hits) >= self.max_search_results:
                    break
            if len(hits) >= self.max_search_results:
                break
        content = "\n".join(hits) if hits else f"未找到包含「{query}」的内容"
        self._log("search_local_text", bool(hits), f"{query} -> {len(hits)}条")
        return ToolResult(True, content)

    def preview_csv(self, path: str, rows: int = 0) -> ToolResult:
        rows = max(1, min(int(rows or 0) or self.max_csv_rows, 100))
        err = self._guard_path(path, self.read_dirs, need_exist=True)
        if err:
            self._security("preview_csv", path, {"err": err})
            return ToolResult(False, f"preview_csv 被拒绝: {err}", reason=err)
        real = self._real(path)
        if not real.endswith(".csv"):
            return ToolResult(False, "仅支持 .csv 文件")
        try:
            if os.path.getsize(real) > 1_048_576:
                return ToolResult(False, "CSV 文件过大(>1MB)，请用 search_local_text 检索关键行")
        except OSError as e:
            return ToolResult(False, f"读取失败: {e}")
        try:
            with open(real, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
                reader = csv.reader(io.StringIO(f.read(1_048_576)))
                out_lines = []
                for idx, row in enumerate(reader):
                    if idx >= rows:
                        out_lines.append(f"...(仅预览前{rows}行)")
                        break
                    out_lines.append(" | ".join(str(c)[:40] for c in row[:20]))
        except OSError as e:
            return ToolResult(False, f"读取失败: {e}")
        self._log("preview_csv", True, real, {"rows": rows})
        return ToolResult(True, "\n".join(out_lines) or "(空CSV)")

    _RISKY_CODE = ["eval(", "exec(", "os.system", "subprocess", "socket", "pickle.loads",
                   "yaml.load(", "requests.get", "urllib", "shutil.rmtree", "os.remove"]

    def lint_code(self, path: str) -> ToolResult:
        err = self._guard_path(path, self.read_dirs, need_exist=True)
        if err:
            self._security("lint_code", path, {"err": err})
            return ToolResult(False, f"lint_code 被拒绝: {err}", reason=err)
        real = self._real(path)
        if not real.endswith(".py"):
            return ToolResult(False, "仅支持 .py 文件")
        try:
            if os.path.getsize(real) > 524_288:
                return ToolResult(False, "文件过大，跳过检查")
            with open(real, "r", encoding="utf-8", errors="replace") as f:
                src = f.read()
        except OSError as e:
            return ToolResult(False, f"读取失败: {e}")
        try:
            tree = ast.parse(src)
        except SyntaxError as e:
            return ToolResult(False, f"语法错误: 第{e.lineno}行 第{e.offset}列 {e.msg}")
        risky = [k for k in self._RISKY_CODE if k in src]
        lines = src.count("\n") + 1
        report = f"语法检查通过（ast.parse），共 {lines} 行"
        if risky:
            report += f"。⚠️ 含潜在危险调用: {', '.join(risky)}（仅提示，未执行）"
        self._log("lint_code", True, real, {"lines": lines, "risky": risky})
        return ToolResult(True, report)

    # ---------- 项目代码工具 ----------
    def scan_project(self, path: str) -> ToolResult:
        err = self._guard_path(path, self.read_dirs, need_exist=True)
        if err:
            self._security("scan_project", path, {"err": err})
            return ToolResult(False, f"scan_project 被拒绝: {err}", reason=err)
        real = self._real(path)
        if not os.path.isdir(real):
            return ToolResult(False, "目标不是目录，请用 list_directory/read_file")
        info = codebase.scan_project(real)
        syms = ", ".join(f"{k}:{v}" for k, v in info["symbols"].items()) or "无"
        head = f"项目 {info['root']}：{info['files']} 个文本文件，{info['dirs']} 个子目录\n符号统计: {syms}\n---文件树---\n"
        body = "\n".join(info["tree"]) or "(无文本文件)"
        content = head + body
        if len(content) > self.max_output_chars:
            content = content[: self.max_output_chars] + "\n...(已截断)"
        self._log("scan_project", True, real, info)
        return ToolResult(True, content)

    def diff_preview(self, path_a: str, path_b: str) -> ToolResult:
        for p in (path_a, path_b):
            err = self._guard_path(p, self.read_dirs, need_exist=True)
            if err:
                self._security("diff_preview", p, {"err": err})
                return ToolResult(False, f"diff_preview 被拒绝: {err}", reason=err)
        ra, rb = self._real(path_a), self._real(path_b)
        try:
            with open(ra, "r", encoding="utf-8", errors="replace") as f:
                a = f.read(self.read_max_bytes + 1)
            with open(rb, "r", encoding="utf-8", errors="replace") as f:
                b = f.read(self.read_max_bytes + 1)
        except OSError as e:
            return ToolResult(False, f"读取失败: {e}")
        if len(a) > self.read_max_bytes or len(b) > self.read_max_bytes:
            return ToolResult(False, "文件过大，跳过对比")
        diff = codebase.diff_text(a, b, os.path.basename(ra), os.path.basename(rb))
        if len(diff) > self.max_output_chars:
            diff = diff[: self.max_output_chars] + "\n...(diff已截断)"
        self._log("diff_preview", True, f"{ra} <-> {rb}")
        return ToolResult(True, diff)

    # ---------- 统一入口 ----------
    def execute(self, name: str, args: dict) -> ToolResult:
        name = str(name or "")
        args = args or {}
        if name == "list_directory":
            return self.list_directory(str(args.get("path", "")))
        if name == "read_file":
            return self.read_file(str(args.get("path", "")))
        if name == "search_local_text":
            return self.search_local_text(str(args.get("query", "")), str(args.get("path", "")))
        if name == "preview_csv":
            return self.preview_csv(str(args.get("path", "")), int(args.get("rows", 0) or 0))
        if name == "lint_code":
            return self.lint_code(str(args.get("path", "")))
        if name == "scan_project":
            return self.scan_project(str(args.get("path", "")))
        if name == "diff_preview":
            return self.diff_preview(str(args.get("path_a", "")), str(args.get("path_b", "")))
        if name == "write_file":
            return self.write_file(str(args.get("path", "")), str(args.get("content", "")))
        if name == "run_command":
            return self.run_command(str(args.get("command", "")))
        if name == "run_script":
            return self.run_script(str(args.get("path", "")), str(args.get("args", "")))
        self._security("unknown_tool", name)
        return ToolResult(False, f"未知工具 {name}，已拒绝")

    def execute_approved(self, name: str, args: dict) -> ToolResult:
        """审批通过后的执行：跳过 approval 门，但保留全部安全校验。"""
        name = str(name or "")
        args = args or {}
        if name == "run_script":
            return self.execute_script_approved(str(args.get("path", "")), str(args.get("args", "")))
        if name == "write_file":
            real = self._real(str(args.get("path", "")))
            err = self._guard_path(real, self.write_dirs, need_exist=False)
            if err:
                return ToolResult(False, f"write_file 被拒绝: {err}", reason=err)
            return self._write_impl(real, str(args.get("content", "")))
        if name == "run_command":
            ok, reason, cmd_list = self._command_ok(str(args.get("command", "")))
            if not ok:
                return ToolResult(False, f"run_command 被拒绝: {reason}", reason=reason)
            return self._run(cmd_list, self.exec_timeout)
        return self.execute(name, args)

    def policy_summary(self) -> str:
        lines = [
            "本地工具策略（deny-by-default）",
            f"可读目录: {self.read_dirs or '(空，禁止读取)'}",
            f"可写目录: {self.write_dirs or '(空，禁止写入)'}",
            f"脚本目录: {self.script_dirs or '(空，禁止运行脚本)'}",
            "可用工具: list_directory, read_file, search_local_text, preview_csv, lint_code, scan_project, diff_preview, write_file, run_command, run_script",
            "脚本执行: 隔离子进程(-I) 禁网络/子进程/动态库/危险模块，超时自动终止",
            f"命令白名单: git status/log/diff, python --version, pip list, conda env list",
            f"允许文件类型: {sorted(self.allowed_ext)}",
            f"禁止文件类型: {sorted(self.blocked_ext)}",
            f"工具策略: {self.tool_policies}",
            f"单文件读取上限: {self.read_max_bytes}B；单次输出上限: {self.max_output_chars}字符",
            f"硬排除: 私密目录 {self.private_dirs or '(未配置)'} 与密钥类文件名永不可访问",
            "安全事件(越权/危险命令/拦截)写入 security_audit.log",
        ]
        return "\n".join(lines)
