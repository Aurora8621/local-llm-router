# -*- coding: utf-8 -*-
"""项目结构索引与代码解析（轻量 LSP 替代，纯标准库）：
- scan_project : 白名单目录文件树 + 符号统计（跳过 .git/node_modules 等）
- scan_symbols : Python(ast) / JS/TS(正则) 提取函数/类/导入
- diff_text    : unified diff（difflib），供代码变更预览
"""
import os
import re
import ast
import difflib

_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
    ".idea", ".vscode", ".pytest_cache", "logs", ".sessions", ".mypy_cache",
}

_TEXT_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".cpp", ".h", ".hpp", ".java", ".go",
    ".rs", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".html", ".htm", ".css", ".xml", ".sql", ".sh", ".bat", ".cmd",
}

_JS_SYMBOL = re.compile(
    r"^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|"
    r"^(?:export\s+)?(?:class\s+)([A-Za-z_$][\w$]*)", re.M)
_JS_IMPORT = re.compile(r"^\s*import\s+.*?from\s+['\"]([^'\"]+)['\"]", re.M)
_MAX_FILES = 200
_MAX_DEPTH = 6


def scan_project(root: str, max_files: int = _MAX_FILES, max_depth: int = _MAX_DEPTH) -> dict:
    """扫描项目根目录：返回文件树、文件数、目录数、符号统计。"""
    root = os.path.realpath(root)
    tree = []
    files = 0
    dirs = 0
    sym_counts = {}

    def walk(d, depth):
        nonlocal files, dirs
        if depth > max_depth or files >= max_files:
            return
        try:
            entries = sorted(os.listdir(d))
        except OSError:
            return
        for name in entries:
            full = os.path.join(d, name)
            if os.path.isdir(full):
                if name in _SKIP_DIRS:
                    continue
                dirs += 1
                walk(full, depth + 1)
            else:
                ext = os.path.splitext(name)[1].lower()
                if ext not in _TEXT_EXT:
                    continue
                files += 1
                tree.append(os.path.relpath(full, root).replace(os.sep, "/"))
                syms = scan_symbols(full)
                for kind, items in syms.items():
                    sym_counts[kind] = sym_counts.get(kind, 0) + len(items)

    walk(root, 0)
    return {"root": root, "tree": tree, "files": files, "dirs": dirs,
            "symbols": sym_counts}


def scan_symbols(path: str) -> dict:
    """提取 {function:[(name,line)], class:[...], import:[...]}。"""
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            src = f.read()
    except OSError:
        return {}
    if ext == ".py":
        return _py_symbols(src)
    if ext in (".js", ".ts", ".jsx", ".tsx"):
        return _js_symbols(src)
    return {}


def _py_symbols(src: str) -> dict:
    out = {"function": [], "class": [], "import": []}
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return out
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out["function"].append((node.name, getattr(node, "lineno", 0)))
        elif isinstance(node, ast.ClassDef):
            out["class"].append((node.name, getattr(node, "lineno", 0)))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            out["import"].append(([a.name for a in node.names], getattr(node, "lineno", 0)))
    return out


def _js_symbols(src: str) -> dict:
    out = {"function": [], "class": [], "import": []}
    for m in _JS_SYMBOL.finditer(src):
        line = src[: m.start()].count("\n") + 1
        if m.group(1):
            out["function"].append((m.group(1), line))
        elif m.group(2):
            out["class"].append((m.group(2), line))
    for m in _JS_IMPORT.finditer(src):
        out["import"].append(([m.group(1)], src[: m.start()].count("\n") + 1))
    return out


def diff_text(a: str, b: str, name_a: str = "原文件", name_b: str = "新内容",
              context: int = 3) -> str:
    """两段文本的统一 diff；无差异返回 '(无差异)'。"""
    la = (a or "").splitlines()
    lb = (b or "").splitlines()
    lines = list(difflib.unified_diff(la, lb, fromfile=name_a, tofile=name_b,
                                      lineterm="", n=context))
    if not lines:
        return "(无差异)"
    return "\n".join(lines)
