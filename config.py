# -*- coding: utf-8 -*-
"""配置加载：公开配置(config.json)与私密密钥(secrets.json)分离。
- 公开配置：F:\\AI\\local-llm-router\\config.json（调度策略、日志路径、免费领取指引）
- 私密密钥：C:\\Users\\YourName\\AI\\llm_dispatcher\\secrets.json（API Key，不进入任何公开目录）
运行状态 state.json 也存放在私密目录（含用量与冷却状态，不含密钥明文之外的信息）。
"""
import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

# 模板占位判定：中文按原文匹配，英文统一转小写按子串匹配
_PLACEHOLDER_CN = ("填入", "占位", "在此", "请填写", "示例")
_PLACEHOLDER_EN = ("your", "xxxx", "example", "replace", "placeholder", "todo", "dummy")

KEY_STATUS_LABEL = {
    "configured": "已配置",
    "empty": "未填写",
    "placeholder": "模板占位",
    "non_ascii": "含非ASCII",
}


class Provider:
    def __init__(self, d: dict):
        self.name = d["name"]
        self.display_name = d.get("display_name", d["name"])
        self.enabled = bool(d.get("enabled", True))
        self.free_only = bool(d.get("free_only", True))  # 免费专用硬开关
        self.api_key = d.get("api_key", "")
        self.base_url = d.get("base_url", "")
        self.model = d.get("model", "")
        self.context_window = int(d.get("context_window", 32768))
        self.max_output_tokens = int(d.get("max_output_tokens", 2048))
        self.caps = d.get("caps", {}) or {}
        self.balance_check = d.get("balance_check", {}) or {}
        self.cooldown_seconds = int(d.get("cooldown_seconds", 300))
        self.priority = int(d.get("priority", 99))
        self.tools_enabled = bool(d.get("tools", True))  # 是否启用 function calling
        self.task_types = list(d.get("task_types") or [])  # 支持的任务类型；为空时由调度器按平台默认补全
        self.note = d.get("note", "")

    @property
    def key_status(self) -> str:
        """Key 有效性：configured / empty / placeholder / non_ascii。"""
        k = (self.api_key or "").strip()
        if not k:
            return "empty"
        low = k.lower()
        if any(t in k for t in _PLACEHOLDER_CN) or any(t in low for t in _PLACEHOLDER_EN):
            return "placeholder"
        if any(ord(ch) >= 128 for ch in k):
            return "non_ascii"
        return "configured"

    @property
    def configured(self) -> bool:
        """仅 Key 通过格式校验才允许进入调度候选。"""
        return self.key_status == "configured"

    @property
    def key_status_label(self) -> str:
        return KEY_STATUS_LABEL.get(self.key_status, self.key_status)

    @property
    def balance_type(self) -> str:
        return self.balance_check.get("type", "manual")

    @property
    def require_positive_balance(self) -> bool:
        return bool(self.balance_check.get("require_positive", False))

    def to_dict(self) -> dict:
        # 回显时脱敏，不泄露 key；同时给出 Key 状态供界面区分
        return {
            "name": self.name,
            "display_name": self.display_name,
            "enabled": self.enabled,
            "free_only": self.free_only,
            "api_key": ("已配置" if self.configured else "未配置"),
            "key_status": self.key_status_label,
            "configured": self.configured,
            "base_url": self.base_url,
            "model": self.model,
            "context_window": self.context_window,
            "max_output_tokens": self.max_output_tokens,
            "caps": self.caps,
            "balance_check": {k: v for k, v in self.balance_check.items() if k != "how_to"},
            "cooldown_seconds": self.cooldown_seconds,
            "priority": self.priority,
        }


def load_config(config_path: str | None = None) -> dict:
    path = config_path or DEFAULT_CONFIG_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"未找到公开配置文件: {path}（应与程序位于同一目录）")
    except json.JSONDecodeError as e:
        raise ValueError(f"config.json 格式损坏（第{e.lineno}行 第{e.colno}列）: {e.msg}")


def resolve_paths(cfg: dict) -> dict:
    private_dir = cfg.get("private_dir", "")
    log_dir = cfg.get("log_dir", os.path.join(BASE_DIR, "logs"))
    return {
        "private_dir": private_dir,
        "secrets_path": os.path.join(private_dir, "secrets.json"),
        "state_path": os.path.join(private_dir, "state.json"),
        "log_dir": log_dir,
    }


def load_providers(secrets_path: str) -> list[Provider]:
    try:
        with open(secrets_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"未找到私密密钥文件: {secrets_path}\n"
            "请将程序目录下的 secrets.example.json 复制到该路径，"
            "填入各平台 API Key 后再启动。")
    except json.JSONDecodeError as e:
        raise ValueError(f"secrets.json 格式损坏（第{e.lineno}行 第{e.colno}列）: {e.msg}")
    providers = [Provider(d) for d in data.get("providers", [])]
    return providers
