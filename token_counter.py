# -*- coding: utf-8 -*-
"""本地 token 估算（保守偏大，用于免费额度预算与上下文上限判断）。
仅做本地估算，不依赖任何外部计费接口。估算值偏大是刻意设计：
宁可多算，不可在额度判断上漏算导致超限。
"""
import re

_CJK_RE = re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]")

# 每 CJK 字符约 1.1 token（偏大保守）；每非 CJK 字符约 0.35 token（≈3字符/token，偏大）
_CJK_PER_CHAR = 1.1
_OTHER_PER_CHAR = 0.35
_BASE = 4  # 系统/格式开销


def estimate_tokens(text: str) -> int:
    """估算一段文本的 token 数（本地启发式，非官方精确值）。"""
    if not text:
        return 0
    cjk = len(_CJK_RE.findall(text))
    other = len(text) - cjk
    return int(cjk * _CJK_PER_CHAR + other * _OTHER_PER_CHAR) + _BASE


def estimate_messages_tokens(messages) -> int:
    """估算整组消息的 token 数。messages 为 OpenAI 格式的 dict 列表。"""
    import json

    return estimate_tokens(json.dumps(messages, ensure_ascii=False))
