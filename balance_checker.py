# -*- coding: utf-8 -*-
"""免费额度 / 余额只读检查模块。

只做**只读**查询（查询你自己的账号余额），绝不自动点击领取、绝不自动注册、
绝不批量薅福利 —— 这些行为违反各平台用户协议且有封号风险。

支持三类官方余额接口：
- deepseek:    GET {base}/user/balance            → is_available / balance_infos
- moonshot:    GET {base}/users/me/balance        → data.available_balance
- siliconflow: GET {base}/user/info               → data.balance / totalBalance
其余平台（智谱/通义/火山等）无公开余额接口 → 标记 manual，给出官方控制台链接由用户自查。
"""
import datetime

import requests

TIMEOUT = 10


def _scheme_ok(url: str) -> bool:
    """非本地回环必须走 https，防止 API Key 在 HTTP 明文链路上传输。"""
    if url.startswith("https://"):
        return True
    return url.startswith(("http://127.0.0.1", "http://localhost"))


def _get_json(url: str, api_key: str) -> dict:
    if not _scheme_ok(url):
        raise RuntimeError("base_url 必须为 https（防止 API Key 明文传输）")
    headers = {"Authorization": f"Bearer {api_key}"}
    resp = requests.get(url, headers=headers, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def _strip_v1(base_url: str) -> str:
    return base_url.replace("/v1", "").rstrip("/")


def check_deepseek(provider) -> dict:
    url = _strip_v1(provider.base_url) + "/user/balance"
    data = _get_json(url, provider.api_key)
    infos = data.get("balance_infos", []) or []
    total = sum(float(i.get("total_balance", 0) or 0) for i in infos)
    granted = sum(float(i.get("granted_balance", 0) or 0) for i in infos)
    topped = sum(float(i.get("topped_up_balance", 0) or 0) for i in infos)
    return {
        "status": "ok",
        "available": bool(data.get("is_available", False)),
        "balance": total,
        "granted": granted,
        "topped_up": topped,
        "currency": (infos[0].get("currency", "CNY") if infos else "CNY"),
        "url": "https://platform.deepseek.com/usage",
    }


def check_moonshot(provider) -> dict:
    url = provider.base_url.rstrip("/") + "/users/me/balance"
    data = _get_json(url, provider.api_key)
    d = data.get("data", {}) or {}
    return {
        "status": "ok",
        "available": float(d.get("available_balance", 0) or 0) > 0,
        "balance": float(d.get("available_balance", 0) or 0),
        "voucher": float(d.get("voucher_balance", 0) or 0),
        "cash": float(d.get("cash_balance", 0) or 0),
        "url": "https://platform.kimi.com/user-center/balance",
    }


def check_siliconflow(provider) -> dict:
    url = provider.base_url.rstrip("/") + "/user/info"
    data = _get_json(url, provider.api_key)
    d = data.get("data", {}) or {}
    return {
        "status": "ok",
        "available": float(d.get("totalBalance", 0) or 0) > 0,
        "balance": float(d.get("balance", 0) or 0),
        "total_balance": float(d.get("totalBalance", 0) or 0),
        "charge_balance": float(d.get("chargeBalance", 0) or 0),
        "url": "https://cloud.siliconflow.cn/account/usage",
    }


def check_provider_balance(provider) -> dict:
    """返回单平台额度检查结果 dict。任何异常都捕获并返回 error，不影响其他平台。"""
    base = {
        "name": provider.name,
        "display_name": provider.display_name,
        "check_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": provider.balance_check.get("check_url", ""),
        "how_to": provider.balance_check.get("how_to", ""),
    }
    try:
        btype = provider.balance_type
        if btype == "manual":
            return {**base, "status": "manual", "message": "无公开余额接口，请到官方控制台查看免费额度/资源包"}
        if not provider.configured:
            return {**base, "status": "nokey",
                    "message": f"API Key 未配置（{provider.key_status_label}），请先在 secrets.json 中填写有效 Key"}
        if btype == "deepseek":
            r = check_deepseek(provider)
        elif btype == "moonshot":
            r = check_moonshot(provider)
        elif btype == "siliconflow":
            r = check_siliconflow(provider)
        else:
            return {**base, "status": "manual", "message": "无公开余额接口，请到官方控制台查看免费额度/资源包"}
        return {**base, **r, "message": "官方接口只读查询成功"}
    except requests.exceptions.HTTPError as e:
        return {**base, "status": "error", "message": f"HTTP {e.response.status_code}，请检查API Key是否正确"}
    except Exception as e:  # noqa: BLE001
        return {**base, "status": "error", "message": f"查询失败: {type(e).__name__}: {e}"}


def check_all_balances(providers) -> list[dict]:
    return [check_provider_balance(p) for p in providers]


def format_balance_report(results: list[dict]) -> str:
    """CLI 下打印用。"""
    lines = []
    for r in results:
        if r["status"] == "ok":
            detail = {k: v for k, v in r.items() if k in ("balance", "granted", "topped_up", "voucher", "cash", "total_balance", "charge_balance", "currency", "available")}
            lines.append(f"[{r['display_name']}] {r['status']} {detail} | {r['message']}")
        else:
            lines.append(f"[{r['display_name']}] {r['status']}: {r['message']}")
    return "\n".join(lines)
