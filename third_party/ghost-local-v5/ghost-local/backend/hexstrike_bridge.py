"""
Bridge HTTP GHOST ↔ HexStrike AI (Flask em GHOST_HEXSTRIKE_URL, default :8888).
Só encaminha POST para caminhos na whitelist (segurança).
"""
import os
from typing import Any, Dict, Optional, Tuple

import httpx

HEXSTRIKE_BASE = os.environ.get("GHOST_HEXSTRIKE_URL", "http://127.0.0.1:8888").rstrip("/")

# Prefixos permitidos para POST /hexstrike/relay (evita SSRF / paths arbitrários)
ALLOW_POST_PREFIXES: Tuple[str, ...] = (
    "/api/command",
    "/api/intelligence/",
    "/api/bugbounty/",
    "/api/visual/",
    "/api/tools/",
    "/api/processes/list",
    "/api/processes/dashboard",
    "/api/telemetry",
    "/api/cache/stats",
    "/api/cache/clear",
    "/api/payloads/",
)


def normalize_path(path: str) -> Optional[str]:
    if not path or not isinstance(path, str):
        return None
    path = path.strip().split("?")[0]
    if not path.startswith("/") or ".." in path:
        return None
    return path


def is_allowed_post(path: str) -> bool:
    p = normalize_path(path)
    if not p:
        return False
    return any(p == pref.rstrip("/") or p.startswith(pref) for pref in ALLOW_POST_PREFIXES)


async def hexstrike_ping() -> Dict[str, Any]:
    """Verifica se o servidor HexStrike responde (GET leve, não /health completo)."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{HEXSTRIKE_BASE}/api/telemetry")
            return {"ok": r.status_code < 500, "status_code": r.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def hexstrike_get_health(timeout: float = 45.0) -> Tuple[int, Any]:
    """Proxy GET /health do HexStrike (pode demorar — muitos `which`)."""
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.get(f"{HEXSTRIKE_BASE}/health")
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"text": r.text[:8000]}


async def hexstrike_post(path: str, body: Optional[Dict[str, Any]], timeout: float = 120.0) -> Tuple[int, Any]:
    if not is_allowed_post(path):
        return 400, {"error": "caminho não permitido na relay", "path": path, "allowed_prefixes": ALLOW_POST_PREFIXES}
    p = normalize_path(path)
    assert p is not None
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.post(f"{HEXSTRIKE_BASE}{p}", json=body if body is not None else {})
        ct = (r.headers.get("content-type") or "").lower()
        if "json" in ct:
            try:
                return r.status_code, r.json()
            except Exception:
                return r.status_code, {"text": r.text[:50000]}
        return r.status_code, {"text": r.text[:50000], "content_type": r.headers.get("content-type")}
