"""Tiny HTTP helpers (standard library only)."""

from __future__ import annotations

import json
import urllib.request


def request_json(method: str, url: str, headers: dict | None = None,
                 payload: dict | None = None, timeout: float = 15) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode() or "{}"
    return json.loads(body)


def request_bytes(url: str, headers: dict | None = None, timeout: float = 20) -> bytes:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()
