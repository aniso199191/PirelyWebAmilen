"""Request normalisation.

Everything an attacker controls is length-bounded here, once, so that the
scoring core never has to defend against 10 MB headers or 200k-element cookie
lists.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

MAX_IP = 64
MAX_ID = 64
MAX_UA = 300
MAX_PATH = 512
MAX_PAYLOAD = 8192
MAX_EMAIL = 120

_IP_HEADERS = ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For")


def _first(value: str | None, limit: int) -> str:
    if not value:
        return ""
    return value.split(",")[0].strip()[:limit]


@dataclass(frozen=True)
class RequestContext:
    """A single request, normalised.

    Attributes are already truncated and stripped; the core can trust lengths.
    """

    ip: str = ""
    method: str = "GET"
    path: str = "/"
    user_agent: str = ""
    device_id: str = ""
    email: str = ""
    account: str = ""
    payload: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "ip", _first(self.ip, MAX_IP))
        object.__setattr__(self, "method", (self.method or "GET").upper()[:10])
        object.__setattr__(self, "path", (self.path or "/").split("?")[0][:MAX_PATH])
        object.__setattr__(self, "user_agent", (self.user_agent or "")[:MAX_UA])
        object.__setattr__(self, "device_id", (self.device_id or "")[:MAX_ID])
        object.__setattr__(self, "email", (self.email or "").strip().lower()[:MAX_EMAIL])
        object.__setattr__(self, "account", (self.account or "").strip().lower()[:MAX_ID])
        object.__setattr__(self, "payload", (self.payload or "")[:MAX_PAYLOAD])

    @classmethod
    def from_headers(cls, ip: str, headers, **kw) -> "RequestContext":
        """Build from a mapping-like header object (case-insensitive or not)."""
        get = headers.get
        real_ip = ip
        for name in _IP_HEADERS:
            value = get(name)
            if value:
                real_ip = _first(value, MAX_IP)
                break
        cookie = get("Cookie") or ""
        device = ""
        for part in cookie.split(";"):
            key, _, value = part.strip().partition("=")
            if key == "pi_did":
                device = value.strip()[:MAX_ID]
                break
        return cls(
            ip=real_ip,
            method=get(":method") or kw.pop("method", "GET"),
            path=kw.pop("path", "/"),
            user_agent=get("User-Agent") or "",
            device_id=device,
            email=kw.pop("email", ""),
            account=kw.pop("account", ""),
            payload=kw.pop("payload", ""),
        )

    def fingerprint(self) -> str:
        """Stable hash over the identifying fields (not the payload)."""
        raw = json.dumps(
            [self.ip, self.device_id, self.user_agent, self.account, self.email],
            ensure_ascii=False,
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:32]
