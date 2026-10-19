"""The open shell: allow-lists, caching, logging, orchestration.

No detection logic lives here. The shell decides *whether the core gets to
speak* and what to do with its answer; the core decides who is hostile.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .context import RequestContext
from .errors import ConfigurationError
from .loading import load as load_core

log = logging.getLogger("pirelywebamilen")

POLICIES = ("strict", "balanced", "observe")


@dataclass(frozen=True)
class Decision:
    action: str
    score: float = 0.0
    reason: str = ""
    core: str = "closed"
    labels: tuple[str, ...] = ()

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    @property
    def challenged(self) -> bool:
        return self.action == "challenge"


class Pirely:
    """Strict-by-default shield.

    Parameters
    ----------
    policy:
        ``strict`` treats a challenge as a block for state-changing methods;
        ``balanced`` lets challenges through with a rate ceiling; ``observe``
        never blocks (useful while tuning).
    allow:
        IPs or CIDRs that are never scored. Loopback is always allowed.
    allow_accounts / allow_devices:
        Explicit identities that bypass scoring.
    cache_ttl:
        Seconds a decision is reused for the same fingerprint.
    audit_path:
        Optional JSONL audit log.
    """

    def __init__(
        self,
        policy: str = "strict",
        allow: list[str] | None = None,
        allow_accounts: list[str] | None = None,
        allow_devices: list[str] | None = None,
        cache_ttl: float = 30.0,
        audit_path: str | Path | None = None,
    ) -> None:
        if policy not in POLICIES:
            raise ConfigurationError(f"policy must be one of {POLICIES}, got {policy!r}")
        self.policy = policy
        self._nets = [ipaddress.ip_network(a, strict=False) for a in (allow or [])]
        self._accounts = {a.strip().lower() for a in (allow_accounts or []) if a}
        self._devices = {d.strip() for d in (allow_devices or []) if d}
        self._ttl = max(0.0, float(cache_ttl))
        self._cache: dict[str, tuple[float, Decision]] = {}
        self._lock = threading.Lock()
        self._audit = Path(audit_path) if audit_path else None
        self._core = load_core()

    # ---------------- public ----------------

    @property
    def core_status(self) -> str:
        return "ready" if self._core is not None else "unavailable"

    def evaluate(self, ctx: RequestContext) -> Decision:
        """Return the decision for one normalised request."""
        if self._allowed(ctx):
            return Decision("allow", 0.0, "allowlist", core="shell")

        fp = ctx.fingerprint()
        cached = self._cache_get(fp)
        if cached is not None:
            return cached

        decision = self._score(ctx)
        if self.policy == "observe":
            decision = Decision("allow", decision.score, decision.reason + "|observe", decision.core, decision.labels)
        elif self.policy == "balanced" and decision.action == "block" and decision.score < 60:
            decision = Decision("challenge", decision.score, decision.reason, decision.core, decision.labels)

        self._cache_put(fp, decision)
        self._write_audit(ctx, decision)
        return decision

    # ---------------- internals ----------------

    def _allowed(self, ctx: RequestContext) -> bool:
        if ctx.account and ctx.account in self._accounts:
            return True
        if ctx.device_id and ctx.device_id in self._devices:
            return True
        if not ctx.ip:
            return True
        try:
            addr = ipaddress.ip_address(ctx.ip)
        except ValueError:
            return False
        if addr.is_loopback:
            return True
        return any(addr in net for net in self._nets)

    def _score(self, ctx: RequestContext) -> Decision:
        if self._core is None:
            return Decision("allow", 0.0, "core-unavailable", core="unavailable")
        fields = {
            "ip": ctx.ip,
            "method": ctx.method,
            "path": ctx.path,
            "user_agent": ctx.user_agent,
            "device_id": ctx.device_id,
            "email": ctx.email,
            "account": ctx.account,
            "payload": ctx.payload,
            "fingerprint": ctx.fingerprint(),
        }
        try:
            raw = self._core.evaluate(fields)
        except Exception as exc:  # a broken core must not take the site down
            log.warning("core raised: %s", exc)
            return Decision("allow", 0.0, "core-error", core="error")
        action = raw.get("action", "allow")
        if action not in ("allow", "challenge", "block"):
            action = "allow"
        return Decision(
            action=action,
            score=float(raw.get("score", 0.0)),
            reason=str(raw.get("reason", ""))[:120],
            labels=tuple(str(x)[:32] for x in raw.get("labels", []) or ()),
        )

    def _cache_get(self, fp: str) -> Decision | None:
        if not self._ttl:
            return None
        with self._lock:
            hit = self._cache.get(fp)
            if not hit:
                return None
            expires, decision = hit
            if expires < time.monotonic():
                self._cache.pop(fp, None)
                return None
            return decision

    def _cache_put(self, fp: str, decision: Decision) -> None:
        if not self._ttl or decision.challenged:
            return
        with self._lock:
            if len(self._cache) > 50_000:
                self._cache.clear()
            self._cache[fp] = (time.monotonic() + self._ttl, decision)

    def _write_audit(self, ctx: RequestContext, decision: Decision) -> None:
        if not self._audit:
            return
        record = {
            "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "ip": ctx.ip,
            "device": ctx.device_id,
            "account": ctx.account,
            "email": ctx.email,
            "path": ctx.path,
            "method": ctx.method,
            "action": decision.action,
            "score": round(decision.score, 2),
            "reason": decision.reason,
            "labels": list(decision.labels),
            "core": decision.core,
        }
        try:
            with self._audit.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            log.warning("audit write failed")
