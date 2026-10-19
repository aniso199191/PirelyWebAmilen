"""Shell tests. A fake core stands in for the closed one."""
from __future__ import annotations

import sys
import types

import pytest

from pirelywebamilen import Decision, Pirely, RequestContext
from pirelywebamilen import loading


def _fake_core(action="block", score=90.0, reason="bad_payload"):
    module = types.ModuleType("pwa_core")
    module.VERSION = "test"
    module.evaluate = lambda fields: {
        "action": action,
        "score": score,
        "reason": reason,
        "labels": ["payload"],
    }
    return module


@pytest.fixture(autouse=True)
def _reset():
    loading.reset()
    sys.modules.pop("pwa_core", None)
    yield
    loading.reset()
    sys.modules.pop("pwa_core", None)


def test_observe_mode_without_core_never_blocks():
    shield = Pirely(policy="observe")
    decision = shield.evaluate(RequestContext(ip="203.0.113.9", path="/x"))
    assert decision.action == "allow"
    assert decision.core == "unavailable"


def test_loopback_is_always_allowed():
    sys.modules["pwa_core"] = _fake_core()
    shield = Pirely()
    assert shield.evaluate(RequestContext(ip="127.0.0.1")).action == "allow"


def test_allowlist_cidr():
    sys.modules["pwa_core"] = _fake_core()
    shield = Pirely(allow=["10.0.0.0/8"])
    assert shield.evaluate(RequestContext(ip="10.1.2.3")).reason == "allowlist"


def test_allowlist_account_and_device():
    sys.modules["pwa_core"] = _fake_core()
    shield = Pirely(allow_accounts=["alice"], allow_devices=["dev-a"])
    assert shield.evaluate(RequestContext(ip="203.0.113.9", account="alice")).action == "allow"
    assert shield.evaluate(RequestContext(ip="203.0.113.9", device_id="dev-a")).action == "allow"


def test_core_block_is_honoured():
    sys.modules["pwa_core"] = _fake_core()
    shield = Pirely()
    decision = shield.evaluate(RequestContext(ip="203.0.113.9", path="/.env"))
    assert decision.blocked
    assert decision.score == 90.0


def test_balanced_downgrades_low_confidence_block():
    sys.modules["pwa_core"] = _fake_core(score=40.0)
    shield = Pirely(policy="balanced")
    assert shield.evaluate(RequestContext(ip="203.0.113.10")).action == "challenge"


def test_cache_reuses_decision():
    calls = {"n": 0}

    def evaluate(fields):
        calls["n"] += 1
        return {"action": "allow", "score": 1.0, "reason": "ok", "labels": []}

    module = types.ModuleType("pwa_core")
    module.VERSION = "test"
    module.evaluate = evaluate
    sys.modules["pwa_core"] = module

    shield = Pirely(cache_ttl=60)
    ctx = RequestContext(ip="203.0.113.11", device_id="d1")
    shield.evaluate(ctx)
    shield.evaluate(ctx)
    assert calls["n"] == 1


def test_bad_policy_rejected():
    from pirelywebamilen import ConfigurationError

    with pytest.raises(ConfigurationError):
        Pirely(policy="yolo")


def test_broken_core_does_not_break_the_site():
    module = types.ModuleType("pwa_core")
    module.evaluate = lambda fields: (_ for _ in ()).throw(RuntimeError("boom"))
    sys.modules["pwa_core"] = module
    shield = Pirely()
    decision = shield.evaluate(RequestContext(ip="203.0.113.12"))
    assert decision.action == "allow"
    assert decision.core == "error"


def test_audit_log(tmp_path):
    sys.modules["pwa_core"] = _fake_core()
    path = tmp_path / "audit.jsonl"
    shield = Pirely(audit_path=path)
    shield.evaluate(RequestContext(ip="203.0.113.13", path="/admin"))
    line = path.read_text(encoding="utf-8").strip()
    assert '"action": "block"' in line
