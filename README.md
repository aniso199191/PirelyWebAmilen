# PirelyWebAmilen

**A strict-by-default web shield with a closed detection core.**

`PirelyWebAmilen` ("PWA") is a request-scoring shield for web services. It links
signals that attackers usually rotate one at a time — IP, subnet, cookie,
User-Agent, TLS/HTTP shape, payload — into a single identity, then decides
whether a request is welcome, worth challenging, or should be cut off.

This repository contains the **open shell**: configuration, request
normalisation, middleware for common frameworks, allow-lists, decision caching,
logging, and the public API.

The **scoring core is closed source** and is not in this repository.
See [`docs/WHY_CLOSED_CORE.md`](docs/WHY_CLOSED_CORE.md) for the reasoning.

---

## Install (shell only)

```bash
pip install pirelywebamilen
```

The shell runs without the core in **observe mode**: it parses and normalises
requests, applies allow-lists, and reports `decision="allow"` with
`core="unavailable"`. Real blocking requires the closed core module
(`pwa_core`, distributed separately as a platform binary).

```python
from pirelywebamilen import Pirely, RequestContext

shield = Pirely(policy="strict", allow=["10.0.0.0/8"])

decision = shield.evaluate(RequestContext(
    ip="203.0.113.9",
    device_id="d1f2c3",
    user_agent="Mozilla/5.0 …",
    path="/api/login",
    payload='{"user":"a"}',
))

print(decision.action, decision.reason, decision.score)
```

## Framework glue

```python
# FastAPI / Starlette
from pirelywebamilen.middleware import StarletteShield
app.add_middleware(StarletteShield, shield=shield)

# Flask / WSGI
from pirelywebamilen.middleware import FlaskShield
FlaskShield(app, shield=shield)
```

Denied requests get `403` with a single neutral body:

```json
{"error": {"message": "已被封禁，请不要做任何违规做法"}}
```

## What the shell does

| Layer | Open | Notes |
|---|---|---|
| Header / cookie parsing (`CF-Connecting-IP`, `X-Forwarded-For`, `pi_did`) | ✔ | normalised, bounded, never trusted blindly |
| Allow-list (IP, CIDR, account, device) | ✔ | checked before any scoring |
| Decision cache + TTL | ✔ | keeps hot paths cheap |
| Neutral deny response | ✔ | no information leak about why |
| Audit log (JSONL) | ✔ | IP / device / email / subnet / payload hash |
| Scoring, identity linking, evasion detection | ✕ | closed core |
| Subnet reputation, challenge escalation | ✕ | closed core |

## Guarantees the design aims for

- **No false positives by default.** A single weak signal (one 404, one long
  URL, one odd UA) can never ban. Multiple *independent* signals must agree.
- **Challenges before bans.** Suspicious-but-ambiguous traffic gets a challenge
  or a rate ceiling, not a permanent block.
- **Rotation does not help.** Cookie-only rotation is defeated by device/UA/TLS
  linking; IP-only rotation is defeated by subnet reputation and cookie reuse.
- **Bans are recorded, not forgotten.** Blocking writes to a durable store, so a
  restart does not reset the attacker's standing.

## Layout

```
pirelywebamilen/
  __init__.py          public API
  context.py           request normalisation
  shell.py             orchestration, allow-list, cache, logging
  middleware.py        Starlette / Flask adapters
  errors.py            exceptions
  loading.py           closed-core loader (imports `pwa_core`)
docs/
  WHY_CLOSED_CORE.md   why the core is not published
  ARCHITECTURE.md      shell internals
  THREAT_MODEL.md      what is defended, what is out of scope
examples/
  fastapi_app.py
tests/
  test_shell.py        runs against a fake core
```

## Status

Shell: usable, tested. Core: closed, distributed as a binary for Linux
x86_64/aarch64. Issues about the core's behaviour are welcome; the source is
not.

## License

MIT for everything in this repository. The closed core is proprietary and is
**not** covered by this license.
