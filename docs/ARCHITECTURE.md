# Architecture

```
 request ──► adapter ──► RequestContext ──► shell ──► core (closed)
             (open)       (open)            (open)      │
                                                ▲       │
                                                └───────┘
                                          Decision(action, score, reason)
```

## Layers

### 1. Adapter (open)

Framework glue only. Extracts the client address, headers, cookie, path and a
bounded body slice. No decisions.

### 2. RequestContext (open)

Normalises everything into fixed-size fields. This is the trust boundary:
after this point the core never sees an unbounded string.

- `ip` ≤ 64 chars, taken from `CF-Connecting-IP` → `X-Real-IP` → `X-Forwarded-For` → socket
- `device_id` ≤ 64 chars from the `pi_did` cookie
- `user_agent` ≤ 300, `path` ≤ 512 (query stripped), `payload` ≤ 8192
- `email` lowercased, `account` trimmed

### 3. Shell (open)

Order of operations, and why:

1. **Allow-list first.** Loopback, configured CIDRs, trusted accounts and
   devices never reach scoring. This is the main defence against false
   positives.
2. **Cache by fingerprint.** Same identity within `cache_ttl` reuses the
   decision; the cache is skipped for challenges.
3. **Core call.** Wrapped in `try/except`. A broken or missing core degrades to
   *allow* with `core="error"|"unavailable"` — the site stays up, the incident
   is logged.
4. **Policy shaping.** `observe` forces allow; `balanced` downgrades
   low-confidence blocks (`score < 60`) to challenges.
5. **Audit.** One JSONL line per decision, including labels but never the body.

### 4. Core (closed)

Scores the normalised fields and returns `allow | challenge | block`, a score,
and short labels. It owns:

- signal weighting and thresholds
- identity linking across IP / subnet / cookie / UA changes
- subnet and ASN reputation
- payload classification
- escalation history

Version contract: `pwa_core.VERSION`, `pwa_core.evaluate(dict) -> dict`.

## Design constraints

- **Fail open on core errors, fail closed on explicit bans.** A crash must not
  take down the site; a recorded ban must not evaporate.
- **No state in the request path beyond the cache.** Bans live in storage, not
  in memory, so a restart does not reset an attacker.
- **Neutral denial.** One message, one status, no hint about which signal fired.
- **Bounded everything.** Header count, string lengths, cache size.

## Deployment

The shell is a pure-Python package with no hard dependencies. The core is a
compiled module; drop it on the path (or set `PWA_CORE_PATH`) and the same
build turns from observe to enforcing.
