# Threat model

## In scope

| Threat | Handling |
|---|---|
| Credential stuffing / brute force on login | per-identity and per-subnet rate ceilings, escalating lockouts |
| Scraping with rotating IPs | identity linking: cookie, UA shape, request cadence, subnet |
| Scraping with rotating cookies | device/UA/TLS-shape linking plus subnet reputation |
| Path probing (`.env`, `.git`, backups) | payload/path classification, instant block plus subnet flag |
| Automated registration floods | per-subnet registration ceilings, email/device marking |
| Injection payloads sent as data | payload classification before the request reaches business logic |
| Slow trickle / many connections | connection-level ceilings enforced by the adapter layer |

## Out of scope (by design)

- **Volumetric DDoS.** This shield decides *per request*; it does not absorb
  hundreds of Gbps. Put a CDN in front; PWA is the layer behind it.
- **Account takeover with valid credentials.** If the password is correct and
  the behaviour is normal, PWA has nothing to judge.
- **Insider action on the server.** Filesystem and shell access are outside the
  request path.
- **Determined attacker with a clean residential IP and a real browser.**
  Distinguishing that from a genuine new user is unsolvable at request level;
  PWA prefers a challenge over a ban.

## False-positive controls

1. Allow-list evaluated before any scoring (loopback always allowed).
2. Single weak signals never ban — independent signals must agree.
3. `balanced` and `observe` policies for tuning on real traffic.
4. Challenges before bans when confidence is low.
5. Bans are reversible per IP, per subnet, per email, per device.
6. Every decision is logged with labels, so a false positive can be explained.

## Explicit non-goals

- No CAPTCHA vendor integration.
- No client-side JavaScript required for enforcement; the cookie is an input,
  not a requirement.
- No silent data exfiltration: the core receives normalised request fields only,
  never request bodies beyond the configured slice.
