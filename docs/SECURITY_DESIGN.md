# Security design

A security product must itself be hard to attack. What is implemented, and what is *not*.

## Implemented

| Area | Control |
|---|---|
| Authentication | scrypt (N=2¹⁴) salted hashes; HS256 JWT with pinned algorithm (`none` rejected), mandatory `exp`, constant-time comparison; dummy hash verification for unknown users (no username timing oracle) |
| Brute force on the platform itself | lockout after 5 failures per (username, IP) for 15 min → HTTP 429 + `Retry-After`; all failures/lockouts audited |
| Authorisation | role hierarchy enforced server-side on every route (`require(role)`); disabled users' tokens stop working immediately; cannot demote/disable the last admin |
| Sessions | short-lived tokens (default 60 min) in `sessionStorage`; each token embeds a fingerprint of the password hash, so **changing or resetting a password immediately ends every older session**; disabled/deleted users are rejected on the next request; WebSocket auth by first message, `Origin` allow-list, periodic re-validation |
| Sign-up | self-registration always creates a read-only **Viewer** (the payload has no role field), is rate-limited to 10 per IP per hour, can be switched off by an Admin, and enforces the password policy (10+ chars, mixed case, digit, not a common password, must not contain the username) |
| Account state | a disabled user sees "account disabled" **only after supplying the correct password**, so the message cannot be used to discover usernames; Admins cannot demote, disable or delete themselves or the last Admin |
| Data ownership | upload history is private to its owner; Admins can see/delete all; other users' job ids return 404 (no probing) |
| Connector keys | `agk_` + 256 random bits, only the SHA-256 hash is stored and the key is shown once; rotate (old key dies instantly), revoke, delete; failed keys throttled per IP (429); per-source event rate limit; batch-size and body-size caps (413 before parsing); a dashboard JWT is **not** accepted on the ingest door and an API key is not accepted anywhere else |
| Connector privacy | opt-in only; exclusions, parameter redaction and IP pseudonymisation applied on the client machine *and* again on arrival; cookies, authorization headers and bodies are never collected; the stored request line never contains redacted values |
| Ingest validation | every field re-validated and bounded server-side (IP syntax, methods, lengths, control characters stripped, absurd timestamps replaced); idempotent by event id |
| Information exposure | the public `/api/health` returns only status and uptime; model, cache and DB details are Admin-only |
| Input validation | Pydantic bounds on every body/query; upload limited by extension, size (`MAX_UPLOAD_MB`) and rows; IPs validated and canonicalised; payload truncated |
| SQL injection | all SQL parameterised; the few interpolated fragments are fixed whitelists (sort column, fixed column names); `LIKE` wildcards escaped |
| Rule injection | generated firewall/WAF text only ever contains validated IPs and a bounded integer port; rules are **never executed** |
| Output injection | React escapes all text; chat renders only `**bold**` via React nodes; PDF text is XML-escaped; CSV cells starting `= + - @` are neutralised |
| Detection evasion | payload features are always recomputed server-side; payload is URL-decoded twice before matching |
| Secrets & config | no secrets in code; `APP_ENV=production` refuses to start without `JWT_SECRET`/`ADMIN_PASSWORD`, rejects `CORS_ORIGINS=*`; generated first-run admin password is printed once |
| Transport & headers | CORS allow-list, no credentials; `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Cache-Control: no-store` on `/api`; nginx adds a CSP; `/docs` disabled in production |
| Model integrity | `bundle.joblib` is only loaded when its SHA-256 matches the sidecar file (pickle executes code on load) |
| Containers | non-root user, health check, single writable data volume |
| Privacy | stored payload samples ≤ 500 chars; attacker IPs in the simulator come from RFC 5737 documentation ranges |
| Accountability | audit log of security-relevant actions |
| Alert e-mail | header-injection safe (CR/LF stripped); SMTP failures never affect detection |

## Known limitations (be upfront in a viva)

* The pre-shared lab key (`ARGUS_BOOTSTRAP_SOURCE_KEY`) is public by design; the app refuses to start with it in production.
* The collector verifies TLS by default; over plain `http://` to a non-local host the key crosses the network in clear text (it warns).
* Log-based monitoring cannot see request bodies.

* **No TLS inside the app** — terminate HTTPS at a reverse proxy/load balancer. Without TLS, JWTs and passwords cross the network in clear text.
* A stolen token stays valid until it expires unless the user is disabled or their password changes (there is no per-token revocation list or "sign out everywhere" button). A refresh-token/denylist scheme would add that.
* Self-registration has no e-mail verification and no CAPTCHA; the per-IP limit is the only abuse control. Switch it off for closed deployments.
* There is no "forgot password" e-mail flow; an Admin resets passwords.
* The login throttle, stream hub and cache are in-memory, per process.
* SQLite is single-node. Use PostgreSQL for multi-instance deployments.
* The model checksum protects against corruption/casual tampering, not against an attacker who can write both files.
* Uploaded CSVs are parsed with pandas; the size and row caps bound resource use, but a hostile CSV can still be CPU-heavy. Run behind a rate limiter.
* Mitigation is a **simulation**. Integrating real enforcement (firewall API, EDR) must add its own authorisation and a human-approval step.
* Detection models trained on simulated data have unknown real-world performance and can be evaded by adaptive attackers (adversarial ML is out of scope).
