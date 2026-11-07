# API design

Base URL `http://localhost:8000` (dev; the Vite proxy forwards `/api` and `/ws`). Interactive docs: `/docs` (disabled when `APP_ENV=production`).

**Conventions** — JSON in/out; `Authorization: Bearer <JWT>` on everything except the **ingest door** (API key), login, registration, the login-page config and health; errors are `{"detail": "..."}` with 401 (unauthenticated), 403 (role), 404, 409 (conflict), 413/415 (upload), 422 (validation), 429 (login throttled, with `Retry-After`).

**Roles** — Viewer < Analyst < Admin; each endpoint lists the *minimum* role.

| Method | Path | Min. role | Purpose |
|---|---|---|---|
| GET | `/api/admin/audit` | Admin | Audit trail (sign-ins, failures, registrations, status changes, mitigations, uploads, deletions, retraining) |
| POST | `/api/admin/registration` | Admin | Turn self-registration on or off |
| GET | `/api/admin/simulation` | Viewer | Current live-simulator settings |
| POST | `/api/admin/simulation` | Admin | Simulator `mode`: **auto** (off while a live source is connected), on, off; plus interval and attack share |
| GET | `/api/admin/system` | Admin | System status: models, cache, uptime, DB size, user count, email/registration state |
| GET | `/api/alerts` | Viewer | List alerts; filters: status, severity, attack_type, q, hours, sort, **scope** (all/live/demo/upload); paging |
| GET | `/api/alerts/{alert_id}` | Viewer | Alert detail incl. triggering event, local explanation, mitigation history |
| PATCH | `/api/alerts/{alert_id}` | Analyst | Set status: open / acknowledged / mitigated / resolved / false_positive |
| POST | `/api/alerts/{alert_id}/mitigate` | Analyst | Apply a mitigation **in simulation**: records it, generates rule text, may add to blocklist |
| GET | `/api/alerts/{alert_id}/recommendations` | Viewer | Measured detector comparison + mitigation options for the alert's attack type |
| POST | `/api/auth/change-password` | Any signed-in user | Change own password; **ends all other sessions** and returns a fresh token |
| GET | `/api/auth/config` | Public | Login-page settings: app name and whether self-registration is on |
| POST | `/api/auth/login` | Public | Credentials → JWT. 401 wrong credentials; **403 account disabled** (only revealed with the correct password); 429 throttled |
| GET | `/api/auth/me` | Any signed-in user | Current user incl. last sign-in |
| POST | `/api/auth/register` | Public | Self-registration → always a Viewer, returns a JWT (rate-limited per IP; 403 when switched off; 409 username taken) |
| GET | `/api/auth/users` | Admin | List users |
| POST | `/api/auth/users` | Admin | Create user with any role |
| DELETE | `/api/auth/users/{user_id}` | Admin | Delete a user (not yourself, not the last Admin) |
| PATCH | `/api/auth/users/{user_id}` | Admin | Change role / enable / disable / reset password / name (cannot change or disable yourself, or remove the last Admin) |
| DELETE | `/api/blocklist/{ip}` | Admin | Remove an IP from the simulated blocklist |
| POST | `/api/chat` | Viewer | Assistant (answers are computed from stored data) |
| GET | `/api/collector/download` | Admin | Download `argus_collector.py` |
| GET | `/api/coverage` | Viewer | Mode (demo/live), connected sources and, for each of the 15 attack types, covered / silent / waiting / not covered (+ what would cover it) |
| POST | `/api/detect/event` | Analyst | Analyse one request/flow; payload text is inspected server-side |
| GET | `/api/detect/jobs` | Viewer | Upload history: **Admin sees everyone’s, others only their own** |
| DELETE | `/api/detect/jobs/{job_id}` | Viewer | Delete an upload log (owner or Admin); `?delete_findings=true` also removes its alerts/events |
| GET | `/api/detect/jobs/{job_id}` | Viewer | One upload incl. full summary (owner or Admin; otherwise 404) |
| POST | `/api/detect/upload` | Analyst | Analyse a CSV (multipart `file`); optional `label` column adds evaluation metrics |
| GET | `/api/events/recent` | Viewer | Most recent stored events |
| GET | `/api/health` | Public | Public liveness probe (status + uptime only) |
| POST | `/api/ingest/events` | API key | **The door.** Collector sends a batch of web events (max 500). Auth: `X-Argus-Key` or `Authorization: Bearer agk_...` (a dashboard JWT is rejected). 401 bad key, 413 too large, 429 rate-limited |
| POST | `/api/ingest/heartbeat` | API key | Collector liveness (every ~30 s); returns the current privacy policy |
| GET | `/api/ingest/policy` | API key | Collector fetches its privacy policy at start-up |
| POST | `/api/lab/simulate` | Analyst | Inject a simulated attack scenario; the detector receives no label |
| GET | `/api/mitigations` | Viewer | Applied mitigations and the simulated blocklist |
| GET | `/api/models/active` | Viewer | Full report of the active training run |
| POST | `/api/models/retrain` | Admin | Start background retraining + hot-swap (202); 409 if already running |
| GET | `/api/models/retrain/status` | Viewer | Retraining progress (polled by the app so the progress bar survives page changes) |
| GET | `/api/models/runs` | Viewer | Training run history (stored in the database) |
| GET | `/api/recommendations/{attack_type}` | Viewer | Recommendations for an attack type without needing an alert |
| GET | `/api/reports/alerts.csv` | Analyst | CSV export (formula-injection safe) |
| GET | `/api/reports/summary.pdf` | Viewer | PDF threat report |
| GET | `/api/sources` | Viewer | List connected sources with health (connected / silent / waiting / revoked); keys are never returned |
| POST | `/api/sources` | Admin | Create a source; returns the API key **once** |
| DELETE | `/api/sources/{source_id}` | Admin | Delete a source and destroy its key; recorded alerts are kept |
| PATCH | `/api/sources/{source_id}` | Admin | Rename / change the privacy policy (reaches the collector within 30 s) |
| POST | `/api/sources/{source_id}/revoke` | Admin | Disable a source; its collector gets 401 |
| POST | `/api/sources/{source_id}/rotate` | Admin | New key (shown once); the old key stops working immediately |
| GET | `/api/stats/forecast` | Viewer | Holt-linear forecast of threats/hour |
| GET | `/api/stats/heatmap` | Viewer | Attack type × hour-of-day counts (UTC) |
| GET | `/api/stats/overview` | Viewer | KPI totals and breakdowns; all `/api/stats/*` accept `scope` |
| GET | `/api/stats/timeline` | Viewer | Hourly totals vs threats |
| GET | `/api/stats/top-sources` | Viewer | Top attacking IPs |
| WS | `/ws/stream` | First-message JWT (any role) | Live events. First message must be `{"type":"auth","token":"<JWT>"}` |

## Live stream protocol (`/ws/stream`)

1. Client opens the socket and sends `{"type":"auth","token":"<JWT>"}` within 5 s (the token never appears in a URL or access log).
2. Server answers `{"type":"hello",...}`, then pushes `{"type":"event", ...}` for every analysed event (live simulator, lab, API) and `{"type":"ping"}` every 30 s of silence.
3. Sockets close with code `1008` on bad/missing auth or disallowed `Origin`; expired or disabled sessions stop streaming at the next ping.
4. Slow clients lose the oldest queued messages rather than blocking detection.

## Example

```bash
TOKEN=$(curl -s localhost:8000/api/auth/login -H 'Content-Type: application/json' \
        -d '{"username":"admin","password":"..."}' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s localhost:8000/api/detect/event -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"src_ip":"198.51.100.7","payload_sample":"/items?id=1 OR 1=1"}'
```
