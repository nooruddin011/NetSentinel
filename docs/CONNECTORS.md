# Connectors: monitoring a real system

Argus can analyse **uploaded files** and **simulated demo traffic**, but its purpose is to watch a *real* system. It does that with **connectors**, the same model used by Splunk, Elastic and Wazuh: a small program next to the client's system sends selected events to Argus. Argus never reaches into the client's systems.

```
 client's web server ─▶ access.log ─▶ COLLECTOR ─(HTTPS + API key)─▶ INGEST DOOR ─▶ web detector ─▶ alerts ─▶ dashboard
        (their machine)                (filters, redacts)             (validates, rate-limits)
```

## The pieces
| Piece | What it is | Where |
|---|---|---|
| **Collector** | Follows a log file, parses each line, applies the privacy policy, sends batches. Standard-library Python, one file | `collector/argus_collector.py` |
| **Parser** | Turns Nginx/Apache *combined* lines and JSON lines into one common event (`ts, src_ip, method, path, query, status, bytes, ua, host`) | inside the collector |
| **Ingest door** | `POST /api/ingest/events`, authenticated by a per-source API key (not a user login) | `api/routes/sources.py` |
| **Source** | A registered connection: name, kind, key (hash only), privacy policy, health | `sources` table |
| **Web detector** | Signature rules + behaviour tracking + text model | see [WEB_DETECTOR.md](WEB_DETECTOR.md) |
| **Coverage** | Which attack types the connected sources can and cannot see | `models/coverage.py`, `GET /api/coverage` |

A new log type (SSH logins, DNS, a firewall) means writing one new parser and detector; the door, keys, privacy policy, health tracking, alerts and dashboard are reused.

## Privacy: the client decides what Argus sees
* **Opt-in.** Nothing is read until an Admin creates a source and runs the collector.
* **Filtering happens on the client's machine, before sending.** Excluded paths are never sent; sensitive query parameters (`password`, `token`, `user_token`, `session`, ...) are replaced by `[REDACTED]`; client IPs can be replaced by stable pseudonyms (`100.64.0.0/10`).
* **Central policy.** The Admin edits the policy in the dashboard; the collector fetches it every 30 s and applies it *together with* its own flags (the stricter union wins).
* **Server-side safety net.** Argus enforces exclusions and redaction again on arrival, so a misconfigured collector cannot leak what the policy forbids.
* **Minimal fields.** Cookies, authorization headers and bodies are never read. `--dry-run` shows exactly what would leave.
* The client can revoke access instantly: **revoke** the key (the collector then gets `401`) or stop the collector.

## API keys
`agk_` + 256 random bits. Only the SHA-256 hash is stored; the key is shown **once**. Keys can be **rotated** (old key dies immediately) or **revoked**; deleting a source destroys the key but keeps recorded alerts. Invalid keys are throttled per IP (30 per 15 minutes), and each source is rate-limited (default 1,000 events/s sustained).

## Delivery guarantees (end to end)
The collector commits its read position only after Argus acknowledges a batch (**no loss**), every event has a stable ID derived from the file position, and Argus ignores IDs it already stored (**no duplicates**). Rotation, truncation, partial lines, oversized lines, outages and restarts are handled and tested (`tests/test_collector.py`).

## Demo mode vs Live mode
| | Demo mode | Live mode |
|---|---|---|
| When | no healthy live source | at least one source is connected |
| Data | simulated traffic, clearly labelled | only real events (analytics can be scoped to *live*, *demo*, *uploads*, *all*) |
| Simulator | on | switches itself off (**Auto**); an Admin can force it **On** or **Off** in Settings |
| Coverage | all 15 attack types shown as *demo* | each type shown as *covered*, *silent* or *not covered* |

A source that stops reporting becomes **silent** after 150 s (the collector sends a heartbeat every 30 s even on a quiet site); coverage shows the warning and Live mode ends until it reconnects. Attackers sometimes disable logging, so silence is itself a signal.

## Coverage: the honest answer to "do you see everything?"
No monitoring product does. The dashboard says exactly what the connected sources can see:

| Source | Covers |
|---|---|
| **Web server access log** (available) | SQL Injection, XSS, Brute Force (web logins), Path Traversal, Command Injection, Web Reconnaissance, DDoS (HTTP floods) |
| Flow CSV upload (available, not real-time) | the 11 flow-trained classes + Zero-Day |
| Honeypot, auth logs, endpoint (EDR), network flow, email gateway | *planned*: Malware, Ransomware, Botnet, Insider Threat, MITM, Phishing, Port Scanning, ... |

Every uncovered attack type lists what would cover it (for example *Ransomware: endpoint or file-server logs*).

## Known limits
* Access logs contain URLs, **not request bodies**: attacks inside POST bodies are invisible (needs a WAF or application logs).
* One client address is assumed to be one user (NAT can distort rate-based rules).
* The text model and thresholds are evaluated on generated data; see the honesty notes in WEB_DETECTOR.md.
* Single-node: the behaviour windows live in memory (they reset on restart) and the database is SQLite.
