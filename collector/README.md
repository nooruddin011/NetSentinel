# Argus collector

A small program that runs **next to your web server**, follows its access log, and streams new requests to your Argus dashboard in real time. One file, Python 3.8+, **no dependencies**.

```
your web server ──writes──▶ access.log ──read by──▶ argus_collector.py ──HTTPS──▶ Argus dashboard
                                                     (filters + redacts here)
```

## 1. Get an API key
In the dashboard: **Sources → Connect a source** (Admin). Choose what to hide, then copy the key. It is shown **once**; if you lose it, rotate it.

## 2. Run it
```bash
export ARGUS_KEY='agk_...'          # Windows (PowerShell): $env:ARGUS_KEY = 'agk_...'
python argus_collector.py --url https://argus.example.com --file /var/log/nginx/access.log
```
Useful options (`--help` lists all):

| Option | Meaning |
|---|---|
| `--file PATH` | log to follow; repeat for several files; wildcards allowed (`/var/log/nginx/*.log`) |
| `--format auto\|combined\|json` | default `auto` detects per line. Supports Nginx/Apache *combined* and JSON lines (Nginx JSON, Caddy, Traefik, custom) |
| `--from-start` | also send what is already in the file (default: only new lines) |
| `--exclude-path /health` | never send requests under this path (repeatable) |
| `--redact-param sid` | hide the value of this query parameter (repeatable; passwords/tokens are hidden by default) |
| `--pseudonymize-ips` | replace client IPs with stable pseudonyms before sending |
| `--dry-run` | print what *would* be sent, send nothing (use this first to check what leaves your server) |
| `--once` | process the file now and exit |

The dashboard can also set **exclusions, redactions and pseudonymisation centrally** (Sources → edit). The collector fetches that policy every 30 seconds and applies it together with its own flags (the stricter combination wins).

## What it sends, and what it never sends
Sent per request: time, client IP (or pseudonym), method, path, query string (secrets redacted), status, response size, User-Agent, host. **Never sent**: cookies, authorization headers, request bodies, response bodies, anything outside the log lines you point it at. Check with `--dry-run`.

## Behaviour you can rely on
* **No loss.** The read position is saved only after Argus confirms a batch. Crash, restart or an Argus outage never skips lines (it backs off 1 s → 60 s and retries).
* **No duplicates.** Every event has a stable ID derived from the file position; Argus ignores IDs it has seen.
* **Log rotation / truncation** (logrotate, `copytruncate`) are handled; the old file is read to its end first.
* **Partial lines** (the web server mid-write) wait until complete. **Oversized lines** (>16 KB) and **malformed lines** are skipped and counted, never fatal.
* A heartbeat every 30 s proves the collector is alive even when the site is quiet; if it stops, Argus marks the source **silent** and shows a warning.

## Run it as a service (Linux, systemd)
```ini
# /etc/systemd/system/argus-collector.service
[Unit]
Description=Argus collector
After=network-online.target
[Service]
User=argus
EnvironmentFile=/etc/argus-collector.env          # contains ARGUS_KEY=agk_...  (chmod 600)
ExecStart=/usr/bin/python3 /opt/argus/argus_collector.py --url https://argus.example.com --file /var/log/nginx/access.log --state-file /var/lib/argus/state.json
Restart=always
[Install]
WantedBy=multi-user.target
```
The `argus` user needs read access to the log (for example membership of the `adm` group).

## Troubleshooting
* *"server rejected the API key"*: the key was truncated when copied, or the source was revoked/rotated.
* *Nothing arrives*: check `--dry-run` prints events; confirm the log is in **combined** or JSON format; confirm the user can read the file.
* *All requests come from one IP (a proxy's)*: configure your web server to log the real client address (Nginx `real_ip_header X-Forwarded-For;`) or use a JSON format with the client IP field.
* Behind HTTPS with a private CA: set `SSL_CERT_FILE` to your CA bundle.
