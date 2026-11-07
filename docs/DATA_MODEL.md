# Data model

SQLite (WAL mode). Schema is created idempotently by `app/db/database.py`.

| Table | Key columns | Notes |
|---|---|---|
| `users` | username (unique, case-insensitive), full_name, password_hash (scrypt), role, is_active, last_login | roles: Viewer / Analyst / Admin; databases from earlier versions are upgraded automatically on start |
| `events` | **source_id, eid** (stable id for idempotent ingestion), ts, src_ip, dst_ip, dst_port, protocol, features_json, payload_sample (≤500 chars), verdict, attack_type, confidence, risk_score, severity, sources_json, origin, job_id, alert_id, blocked | one row per analysed event (uploads store threats only) |
| `alerts` | first_seen, last_seen, **count**, attack_type, severity, risk_score, confidence, src_ip, dst_ip, status, explanation_json, handled_by | de-duplicated by (src_ip, attack_type) inside `DEDUPE_WINDOW_SECONDS` while open/acknowledged |
| `mitigations` | alert_id, solution_id, title, rule_text, status=`simulated`, applied_by | what the analyst chose; nothing is executed |
| `blocklist` | ip (PK), reason, alert_id, created_by | simulated; later events from these IPs are marked `blocked` |
| `sources` | name, kind, key_prefix, **key_hash** (SHA-256; never returned), policy_json, last_seen, last_heartbeat, events/threats/rejected totals, revoked_at | one row per connected system; the key itself is never stored |
| `upload_jobs` | filename, created_by, status, rows_total, rows_flagged, summary_json | visible to the uploader and to Admins; deleting a log can optionally delete its alerts/events |
| `model_runs` | created_at, dataset, is_active, report_json | full metrics of each training run, stored in the DB |
| `audit_log` | ts, username, action, target, detail, ip | logins (incl. failures/lockouts), status changes, mitigations, uploads, reports, retraining, user changes |
| `settings` | key, value | runtime toggles (simulator) |

Retention: events and resolved alerts older than `RETENTION_DAYS` are purged hourly; **open alerts are never purged**; audit entries are kept ≥ 90 days.

## Feature schema (34 model inputs)

30 raw features + 4 derived (`bytes_per_sec`, `pkts_per_sec`, `avg_pkt_size`, `byte_ratio`), heavy-tailed ones `log1p`-compressed. Groups:

* **Flow:** duration, protocol flags, dst_port, bytes/packets each way
* **Behaviour (per source, 60 s window):** conn_count_src, distinct_dst_ports, distinct_dst_hosts, failed_logins, error_rate, syn_ratio
* **Payload text:** payload_len, payload_entropy, special_char_ratio, sql_kw_count, script_tag_count, has_ip_url, phish_kw_count
* **Context / enrichment:** domain_age_days, cert_mismatch, latency_ratio, off_hours, unusual_dest
* **Malware/C2:** smb_write_rate, beacon_interval_std, dns_query_rate

Full definitions and units: `data/schemas/feature_schema.json`. Missing columns in an upload fall back to the values of an ordinary HTTPS page load; the upload result reports how many were defaulted.
