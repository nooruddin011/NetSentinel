# The Argus lab: attack a real website and watch Argus detect it, live

Everything runs on **your own computer** in Docker, bound to `127.0.0.1` (nothing is reachable from other machines).

```
 you (browser / attack tools) ─▶ target-proxy (nginx) ─▶ DVWA (vulnerable site)
                                      │ writes access.log
                                      ▼
                                  collector ─▶ Argus backend ─▶ Argus dashboard (you watch here)
```
**Only attack the lab target.** Attacking systems you do not own is illegal.

## 0. One-time setup
Install **Docker Desktop** (free for personal and educational use). On Windows keep the *WSL 2* option ticked, restart, and check `docker run hello-world` works. You need about 4 GB of free RAM.

## 1. Start everything
From the project folder:
```bash
docker compose -f lab/docker-compose.lab.yml up --build -d
```
The first run downloads images and builds Argus (several minutes). Check all services are up: `docker compose -f lab/docker-compose.lab.yml ps`.

| What | Address | Login |
|---|---|---|
| Argus dashboard | http://localhost:8080 | `admin` / `Lab-Admin-Passw0rd!` |
| Target website (DVWA) | http://localhost:8081 | `admin` / `password` (after step 2) |

## 2. Prepare the target (once)
1. Open http://localhost:8081/setup.php and click **Create / Reset Database**.
2. Sign in with `admin` / `password`.
3. Open **DVWA Security** and set the level to **Low**.

## 3. Confirm Argus is connected
Dashboard → **Sources**: *Lab web server (DVWA)* should show **Connected**. The **Overview** switches to **Live mode** and the *simulated demo feed* turns itself off.
If it stays on "Waiting": `docker compose -f lab/docker-compose.lab.yml logs collector`.

## 4. Attack it in the browser
In DVWA (left menu) try these. Each produces a request with the payload in the URL, so it appears in the access log:

| Page | Type | Example |
|---|---|---|
| SQL Injection | SQL injection | `1' OR '1'='1` in *User ID*, press Submit |
| XSS (Reflected) | script injection | `<script>alert(1)</script>` in the name box |
| Brute Force | password guessing | submit the login form 10+ times quickly with different passwords |
| File Inclusion | path traversal | change the URL to `?page=../../../../etc/passwd` |

Watch **Alerts** and **Overview** update within about two seconds. Open an alert: you see the request, the evidence, the explanation, and mitigation options (which generate firewall/WAF rules; nothing is executed).

*Not visible:* DVWA's *Command Injection* page sends its input in a POST **body**, and access logs do not record bodies. This is a genuine limit of log-based monitoring (see docs/WEB_DETECTOR.md).

## 5. Or run real attack tools
Automated demo (no tools needed; runs on your computer against the target):
```bash
python lab/attack_demo.py                  # SQLi, XSS, traversal, command injection, brute force, scan, flood
python lab/attack_demo.py sqli xss brute   # only some
```
Real tools in a throwaway Kali container:
```bash
docker compose -f lab/docker-compose.lab.yml --profile attacker run --rm attacker
# inside it (takes a few minutes to install the first time):
sqlmap -u "http://target-proxy/vulnerabilities/sqli/?id=1&Submit=Submit" --batch --level=1
nikto -h http://target-proxy
```
(`sqlmap`/`nikto`/`hydra` identify themselves in the User-Agent, which Argus also detects. DVWA pages need a logged-in session to *succeed*, but the requests are logged and detected either way.)

## Notes
* All requests appear to come from the Docker gateway address (Docker Desktop's NAT), so every attacker shares one IP; on Linux you see real addresses.
* Verify the detection chain **without Docker**: `python scripts/verify_connector_pipeline.py`.
* If the `ghcr.io/digininja/dvwa` image changes or is unavailable, replace the `dvwa` and `db` services with the single-container image `vulnerables/web-dvwa` (service name must stay `dvwa`).
* Stop: `docker compose -f lab/docker-compose.lab.yml down`. Wipe all lab data too: add `-v`.
* The passwords and API key in the compose file are published and for this lab only. Argus refuses to start with that pre-shared key when `APP_ENV=production`.
