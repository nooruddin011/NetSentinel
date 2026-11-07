#!/usr/bin/env python3
"""Argus collector: streams new web-server access-log lines to an Argus dashboard, in real time.

Runs next to the web server (Nginx, Apache, Caddy, ...). Python 3.8+, standard library only.

    python argus_collector.py --url https://argus.example.com --file /var/log/nginx/access.log
    (the API key comes from the ARGUS_KEY environment variable or --key-file; create it in the dashboard under Sources)

Design guarantees
  * Privacy first   Secrets are redacted and excluded paths are dropped HERE, on your machine, before anything is sent.
                    Optionally client IPs are replaced by stable pseudonyms (--pseudonymize-ips).
  * No loss         The read position is saved only after the server confirms a batch, so a crash or outage never skips lines.
  * No duplicates   Every event carries a stable ID; the server ignores IDs it has already stored.
  * Robust          Log rotation, truncation, partial lines, oversized lines, malformed lines, server outages (backs off and retries).
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import hmac
import json
import logging
import os
import re
import signal
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

VERSION = "1.0.0"
MAX_LINE_BYTES = 16 * 1024
REDACTED = "[REDACTED]"
DEFAULT_REDACT = ["password", "passwd", "pass", "pwd", "token", "user_token", "csrf_token", "_token", "authenticity_token", "access_token",
                  "refresh_token", "jwt", "auth", "secret", "api_key", "apikey", "authorization", "session", "sessionid", "csrf"]
log = logging.getLogger("argus-collector")

# ----------------------------------------------------------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------------------------------------------------------
_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}|-) (?P<bytes>\d+|-)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?')
_TIME = re.compile(r"(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})")
_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_ESC = re.compile(r"\\x([0-9A-Fa-f]{2})|\\([\"\\])")


def unescape(s: str) -> str:
    """Undo the escaping Nginx/Apache apply inside quoted log fields (\\xHH, \\", \\\\), re-assembling UTF-8 bytes."""
    if "\\" not in s:
        return s
    out, pos = bytearray(), 0
    for m in _ESC.finditer(s):
        out += s[pos:m.start()].encode("utf-8", "replace")
        out += bytes([int(m.group(1), 16)]) if m.group(1) else m.group(2).encode()
        pos = m.end()
    out += s[pos:].encode("utf-8", "replace")
    return out.decode("utf-8", "replace")


def parse_clf_time(text: str):
    m = _TIME.match(text.strip())
    if not m or m.group(2) not in _MONTHS:
        return None
    d, mon, y, hh, mm, ss, sign, th, tm = m.groups()
    try:
        tz = timezone((1 if sign == "+" else -1) * timedelta(hours=int(th), minutes=int(tm)))
        return datetime(int(y), _MONTHS[mon], int(d), int(hh), int(mm), int(ss), tzinfo=tz).timestamp()
    except (ValueError, OverflowError):
        return None


def split_request(req: str):
    """'GET /a?b=1 HTTP/1.1' -> (method, path, query, host). Tolerates spaces inside the target and absolute URIs."""
    parts = req.split(" ")
    if len(parts) < 2 or not parts[0] or parts[0] == "-":
        return None
    method = parts[0]
    rest = parts[1:]
    if len(rest) > 1 and rest[-1].upper().startswith("HTTP/"):
        rest = rest[:-1]
    target, host = " ".join(rest), ""
    if target.lower().startswith(("http://", "https://")):  # proxy-style absolute URI
        u = urlparse(target)
        host, target = u.netloc, (u.path or "/") + (("?" + u.query) if u.query else "")
    path, _, query = target.partition("?")
    return method, path or "/", query, host


def parse_combined(line: str):
    m = _COMBINED.match(line)
    if not m:
        return None
    sr = split_request(unescape(m.group("req")))
    if not sr or m.group("ip") == "-":
        return None
    method, path, query, host = sr
    ua = unescape(m.group("ua") or "")
    return dict(ts=parse_clf_time(m.group("time")), src_ip=m.group("ip"), method=method, path=path, query=query, host=host,
                status=int(m.group("status")) if m.group("status") != "-" else 0,
                bytes=int(m.group("bytes")) if m.group("bytes") != "-" else 0, ua="" if ua == "-" else ua)


def _flatten(obj, prefix="", out=None):
    out = {} if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten(v, f"{prefix}{str(k).lower()}.", out)
            if not isinstance(v, (dict, list)):
                out.setdefault(str(k).lower(), v)
    elif isinstance(obj, list) and obj and not isinstance(obj[0], (dict, list)):
        out[prefix.rstrip(".")] = obj[0]
        out.setdefault(prefix.rstrip(".").rsplit(".", 1)[-1], obj[0])
    elif not isinstance(obj, (dict, list)) and prefix:
        out[prefix.rstrip(".")] = obj
    return out


_J = dict(
    ip=["remote_addr", "client_ip", "clientip", "remote_ip", "src_ip", "ip", "request.remote_ip", "request.client_ip", "http_x_forwarded_for"],
    method=["request_method", "method", "request.method", "verb"],
    uri=["request_uri", "uri", "request.uri", "url", "path", "req.url", "request_path"],
    request=["request"],
    status=["status", "response_code", "status_code", "resp.status", "response.status"],
    bytes=["body_bytes_sent", "bytes_sent", "bytes", "size", "response_size", "resp_size"],
    ua=["http_user_agent", "user_agent", "ua", "agent", "request.headers.user-agent", "request.headers.user_agent"],
    host=["host", "http_host", "server_name", "request.host"],
    time=["time_iso8601", "timestamp", "@timestamp", "ts", "time", "time_local"],
)


def parse_json_line(line: str):
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    flat = _flatten(obj)
    pick = lambda key: next((flat[k] for k in _J[key] if flat.get(k) not in (None, "")), None)  # noqa: E731
    ip, uri, method = pick("ip"), pick("uri"), pick("method")
    if not (isinstance(ip, str) and ip):
        return None
    ip = ip.split(",")[0].strip()  # X-Forwarded-For lists: the first entry is the client
    if uri is None or method is None:
        req = pick("request")
        sr = split_request(str(req)) if isinstance(req, str) else None
        if not sr:
            return None
        method, path, query, host = sr
    else:
        path, _, query = str(uri).partition("?")
        host = ""
    t = pick("time")
    ts = None
    if isinstance(t, (int, float)):
        ts = float(t) / 1000.0 if t > 1e11 else float(t)
    elif isinstance(t, str):
        ts = parse_clf_time(t)
        if ts is None:
            try:
                dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                ts = (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
            except ValueError:
                ts = None
    try:
        status, size = int(pick("status") or 0), int(pick("bytes") or 0)
    except (TypeError, ValueError):
        status, size = 0, 0
    return dict(ts=ts, src_ip=ip, method=str(method).upper(), path=path or "/", query=query, host=str(pick("host") or host or ""),
                status=status, bytes=size, ua=str(pick("ua") or ""))


def parse_line(line: str, fmt: str):
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    if fmt == "json" or (fmt == "auto" and line.lstrip().startswith("{")):
        return parse_json_line(line)
    return parse_combined(line)


# ----------------------------------------------------------------------------------------------------------------------
# Privacy (applied locally, before anything leaves this machine)
# ----------------------------------------------------------------------------------------------------------------------
class Privacy:
    def __init__(self, exclude_paths=(), redact_params=(), pseudonymize=False, salt: bytes = b""):
        self.exclude = [p if p.startswith("/") else "/" + p for p in exclude_paths if p]
        self.redact = {p.lower() for p in redact_params if p}
        self.pseudonymize, self.salt = pseudonymize, salt

    def merged(self, server_policy: dict | None):
        """Local flags AND the dashboard's policy both apply (the stricter union wins)."""
        sp = server_policy or {}
        return Privacy(set(self.exclude) | set(sp.get("exclude_paths") or []), self.redact | set(sp.get("redact_params") or []),
                       self.pseudonymize or bool(sp.get("pseudonymize_ips")), self.salt)

    def pseudonym(self, ip: str) -> str:
        h = hmac.new(self.salt, ip.encode(), hashlib.sha256).digest()
        return f"100.{64 + (h[0] & 0x3F)}.{h[1]}.{h[2]}"  # carrier-grade-NAT range: never a real public address

    def apply(self, ev: dict):
        """Return the event ready to send, or None if its path is excluded."""
        if any(ev["path"].startswith(p) for p in self.exclude):
            return None
        if self.redact and ev["query"]:
            ev["query"] = "&".join(f"{k}={REDACTED}" if sep and k.lower() in self.redact else part
                                   for part in ev["query"].split("&") for k, sep, _v in [part.partition("=")])
        if self.pseudonymize:
            ev["src_ip"] = self.pseudonym(ev["src_ip"])
        return ev


def load_salt(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            data = f.read().strip()
            if len(data) >= 32:
                return data
    except OSError:
        pass
    data = os.urandom(32).hex().encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return data


# ----------------------------------------------------------------------------------------------------------------------
# Tailing files with rotation handling and committed offsets
# ----------------------------------------------------------------------------------------------------------------------
class State:
    """Remembers (inode, offset) per file in a small JSON file, written atomically."""

    def __init__(self, path):
        self.path, self.data = path, {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, inode, offset):
        self.data[key] = dict(inode=inode, offset=offset)

    def save(self):
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f)
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("could not save state file %s: %s", self.path, exc)


class Tailer:
    def __init__(self, path: str, state: State, from_start: bool):
        self.path, self.state, self.from_start = path, state, from_start
        self.fh = None
        self.inode = None
        self.offset = 0          # offset of the next unread byte
        self.committed = 0       # offset the server has acknowledged
        self.new_file = False

    # -- opening / rotation ------------------------------------------------------------------------------------------
    def _open(self, start_at_end_if_unknown: bool):
        st = os.stat(self.path)
        fh = open(self.path, "rb")
        saved = self.state.get(self.path)
        if saved and saved.get("inode") == st.st_ino and saved.get("offset", 0) <= st.st_size:
            off = saved["offset"]                       # resume exactly where we stopped
        elif saved:
            off = 0                                     # same path, different file (rotated while we were down)
        else:
            off = st.st_size if (start_at_end_if_unknown and not self.from_start) else 0
        fh.seek(off)
        self.fh, self.inode, self.offset, self.committed = fh, st.st_ino, off, off
        log.info("tailing %s (inode %s) from byte %d", self.path, st.st_ino, off)

    def _check_rotation(self):
        """Called at EOF. Returns True if a new file now lives at the path (or the file was truncated)."""
        try:
            st = os.stat(self.path)
        except OSError:
            return False
        if st.st_ino != self.inode:                    # rename + create (logrotate default)
            self.fh.close()
            fh = open(self.path, "rb")
            self.fh, self.inode, self.offset, self.committed = fh, st.st_ino, 0, 0
            log.info("log rotated: now reading new file %s", self.path)
            return True
        if st.st_size < self.offset:                   # copytruncate
            self.fh.seek(0)
            self.offset, self.committed = 0, 0
            log.info("log truncated: restarting %s from the beginning", self.path)
            return True
        return False

    def read(self, max_lines: int):
        """Return up to max_lines complete lines as (line_start_offset, text). Partial last lines are left for later."""
        if self.fh is None:
            try:
                self._open(start_at_end_if_unknown=not self.new_file)
            except OSError:
                return []
        out = []
        while len(out) < max_lines:
            start = self.offset
            raw = self.fh.readline(MAX_LINE_BYTES + 1)
            if not raw:
                if not self._check_rotation():
                    break
                continue
            if not raw.endswith(b"\n"):
                if len(raw) > MAX_LINE_BYTES:           # absurdly long line: skip it entirely
                    while raw and not raw.endswith(b"\n"):
                        raw = self.fh.readline(MAX_LINE_BYTES)
                    self.offset = self.fh.tell()
                    out.append((start, ""))              # empty text -> counted as skipped, offset still advances
                    continue
                self.fh.seek(start)                      # incomplete line (writer mid-write): try again later
                break
            self.offset = self.fh.tell()
            out.append((start, raw.decode("utf-8", "replace")))
        return out

    def commit(self):
        """The server confirmed everything read so far: persist the position."""
        self.committed = self.offset
        self.state.set(self.path, self.inode, self.committed)

    def rollback(self):
        """The server did NOT confirm: go back to the last committed position and read again later."""
        if self.fh is not None:
            self.fh.seek(self.committed)
            self.offset = self.committed

    def close(self):
        if self.fh is not None:
            self.fh.close()
            self.fh = None


# ----------------------------------------------------------------------------------------------------------------------
# Transport
# ----------------------------------------------------------------------------------------------------------------------
class HttpTransport:
    def __init__(self, base_url, key, verify_tls=True, timeout=15):
        self.base, self.key, self.timeout = base_url.rstrip("/"), key, timeout
        self.ctx = None
        if base_url.lower().startswith("https"):
            self.ctx = ssl.create_default_context()
            if not verify_tls:
                self.ctx.check_hostname, self.ctx.verify_mode = False, ssl.CERT_NONE
        host = urlparse(base_url).hostname or ""
        if base_url.lower().startswith("http://") and host not in ("localhost", "127.0.0.1", "::1"):
            log.warning("The API key is sent over plain HTTP to %s. Use HTTPS unless this is a private network.", host)

    def _call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Content-Type": "application/json", "X-Argus-Key": self.key, "User-Agent": f"argus-collector/{VERSION}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                return r.status, _json(r.read())
        except urllib.error.HTTPError as e:
            return e.code, _json(e.read())
        except (urllib.error.URLError, OSError, ValueError) as e:
            return 0, {"detail": str(e)}

    def send_events(self, events):
        return self._call("POST", "/api/ingest/events", {"events": events})

    def heartbeat(self, info):
        return self._call("POST", "/api/ingest/heartbeat", info)

    def policy(self):
        return self._call("GET", "/api/ingest/policy")


def _json(raw):
    try:
        return json.loads(raw.decode("utf-8", "replace") or "{}")
    except ValueError:
        return {}


# ----------------------------------------------------------------------------------------------------------------------
# The collector loop
# ----------------------------------------------------------------------------------------------------------------------
class Collector:
    def __init__(self, files, transport, privacy: Privacy, state: State, fmt="auto", batch_size=200, from_start=False,
                 heartbeat_interval=30, poll_interval=0.5, sleep=time.sleep, dry_run=False):
        self.patterns, self.transport, self.local_privacy, self.state = files, transport, privacy, state
        self.privacy = privacy
        self.fmt, self.batch, self.from_start = fmt, batch_size, from_start
        self.hb_every, self.poll, self.sleep, self.dry = heartbeat_interval, poll_interval, sleep, dry_run
        self.tailers = {}
        self.stats = dict(lines_read=0, events_sent=0, events_failed=0, skipped=0, excluded=0, duplicates=0, batches=0)
        self._last_hb = 0.0
        self._last_discovery = 0.0
        self._backoff = 0.0
        self._first_discovery = True
        self.stop = False
        self.fatal_auth = False

    # -- discovery ----------------------------------------------------------------------------------------------------
    def discover(self, now=None):
        now = now if now is not None else time.time()
        if now - self._last_discovery < 5 and self.tailers:
            return
        self._last_discovery = now
        for pattern in self.patterns:
            for path in sorted(glob.glob(pattern)):
                path = os.path.abspath(path)
                if path not in self.tailers and os.path.isfile(path):
                    t = Tailer(path, self.state, self.from_start)
                    t.new_file = not self._first_discovery   # files that appear later are read from their first byte
                    self.tailers[path] = t
        self._first_discovery = False

    # -- one pass over all files ----------------------------------------------------------------------------------------
    def step(self) -> int:
        """Read what is available, send it, commit on success. Returns the number of lines handled."""
        self.discover()
        handled = 0
        for t in list(self.tailers.values()):
            lines = t.read(self.batch)
            if not lines:
                continue
            events, skipped, excluded = [], 0, 0
            for start, text in lines:
                ev = parse_line(text, self.fmt) if text else None
                if ev is None:
                    skipped += 1
                    continue
                if ev["ts"] is None:
                    ev["ts"] = time.time()
                ev = self.privacy.apply(ev)
                if ev is None:
                    excluded += 1
                    continue
                ev["eid"] = hashlib.sha1(f"{t.inode}|{start}|{text}".encode("utf-8", "replace")).hexdigest()[:24]
                events.append(ev)
            self.stats["lines_read"] += len(lines)
            if self._deliver(events):
                t.commit()
                self.state.save()
                self.stats["skipped"] += skipped
                self.stats["excluded"] += excluded
                handled += len(lines)
            else:
                t.rollback()   # nothing lost: the same lines will be read again after the back-off
                self.stats["lines_read"] -= len(lines)
        self._heartbeat_if_due()
        return handled

    def _deliver(self, events) -> bool:
        if not events or self.dry:
            if self.dry:
                for ev in events:
                    print(json.dumps(ev))
            return True
        for chunk_size in [len(events)] + [c for c in (100, 25, 5, 1) if c < len(events)]:
            ok = True
            for i in range(0, len(events), chunk_size):
                chunk = events[i:i + chunk_size]
                code, body = self.transport.send_events(chunk)
                if code == 413 and chunk_size > 1:
                    ok = None
                    break
                if 200 <= code < 300:
                    self.stats["events_sent"] += body.get("accepted", len(chunk))
                    self.stats["duplicates"] += body.get("duplicates", 0)
                    self.stats["batches"] += 1
                    self._backoff = 0.0
                    continue
                if code == 413:                              # a single event is too large: drop it, keep going
                    log.error("dropping an event the server refuses as too large")
                    self.stats["events_failed"] += 1
                    continue
                if code in (401, 403):
                    self.fatal_auth = True
                    log.critical("The server rejected the API key (revoked or rotated?). Retrying every 60 s: %s", body.get("detail", ""))
                    self._wait(60)
                    return False
                if code in (400, 422):                       # malformed for the server: retrying cannot help, drop and move on
                    log.error("server rejected a batch (%s): %s - dropping it", code, body.get("detail", ""))
                    self.stats["events_failed"] += len(chunk)
                    continue
                self._backoff = min(60.0, max(1.0, self._backoff * 2 or 1.0))      # 0 (network), 429, 5xx
                log.warning("server unavailable or busy (code %s: %s); retrying in %.0f s", code, body.get("detail", ""), self._backoff)
                self._wait(self._backoff)
                return False
            if ok is None:
                continue          # retry the whole batch with a smaller chunk size
            self.fatal_auth = False
            return True
        return True

    def _wait(self, seconds):
        remaining = float(seconds)
        while not self.stop and remaining > 0:
            step = min(0.5, remaining)
            self.sleep(step)
            remaining -= step

    def _heartbeat_if_due(self, force=False):
        now = time.time()
        if not force and now - self._last_hb < self.hb_every:
            return
        self._last_hb = now
        if self.dry:
            return
        info = dict(version=VERSION, hostname=socket.gethostname()[:100], files=list(self.tailers)[:20], lines_read=self.stats["lines_read"],
                    events_sent=self.stats["events_sent"], events_failed=self.stats["events_failed"], queue_size=0)
        code, body = self.transport.heartbeat(info)
        if 200 <= code < 300:
            self.privacy = self.local_privacy.merged(body.get("policy"))
        elif code in (401, 403):
            log.critical("heartbeat rejected: the API key is invalid or revoked")

    def run(self):
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "stop", True))
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, lambda *_: setattr(self, "stop", True))
        self._heartbeat_if_due(force=True)
        log.info("running; press Ctrl+C to stop")
        while not self.stop:
            if self.step() == 0:
                self.sleep(self.poll)
        self.state.save()
        log.info("stopped. %s", self.stats)


# ----------------------------------------------------------------------------------------------------------------------
# Command line
# ----------------------------------------------------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("ARGUS_URL"), help="dashboard address, e.g. https://argus.example.com (or env ARGUS_URL)")
    ap.add_argument("--key-file", help="file containing the API key (alternative to the ARGUS_KEY environment variable)")
    ap.add_argument("--file", action="append", required=True, help="access log to follow (repeatable; wildcards allowed)")
    ap.add_argument("--format", choices=["auto", "combined", "json"], default="auto", help="log format (default: detect per line)")
    ap.add_argument("--from-start", action="store_true", help="read existing files from their first line instead of only new lines")
    ap.add_argument("--once", action="store_true", help="process what is there now, then exit (batch / test mode)")
    ap.add_argument("--dry-run", action="store_true", help="parse and print events as JSON; send nothing")
    ap.add_argument("--exclude-path", action="append", default=[], help="never send requests whose path starts with this (repeatable)")
    ap.add_argument("--redact-param", action="append", default=[], help="also redact this query parameter's value (repeatable)")
    ap.add_argument("--pseudonymize-ips", action="store_true", help="replace client IPs with stable pseudonyms (100.64.0.0/10)")
    ap.add_argument("--salt-file", default="argus_collector.salt", help="secret salt for pseudonyms (created on first use, keep it private)")
    ap.add_argument("--state-file", default="argus_collector.state.json", help="where read positions are saved")
    ap.add_argument("--batch-size", type=int, default=200)
    ap.add_argument("--heartbeat-interval", type=int, default=30)
    ap.add_argument("--insecure-skip-tls-verify", action="store_true", help="do not verify the server certificate (not recommended)")
    ap.add_argument("--log-level", default="INFO")
    ap.add_argument("--version", action="version", version=f"argus-collector {VERSION}")
    a = ap.parse_args(argv)
    logging.basicConfig(level=getattr(logging, a.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)-8s %(message)s")

    key = os.environ.get("ARGUS_KEY", "")
    if a.key_file:
        with open(a.key_file, "r", encoding="utf-8") as f:
            key = f.read().strip()
    if not a.dry_run and (not a.url or not key):
        ap.error("--url and an API key (ARGUS_KEY environment variable or --key-file) are required")
    salt = load_salt(a.salt_file) if a.pseudonymize_ips else b""
    local = Privacy(a.exclude_path, set(DEFAULT_REDACT) | set(a.redact_param), a.pseudonymize_ips, salt)
    transport = HttpTransport(a.url or "", key, not a.insecure_skip_tls_verify)
    if not a.dry_run:
        code, body = transport.policy()
        if code in (401, 403):
            print("ERROR: the server rejected the API key. Check it was copied completely, and that the source is not revoked.", file=sys.stderr)
            return 2
        if code == 0:
            log.warning("cannot reach %s yet (%s); will keep trying", a.url, body.get("detail"))
        else:
            log.info("connected to Argus as source '%s'", body.get("name", "?"))
    col = Collector(a.file, transport, local, State(a.state_file), a.format, a.batch_size, a.from_start, a.heartbeat_interval, dry_run=a.dry_run)
    if a.once:
        col.from_start = True
        col._heartbeat_if_due(force=True)   # fetch the dashboard's privacy policy before sending anything
        col.discover()
        while col.step():
            pass
        print(json.dumps(col.stats))
        return 0
    col.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
