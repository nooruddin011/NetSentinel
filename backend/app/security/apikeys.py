"""API keys for connectors ("the door").

A key looks like  agk_<43 url-safe chars>  (256 bits of randomness). Only its SHA-256 hash is stored, so a
database leak does not reveal usable keys; the full key is shown exactly once, at creation or rotation.
Because the secret is long and random, a plain fast hash is appropriate here (unlike human passwords).
"""
from __future__ import annotations

import hashlib
import re
import secrets

PREFIX = "agk_"
_KEY_RE = re.compile(r"^agk_[A-Za-z0-9_-]{32,64}$")


def generate_key():
    """Return (full_key, display_prefix, sha256_hash)."""
    full = PREFIX + secrets.token_urlsafe(32)
    return full, full[:10], hash_key(full)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def looks_like_key(value: str) -> bool:
    return bool(value) and bool(_KEY_RE.match(value))
