"""Password hashing with scrypt from the standard library (memory-hard, salted)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        _N, _R, _P, base64.b64encode(salt).decode(), base64.b64encode(dk).decode()
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False


_COMMON = {"password1234", "password123!", "passw0rd123", "welcome1234", "qwerty12345", "admin12345", "letmein1234",
           "changeme123", "iloveyou123", "abcd123456", "administrator1"}


def password_problems(password: str, username: str | None = None) -> list:
    """Policy: 10+ characters, upper + lower case, a digit, not trivially common, not containing the username."""
    problems = []
    if len(password) < 10:
        problems.append("must be at least 10 characters")
    if not any(c.islower() for c in password) or not any(c.isupper() for c in password):
        problems.append("must contain upper and lower case letters")
    if not any(c.isdigit() for c in password):
        problems.append("must contain a digit")
    if password.lower() in _COMMON:
        problems.append("is too common")
    if username and len(username) >= 3 and username.lower() in password.lower():
        problems.append("must not contain your username")
    return problems


def password_version(stored_hash: str) -> str:
    """Short fingerprint of the current password hash. Embedded in JWTs so that changing or resetting a
    password immediately invalidates every older session."""
    return hashlib.sha256(stored_hash.encode("utf-8")).hexdigest()[:12]
