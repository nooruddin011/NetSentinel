"""Minimal HS256 JSON Web Tokens (RFC 7519) using only the standard library.

Hardening: the algorithm is pinned (tokens claiming any other `alg`, including "none", are
rejected), signatures are compared in constant time, and `exp` is mandatory.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid


class TokenError(Exception):
    pass


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(signing_input: bytes, secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()


def encode_token(claims: dict, secret: str, ttl_seconds: int) -> str:
    now = int(time.time())
    payload = {**claims, "iat": now, "exp": now + int(ttl_seconds), "jti": uuid.uuid4().hex}
    header = {"alg": "HS256", "typ": "JWT"}
    head = _b64e(json.dumps(header, separators=(",", ":")).encode())
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64e(_sign(f"{head}.{body}".encode("ascii"), secret))
    return f"{head}.{body}.{sig}"


def decode_token(token: str, secret: str) -> dict:
    try:
        head_b64, body_b64, sig_b64 = token.split(".")
        header = json.loads(_b64d(head_b64))
        if header.get("alg") != "HS256":
            raise TokenError("unsupported algorithm")
        expected = _sign(f"{head_b64}.{body_b64}".encode("ascii"), secret)
        if not hmac.compare_digest(expected, _b64d(sig_b64)):
            raise TokenError("bad signature")
        payload = json.loads(_b64d(body_b64))
    except TokenError:
        raise
    except Exception as exc:  # malformed base64 / json / structure
        raise TokenError("malformed token") from exc
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or exp < time.time():
        raise TokenError("token expired")
    return payload
