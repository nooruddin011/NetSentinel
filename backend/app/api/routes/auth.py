from __future__ import annotations

import sqlite3
import secrets
import logging

import requests
from cachecontrol import CacheControl
from google.auth import exceptions as google_auth_exceptions
from google.auth.transport.requests import Request as GoogleTransportRequest
from google.oauth2 import id_token as google_id_token
from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.deps import client_ip, current_user, get_ctx, require
from app.branding import APP_NAME
from app.schemas.api import GoogleCredential, LoginRequest, PasswordChange, RegisterRequest, UserCreate, UserUpdate
from app.security.jwt import encode_token
from app.security.passwords import hash_password, password_problems, password_version, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger(__name__)
# Verified against when the username does not exist, so response time doesn't reveal valid usernames.
_DUMMY_HASH = hash_password("dummy-password-for-timing")
DISABLED_MSG = "This account has been disabled by an administrator. Please contact an Admin."


class _BoundedGoogleRequest(GoogleTransportRequest):
    """Limit certificate fetches so an unavailable Google endpoint cannot hang sign-in."""
    def __call__(self, url, method="GET", body=None, headers=None, timeout=5, **kwargs):
        return super().__call__(url, method=method, body=body, headers=headers, timeout=min(timeout, 5), **kwargs)


_GOOGLE_VERIFY_REQUEST = _BoundedGoogleRequest(session=CacheControl(requests.Session()))


def _public(u: dict) -> dict:
    return dict(id=u["id"], username=u["username"], full_name=u.get("full_name"), role=u["role"],
                workspace_id=u.get("workspace_id"), workspace_name=u.get("workspace_name"))


def _issue(ctx, user: dict) -> dict:
    ttl = ctx.settings.jwt_ttl_minutes * 60
    token = encode_token({"sub": str(user["id"]), "role": user["role"], "name": user["username"],
                          "pv": password_version(user["password_hash"])}, ctx.settings.jwt_secret, ttl)
    return dict(access_token=token, token_type="bearer", expires_in=ttl, user=_public(user))


def registration_enabled(ctx) -> bool:
    return ctx.repo.get_setting("registration.enabled", str(ctx.settings.allow_self_registration)).lower() == "true"


def _policy_or_422(password: str, username: str):
    problems = password_problems(password, username)
    if problems:
        raise HTTPException(422, "Password " + ", ".join(problems))


def _verified_google_claims(credential: str, ctx) -> dict:
    if not ctx.settings.google_client_id:
        raise HTTPException(503, "Google sign-in is not configured on this server")
    try:
        claims = google_id_token.verify_oauth2_token(
            credential, _GOOGLE_VERIFY_REQUEST, audience=ctx.settings.google_client_id,
            clock_skew_in_seconds=60)
    except ValueError as exc:
        reason = str(exc).lower()
        if "audience" in reason or "recipient" in reason:
            category = "audience"
        elif "issuer" in reason:
            category = "issuer"
        elif "expired" in reason:
            category = "expired"
        elif "early" in reason or "issued" in reason:
            category = "time"
        elif "signature" in reason or "certificate" in reason:
            category = "signature"
        else:
            category = "invalid_token"
        # Never log the credential or decoded claims; record only a safe failure category.
        logger.warning("Google ID token verification rejected (%s)", category)
        raise HTTPException(401, "Google sign-in could not be verified. Please try again.")
    except google_auth_exceptions.GoogleAuthError:
        raise HTTPException(503, "Google sign-in verification is temporarily unavailable. Please try again.")
    subject = claims.get("sub")
    email = claims.get("email")
    if not subject or not email or claims.get("email_verified") is not True:
        raise HTTPException(403, "Google must provide a verified email address for this account")
    return {"subject": str(subject), "email": str(email).strip().lower(), "name": claims.get("name")}


@router.get("/config")
def public_config(ctx=Depends(get_ctx)):
    """Public: lets the login page know whether to offer 'Create account'."""
    return dict(app_name=APP_NAME, registration_enabled=registration_enabled(ctx),
                google_client_id=ctx.settings.google_client_id or None)


@router.post("/google")
def google_login(body: GoogleCredential, request: Request, ctx=Depends(get_ctx)):
    """Verify a Google ID token and exchange it for a normal NetSentinel session."""
    claims = _verified_google_claims(body.credential, ctx)
    user = ctx.repo.get_user_by_google_subject(claims["subject"])
    created = False
    if user is None:
        # Never merge accounts just because a Google email resembles a local username.
        if ctx.repo.get_user_by_name(claims["email"]):
            raise HTTPException(409, "An account may already use this email as its username. Sign in with that account and link Google from My Account.")
        if not registration_enabled(ctx):
            raise HTTPException(403, "New account creation is turned off. Ask a workspace Admin for an account, or sign in to your linked Google account.")
        ip = client_ip(request)
        key = f"register|{ip}"
        wait = ctx.reg_throttle.retry_after(key)
        if wait:
            raise HTTPException(429, "Too many sign-ups from this address. Try again later.", headers={"Retry-After": str(wait)})
        ctx.reg_throttle.failure(key)
        random_password_hash = hash_password(secrets.token_urlsafe(48))
        try:
            user_id, created = ctx.repo.register_google_user(
                claims["subject"], claims["email"], claims["name"], random_password_hash)
        except sqlite3.IntegrityError:
            # A simultaneous first sign-in may have inserted the same Google subject.
            user = ctx.repo.get_user_by_google_subject(claims["subject"])
            if not user:
                raise HTTPException(409, "Could not create the account. Please try signing in again.")
        else:
            user = ctx.repo.get_user(user_id)
    if not user:
        raise HTTPException(401, "Google account was not found")
    if not user["is_active"]:
        ctx.repo.audit(user["username"], "auth.google_disabled_login", None, None, client_ip(request), user["workspace_id"])
        raise HTTPException(403, DISABLED_MSG)
    ctx.throttle.success(f"google|{claims['subject']}|{client_ip(request)}")
    ctx.repo.touch_login(user["id"])
    ctx.repo.audit(user["username"], "auth.google_register" if created else "auth.google_login",
                   None, claims["email"], client_ip(request), user["workspace_id"])
    return _issue(ctx, user)


@router.get("/google/identity")
def google_identity(user=Depends(current_user), ctx=Depends(get_ctx)):
    identity = ctx.repo.get_google_identity(user["id"])
    return dict(linked=bool(identity), email=identity["email"] if identity else None)


@router.post("/google/link")
def link_google(body: GoogleCredential, request: Request, user=Depends(current_user), ctx=Depends(get_ctx)):
    claims = _verified_google_claims(body.credential, ctx)
    result = ctx.repo.link_google_identity(user["id"], claims["subject"], claims["email"])
    if result == "identity_in_use":
        raise HTTPException(409, "That Google account is already linked to another NetSentinel user")
    if result == "different_identity_linked":
        raise HTTPException(409, "This NetSentinel account already has a different Google account linked")
    if result == "user_not_found":
        raise HTTPException(404, "Account not found")
    ctx.repo.audit(user["username"], "auth.google_link", claims["email"], None, client_ip(request))
    return dict(linked=True, email=claims["email"])


@router.post("/login")
def login(body: LoginRequest, request: Request, ctx=Depends(get_ctx)):
    ip = client_ip(request)
    key = f"{body.username.lower()}|{ip}"
    wait = ctx.throttle.retry_after(key)
    if wait:
        ctx.repo.audit(body.username, "auth.locked", None, "too many failed logins", ip)
        raise HTTPException(429, "Too many failed attempts. Try again later.", headers={"Retry-After": str(wait)})
    user = ctx.repo.get_user_by_name(body.username.strip())
    ok = verify_password(body.password, user["password_hash"] if user else _DUMMY_HASH)
    if user and ok and not user["is_active"]:
        # Only someone who knows the correct password learns the account is disabled (no username enumeration).
        ctx.repo.audit(user["username"], "auth.disabled_login", None, None, ip)
        raise HTTPException(403, DISABLED_MSG)
    if not (user and ok):
        ctx.throttle.failure(key)
        ctx.repo.audit(body.username, "auth.failed", None, None, ip)
        raise HTTPException(401, "Invalid username or password")
    ctx.throttle.success(key)
    ctx.repo.touch_login(user["id"])
    ctx.repo.audit(user["username"], "auth.login", None, None, ip, user["workspace_id"])
    return _issue(ctx, user)


@router.post("/register", status_code=201)
def register(body: RegisterRequest, request: Request, ctx=Depends(get_ctx)):
    """Public workspace creation is Google-only; local credentials are provisioned by a workspace Admin."""
    raise HTTPException(403, "Create a workspace with Google sign-in. For a username and password, ask your workspace Admin to create your account.")


@router.get("/me")
def me(user=Depends(current_user)):
    return dict(_public(user), last_login=user.get("last_login"), created_at=user.get("created_at"))


@router.post("/change-password")
def change_password(body: PasswordChange, request: Request, user=Depends(current_user), ctx=Depends(get_ctx)):
    if not verify_password(body.current_password, user["password_hash"]):
        raise HTTPException(400, "Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(422, "The new password must be different from the current one")
    _policy_or_422(body.new_password, user["username"])
    ctx.repo.update_user(user["id"], password_hash=hash_password(body.new_password))
    ctx.repo.audit(user["username"], "auth.password_changed", None, None, client_ip(request))
    # Old tokens are now invalid (password fingerprint changed); hand back a fresh one so this session continues.
    return dict(status="ok", **_issue(ctx, ctx.repo.get_user(user["id"])))


@router.get("/users")
def list_users(user=Depends(require("admin")), ctx=Depends(get_ctx)):
    return dict(users=ctx.repo.list_users())


@router.post("/users", status_code=201)
def create_user(body: UserCreate, request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    _policy_or_422(body.password, body.username)
    try:
        uid = ctx.repo.create_user(body.username, hash_password(body.password), body.role, body.full_name, user["workspace_id"])
    except sqlite3.IntegrityError:
        raise HTTPException(409, "That username is already taken")
    ctx.repo.audit(user["username"], "user.create", body.username, f"role={body.role}", client_ip(request))
    return dict(id=uid, username=body.username, role=body.role)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    target = ctx.repo.get_user(user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if target["id"] == user["id"] and ((body.role is not None and body.role != target["role"]) or body.is_active is False):
        raise HTTPException(409, "You cannot change your own role or disable your own account")
    losing_admin = target["role"] == "admin" and target["is_active"] and (
        (body.role is not None and body.role != "admin") or body.is_active is False)
    if losing_admin and ctx.repo.count_admins() <= 1:
        raise HTTPException(409, "Cannot remove the last active Admin")
    pw = None
    if body.password is not None:
        _policy_or_422(body.password, target["username"])
        pw = hash_password(body.password)
    ctx.repo.update_user(user_id, role=body.role, is_active=body.is_active, password_hash=pw, full_name=body.full_name)
    ctx.repo.audit(user["username"], "user.update", target["username"],
                   f"role={body.role} active={body.is_active} pw={'reset' if pw else 'unchanged'}", client_ip(request))
    return dict(status="ok")


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    target = ctx.repo.get_user(user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if target["id"] == user["id"]:
        raise HTTPException(409, "You cannot delete your own account")
    if target["role"] == "admin" and target["is_active"] and ctx.repo.count_admins() <= 1:
        raise HTTPException(409, "Cannot delete the last active Admin")
    ctx.repo.delete_user(user_id)
    ctx.repo.audit(user["username"], "user.delete", target["username"], f"role={target['role']}", client_ip(request))
    return dict(status="ok")
