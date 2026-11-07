from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.deps import client_ip, current_user, get_ctx, require
from app.branding import APP_NAME
from app.schemas.api import LoginRequest, PasswordChange, RegisterRequest, UserCreate, UserUpdate
from app.security.jwt import encode_token
from app.security.passwords import hash_password, password_problems, password_version, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])
# Verified against when the username does not exist, so response time doesn't reveal valid usernames.
_DUMMY_HASH = hash_password("dummy-password-for-timing")
DISABLED_MSG = "This account has been disabled by an administrator. Please contact an Admin."


def _public(u: dict) -> dict:
    return dict(id=u["id"], username=u["username"], full_name=u.get("full_name"), role=u["role"])


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


@router.get("/config")
def public_config(ctx=Depends(get_ctx)):
    """Public: lets the login page know whether to offer 'Create account'."""
    return dict(app_name=APP_NAME, registration_enabled=registration_enabled(ctx))


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
    ctx.repo.audit(user["username"], "auth.login", None, None, ip)
    return _issue(ctx, user)


@router.post("/register", status_code=201)
def register(body: RegisterRequest, request: Request, ctx=Depends(get_ctx)):
    """Self-service sign-up. Always creates a **Viewer** (read-only); an Admin can grant more access later."""
    if not registration_enabled(ctx):
        raise HTTPException(403, "Self-registration is turned off. Please ask an Admin to create your account.")
    ip = client_ip(request)
    key = f"register|{ip}"
    wait = ctx.reg_throttle.retry_after(key)
    if wait:
        raise HTTPException(429, "Too many sign-ups from this address. Try again later.", headers={"Retry-After": str(wait)})
    ctx.reg_throttle.failure(key)  # every attempt counts toward the hourly cap
    _policy_or_422(body.password, body.username)
    try:
        uid = ctx.repo.create_user(body.username, hash_password(body.password), "viewer", body.full_name)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "That username is already taken")
    ctx.repo.audit(body.username, "auth.register", None, "role=viewer", ip)
    user = ctx.repo.get_user(uid)
    ctx.repo.touch_login(uid)
    return _issue(ctx, user)


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
        uid = ctx.repo.create_user(body.username, hash_password(body.password), body.role, body.full_name)
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
