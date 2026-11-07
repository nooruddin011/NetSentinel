"""FastAPI dependencies: context, authentication, role checks."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.security.jwt import TokenError, decode_token
from app.security.passwords import password_version
from app.security.rbac import has_role

_bearer = HTTPBearer(auto_error=False)


def get_ctx(request: Request):
    return request.app.state.ctx


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def authenticate_token(ctx, token: str) -> dict:
    deny = lambda msg: HTTPException(401, msg, headers={"WWW-Authenticate": "Bearer"})  # noqa: E731
    try:
        payload = decode_token(token, ctx.settings.jwt_secret)
        user = ctx.repo.get_user(int(payload["sub"]))
    except (TokenError, KeyError, ValueError):
        raise deny("Your session has expired. Please sign in again.")
    if not user:
        raise deny("This account no longer exists.")
    if not user["is_active"]:
        raise deny("This account has been disabled by an administrator.")
    if payload.get("pv") != password_version(user["password_hash"]):
        raise deny("Your password was changed. Please sign in again.")
    return user


def current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer), ctx=Depends(get_ctx)) -> dict:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
    return authenticate_token(ctx, creds.credentials)


def require(role: str):
    def dep(user: dict = Depends(current_user)) -> dict:
        if not has_role(user["role"], role):
            raise HTTPException(403, f"This action requires the {role.capitalize()} role")
        return user
    return dep
