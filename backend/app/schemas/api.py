"""Request models (pydantic v2). Bounds are enforced here so handlers can trust their input."""
from __future__ import annotations

import re
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

from app.ml.schema import RAW_FEATURES
from app.models.attacks import ATTACKS

AttackName = Literal[tuple(ATTACKS)]  # type: ignore[valid-type]
Role = Literal["viewer", "analyst", "admin"]
Status = Literal["open", "acknowledged", "mitigated", "resolved", "false_positive"]
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{3,64}$")
USERNAME_HINT = "Username must be 3-64 characters: letters, digits and _ . - @ (no spaces)"


def _clean_name(v):
    if v is None:
        return None
    v = " ".join(str(v).split())
    if len(v) > 64 or any(ch in v for ch in "<>") or any(ord(ch) < 32 for ch in v):
        raise ValueError("Full name must be at most 64 characters without < > or control characters")
    return v or None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class RegisterRequest(BaseModel):
    username: str
    password: str = Field(max_length=256)
    full_name: Optional[str] = Field(default=None, max_length=200)

    @field_validator("username")
    @classmethod
    def _u(cls, v):
        v = v.strip()
        if not USERNAME_RE.match(v):
            raise ValueError(USERNAME_HINT)
        return v

    @field_validator("full_name")
    @classmethod
    def _n(cls, v):
        return _clean_name(v)


class UserCreate(RegisterRequest):
    role: Role = "viewer"


class UserUpdate(BaseModel):
    role: Optional[Role] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, max_length=256)
    full_name: Optional[str] = Field(default=None, max_length=200)

    @field_validator("full_name")
    @classmethod
    def _n(cls, v):
        return _clean_name(v)


class RegistrationSetting(BaseModel):
    enabled: bool


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class StatusUpdate(BaseModel):
    status: Status


class MitigateRequest(BaseModel):
    solution_id: str = Field(min_length=1, max_length=64)


class DetectEvent(BaseModel):
    """One flow/request to analyse. Unknown numeric features default to a typical benign value."""
    src_ip: Optional[str] = Field(default=None, max_length=45)
    dst_ip: Optional[str] = Field(default=None, max_length=45)
    protocol: Optional[Literal["TCP", "UDP", "ICMP", "tcp", "udp", "icmp"]] = None
    payload_sample: Optional[str] = Field(default=None, max_length=2000)
    features: dict[str, float] = Field(default_factory=dict)

    @field_validator("features")
    @classmethod
    def _f(cls, v):
        if len(v) > 64:
            raise ValueError("too many features")
        return {k: float(x) for k, x in v.items() if k in RAW_FEATURES}


class SimulateRequest(BaseModel):
    scenario: AttackName
    stealth: float = Field(default=0.0, ge=0.0, le=1.0)


class ChatRequest(BaseModel):
    message: str = Field(max_length=500)


class SimulationSettings(BaseModel):
    mode: Optional[Literal["auto", "on", "off"]] = None
    enabled: Optional[bool] = None  # legacy: true -> "on", false -> "off"
    interval: Optional[float] = Field(default=None, ge=0.2, le=10)
    attack_ratio: Optional[float] = Field(default=None, ge=0.0, le=0.9)


class RetrainRequest(BaseModel):
    quick: bool = True
    samples: Optional[int] = Field(default=None, ge=2000, le=100000)


class SourcePolicy(BaseModel):
    exclude_paths: list[str] = Field(default_factory=list, max_length=50)
    redact_params: Optional[list[str]] = Field(default=None, max_length=100)
    pseudonymize_ips: bool = False
    protected_ip: str = Field(default="", max_length=45)


class SourceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=64)
    kind: Literal["web_access_log"] = "web_access_log"
    policy: SourcePolicy = Field(default_factory=SourcePolicy)

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        v = " ".join(v.split())
        if len(v) < 2 or any(ch in v for ch in "<>") or any(ord(ch) < 32 for ch in v):
            raise ValueError("Name must be 2-64 characters without < > or control characters")
        return v


class SourceUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=64)
    policy: Optional[SourcePolicy] = None


class IngestBatch(BaseModel):
    events: list[dict] = Field(default_factory=list, max_length=2000)


class HeartbeatInfo(BaseModel):
    version: Optional[str] = Field(default=None, max_length=32)
    hostname: Optional[str] = Field(default=None, max_length=100)
    files: list[str] = Field(default_factory=list, max_length=20)
    lines_read: int = 0
    events_sent: int = 0
    events_failed: int = 0
    queue_size: int = 0
