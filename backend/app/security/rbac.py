"""Role-based access control: viewer < analyst < admin."""
from __future__ import annotations

ROLE_LEVEL = {"viewer": 1, "analyst": 2, "admin": 3}
ROLES = tuple(ROLE_LEVEL)


def has_role(user_role: str, required: str) -> bool:
    return ROLE_LEVEL.get(user_role, 0) >= ROLE_LEVEL.get(required, 99)
