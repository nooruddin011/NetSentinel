"""Small network helpers shared across layers."""
from __future__ import annotations

import ipaddress


def is_valid_ip(value: object) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def safe_ip(value: object, default: str = "0.0.0.0") -> str:
    """Return a canonical IP string, or `default` when the input is not a valid IP.

    Used before any value is interpolated into firewall-rule text, so attacker-controlled
    strings can never end up inside a generated command.
    """
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return default
