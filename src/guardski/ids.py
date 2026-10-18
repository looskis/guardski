from __future__ import annotations

import hashlib
import json


def canonical(value: object) -> str:
    """Canonical JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def asset_id(addr: str) -> str:
    """Stable host-asset id for an observed address."""
    return f"asset:{addr}"


def target_asset_id(target_id: str) -> str:
    """Fallback asset id for a target with no mapped host address."""
    return f"target:{target_id}"


def service_id(addr: str, port: int | str, proto: str) -> str:
    """Stable service id in the Nmap `addr:port/proto` shape."""
    return f"service:{addr}:{port}/{proto}"


def network_id(cidr: str) -> str:
    return f"network:{cidr}"


def impact_id(asset: str, kind: str) -> str:
    return f"impact:{asset}:{kind}"


def fact_id(asset: str, kind: str, subject: str, value: object) -> str:
    """Content-addressed fact id: `sha256(asset|kind|subject|canonical(value))`.

    Re-observing the same value refreshes `last_seen`; a changed value is a new id.
    """
    material = f"{asset}|{kind}|{subject}|{canonical(value)}"
    return hashlib.sha256(material.encode()).hexdigest()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()
