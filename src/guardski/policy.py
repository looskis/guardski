from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .actions import CATALOG, ActionRequest
from .roe import RoE


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason_code: str
    detail: str = ""


@dataclass
class BudgetState:
    tasks_this_hour: int = 0
    per_asset: dict = field(default_factory=dict)


def expand_targets(targets: tuple[str, ...], allow_cidrs: tuple[str, ...] = ()) -> list[str]:
    expanded: list[str] = []
    for target in targets:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            expanded.append(target)
            continue
        if network.num_addresses == 1:
            expanded.append(str(network.network_address))
        else:
            for address in network.hosts():
                expanded.append(str(address))
    return expanded


def _in_window(roe: RoE, now: float) -> bool:
    if not roe.time_windows:
        return True
    moment = datetime.fromtimestamp(now, UTC)
    for window in roe.time_windows:
        if window.days and moment.weekday() not in window.days:
            continue
        current = moment.strftime("%H:%M")
        if window.start <= current <= window.end:
            return True
    return False


def authorize(
    action: ActionRequest,
    roe: RoE,
    now: float,
    budget: BudgetState | None = None,
    catalog: dict | None = None,
    credentials: dict | None = None,
    signature_ok: bool = True,
) -> Decision:
    catalog = CATALOG if catalog is None else catalog
    credentials = credentials or {}
    if not signature_ok:
        return Decision(False, "roe_invalid", "signature invalid")
    if now > roe.expires_at or now < roe.issued_at:
        return Decision(False, "roe_expired", "outside the RoE validity window")
    spec = catalog.get(action.action_id)
    if spec is None or action.action_id not in roe.allowed_actions:
        return Decision(False, "action_not_allowed", action.action_id)
    if action.action_id in roe.denied_actions:
        return Decision(False, "action_denied", action.action_id)
    if action.action_id.startswith("recon.") and not roe.discovery:
        return Decision(False, "discovery_disabled", action.action_id)
    if spec.get("hard_stop_class"):
        return Decision(False, "hard_stop", str(spec["hard_stop_class"]))
    if action.tier != spec.get("tier"):
        return Decision(False, "tier_mismatch", f"{action.tier} != {spec.get('tier')}")
    tier = spec.get("tier", "C")
    if tier > roe.max_tier:
        return Decision(False, "tier_too_high", tier)
    expanded = expand_targets(action.targets, roe.scope_allow)
    for address in expanded:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not any(ip in ipaddress.ip_network(c, strict=False) for c in roe.scope_allow):
            return Decision(False, "target_out_of_scope", address)
        if any(
            ip in ipaddress.ip_network(c, strict=False)
            for c in roe.scope_exclude
            if "/" in c or _is_ip(c)
        ):
            return Decision(False, "target_excluded", address)
    if not _in_window(roe, now):
        return Decision(False, "outside_time_window", str(now))
    if action.intensity < 1 or action.intensity > roe.max_intensity:
        return Decision(False, "intensity_exceeded", str(action.intensity))
    for credential_id in action.credential_ids:
        if credential_id not in roe.credentials:
            return Decision(False, "credential_missing", credential_id)
        record = credentials.get(credential_id)
        if record is None:
            return Decision(False, "credential_missing", credential_id)
        if record.get("expires_at") is not None and record["expires_at"] <= now:
            return Decision(False, "credential_expired", credential_id)
        scope = record.get("scope", [])
        for address in expanded:
            if not any(_in_cidr(address, c) for c in scope):
                return Decision(False, "credential_out_of_scope", credential_id)
    if budget is not None:
        if budget.tasks_this_hour >= roe.max_tasks_per_hour:
            return Decision(False, "budget_exhausted", "hourly")
    return Decision(True, "ok", "")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _in_cidr(address: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
