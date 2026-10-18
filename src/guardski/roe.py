from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

TIERS = ("A", "B", "C")


class RoeError(ValueError):
    pass


@dataclass(frozen=True)
class TimeWindow:
    days: tuple[int, ...] = ()
    start: str = "00:00"
    end: str = "23:59"
    tz: str = "UTC"


@dataclass(frozen=True)
class RoE:
    id: str
    issued_at: float
    expires_at: float
    scope_allow: tuple[str, ...] = ()
    scope_exclude: tuple[str, ...] = ()
    time_windows: tuple[TimeWindow, ...] = ()
    max_tier: str = "A"
    max_intensity: int = 5
    max_actions_per_minute: int = 60
    credentials: tuple[str, ...] = ()
    discovery: bool = False
    allowed_actions: tuple[str, ...] = ()
    denied_actions: tuple[str, ...] = ()
    max_tasks_per_hour: int = 100
    approvals: tuple[dict, ...] = ()
    signer_fingerprints: tuple[str, ...] = ()

    def canonical(self) -> bytes:
        data = asdict(self)
        data.pop("approvals", None)
        data.pop("signer_fingerprints", None)
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()


def _window(raw: dict) -> TimeWindow:
    days = raw.get("days", [])
    if not isinstance(days, list) or any(not isinstance(d, int) or not 0 <= d <= 6 for d in days):
        raise RoeError("time_window.days must be integers 0-6 (Monday=0)")
    return TimeWindow(
        tuple(days),
        str(raw.get("start", "00:00")),
        str(raw.get("end", "23:59")),
        str(raw.get("tz", "UTC")),
    )


def parse_roe(data: dict) -> RoE:
    if not isinstance(data, dict):
        raise RoeError("RoE must be a table")
    tier = str(data.get("max_tier", "A"))
    if tier not in TIERS:
        raise RoeError("max_tier must be A, B, or C")
    windows = tuple(_window(w) for w in data.get("time_windows", []))
    approvals = tuple(data.get("approvals", []))
    roe = RoE(
        id=str(data["id"]),
        issued_at=float(data["issued_at"]),
        expires_at=float(data["expires_at"]),
        scope_allow=tuple(data.get("scope_allow", [])),
        scope_exclude=tuple(data.get("scope_exclude", [])),
        time_windows=windows,
        max_tier=tier,
        max_intensity=int(data.get("max_intensity", 5)),
        max_actions_per_minute=int(data.get("max_actions_per_minute", 60)),
        credentials=tuple(data.get("credentials", [])),
        discovery=bool(data.get("discovery", False)),
        allowed_actions=tuple(data.get("allowed_actions", [])),
        denied_actions=tuple(data.get("denied_actions", [])),
        max_tasks_per_hour=int(data.get("max_tasks_per_hour", 100)),
        approvals=approvals,
    )
    if tier == "C" and len(approvals) < 2:
        raise RoeError("max_tier C requires at least two approver signatures")
    return roe


def load_roe(path: Path) -> RoE:
    try:
        data = tomllib.loads(Path(path).read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise RoeError(f"Cannot read RoE: {exc}") from exc
    return parse_roe(data.get("roe", data))
