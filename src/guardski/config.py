from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import tomllib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from croniter import croniter

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "INFO")
KINDS = {"filesystem", "rootfs", "image", "archive", "sbom", "web", "network"}
CRITICALITIES = ("critical", "high", "medium", "low")
ENVIRONMENTS = ("production", "staging", "test", "ot")
DATA_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")


class ConfigError(ValueError):
    pass


def keys(data: dict, allowed: set[str], context: str) -> None:
    if not isinstance(data, dict):
        raise ConfigError(f"{context} must be a table")
    unknown = set(data) - allowed
    if unknown:
        raise ConfigError(f"Unknown {context} setting(s): {', '.join(sorted(unknown))}")


def integer(value: object, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ConfigError(f"{name} must be an integer between {low} and {high}")
    return value


def boolean(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(f"{name} must be true or false")
    return value


def string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise ConfigError(f"{name} must be a nonempty string without control characters")
    return value


def local_path(value: object, base: Path, name: str) -> Path:
    path = Path(string(value, name)).expanduser()
    return (base / path).resolve()


def _enum(item: dict, key: str, context: str, allowed: tuple[str, ...]) -> str | None:
    if key not in item:
        return None
    value = string(item[key], f"{context}.{key}")
    if value not in allowed:
        raise ConfigError(f"{context}.{key} must be one of: {', '.join(allowed)}")
    return value


def _tags(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError("target.tags must be a list of lowercase tokens")
    tags = []
    for raw in value:
        token = string(raw, "target.tags")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", token):
            raise ConfigError("target.tags must be nonempty lowercase tokens")
        tags.append(token)
    return tuple(sorted(set(tags)))


def _trusts(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError("target.trusts must be a list of target ids")
    return tuple(string(item, "target.trusts") for item in value)


@dataclass(frozen=True)
class Schedule:
    cron: str | None = "0 2 * * *"
    interval_seconds: int | None = None
    run_on_start: bool = True

    def next_after(self, now: float) -> float:
        if self.interval_seconds is not None:
            return now + self.interval_seconds
        return croniter(self.cron, datetime.fromtimestamp(now, UTC)).get_next(datetime).timestamp()


def read_schedule(data: dict) -> Schedule:
    keys(data, {"cron", "interval_seconds", "run_on_start"}, "schedule")
    run_on_start = boolean(data.get("run_on_start", True), "run_on_start")
    if "interval_seconds" in data:
        if "cron" in data:
            raise ConfigError("Use either cron or interval_seconds, not both")
        return Schedule(
            None, integer(data["interval_seconds"], "interval_seconds", 10, 31536000), run_on_start
        )
    expression = string(data.get("cron", "0 2 * * *"), "cron")
    if len(expression.split()) != 5 or not croniter.is_valid(expression):
        raise ConfigError("cron must be a valid five-field expression (UTC)")
    schedule = Schedule(expression, None, run_on_start)
    try:
        schedule.next_after(datetime.now(UTC).timestamp())
    except ValueError as exc:
        raise ConfigError(f"cron has no reachable occurrence: {expression}") from exc
    return schedule


@dataclass(frozen=True)
class Target:
    id: str
    kind: str
    value: str
    owner: str
    schedule: Schedule
    scanners: tuple[str, ...] = ("vuln", "misconfig", "secret")
    ports: str = "1-1024,1433,1521,2375,2376,3306,3389,5432,5900,6379,8080,8443,9200,27017"
    host: str | None = None
    criticality: str | None = None
    environment: str | None = None
    tags: tuple[str, ...] = ()
    data_classification: str | None = None
    trusts: tuple[str, ...] = ()

    @property
    def engine(self) -> str:
        return {"web": "nuclei", "network": "nmap"}.get(self.kind, "trivy")


@dataclass(frozen=True)
class Config:
    state_dir: Path
    schedule: Schedule
    targets: tuple[Target, ...]
    offline: bool
    timeout_seconds: int
    max_output_mb: int
    trivy: str
    nuclei: str
    nmap: str
    templates: tuple[str, ...]
    rate_limit: int
    sla_days: dict[str, int]
    max_db_age_hours: int = 168

    def snapshot(self) -> dict:
        result = asdict(self)
        result["state_dir"] = str(self.state_dir)
        return result

    @property
    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.snapshot(), sort_keys=True).encode()).hexdigest()

    def job_digest(self, target: Target) -> str:
        # A target or scan-policy change is a new schedule, even when the ID is unchanged.
        data = self.snapshot()
        data["targets"] = [asdict(target)]
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def scan_digest(self, target: Target) -> str:
        """Digest of the scan-relevant configuration only.

        Coverage and remediation eligibility depend on this, not on the whole config, so a
        model/notification/retention change does not invalidate coverage. A change to scope,
        ports, scanners, templates, engine, or the database-age policy does.
        """
        data = {
            "id": target.id,
            "kind": target.kind,
            "value": target.value,
            "host": target.host,
            "scanners": list(target.scanners),
            "ports": target.ports,
            "engine": target.engine,
            "timeout_seconds": self.timeout_seconds,
            "max_db_age_hours": self.max_db_age_hours,
            "offline": self.offline,
            "templates": self.template_hashes(),
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def template_hashes(self) -> dict[str, str]:
        result = {}
        for path in self.templates:
            try:
                result[path] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
            except OSError:
                result[path] = ""
        return result


def load_config(path: Path) -> Config:
    path = path.resolve()
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc
    keys(data, {"agent", "schedule", "engines", "policy", "targets"}, "top-level")
    agent = data.get("agent", {})
    engines = data.get("engines", {})
    policy = data.get("policy", {})
    keys(
        agent,
        {"state_dir", "offline", "timeout_seconds", "max_output_mb", "max_db_age_hours"},
        "agent",
    )
    keys(engines, {"trivy", "nuclei", "nmap", "nuclei_templates", "rate_limit"}, "engines")
    keys(policy, {"critical_days", "high_days", "medium_days", "low_days"}, "policy")
    base = path.parent
    state_dir = local_path(agent.get("state_dir", ".guardski"), base, "state_dir")
    offline = boolean(agent.get("offline", False), "offline")
    schedule = read_schedule(data.get("schedule", {}))
    raw_targets = data.get("targets", [])
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ConfigError("Configure at least one [[targets]] entry")
    targets = []
    seen = set()
    for item in raw_targets:
        keys(
            item,
            {
                "id",
                "kind",
                "value",
                "owner",
                "schedule",
                "scanners",
                "ports",
                "host",
                "criticality",
                "environment",
                "tags",
                "data_classification",
                "trusts",
            },
            "target",
        )
        tid = string(item.get("id"), "target.id")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", tid) or tid in seen:
            raise ConfigError(f"Invalid or duplicate target ID: {tid}")
        seen.add(tid)
        kind = string(item.get("kind"), "target.kind")
        if kind not in KINDS:
            raise ConfigError(f"Unsupported target kind: {kind}")
        value = string(item.get("value"), "target.value")
        owner = string(item.get("owner"), "target.owner")
        if kind in {"filesystem", "rootfs", "archive", "sbom"}:
            value = str(local_path(value, base, "target.value"))
            target_path = Path(value)
            if kind in {"filesystem", "rootfs"} and not target_path.is_dir():
                raise ConfigError(f"Target directory does not exist: {value}")
            if kind in {"archive", "sbom"} and not target_path.is_file():
                raise ConfigError(f"Target file does not exist: {value}")
            if target_path == state_dir or target_path.is_relative_to(state_dir):
                raise ConfigError("Targets must be outside the agent state directory")
        elif kind == "image":
            if offline:
                raise ConfigError(
                    "Use an archive target for offline images; registry images need network"
                )
            if value.startswith("-") or any(c.isspace() for c in value):
                raise ConfigError("Invalid container image reference")
        elif kind == "web":
            try:
                url = urlsplit(value)
                _ = url.port
                if (
                    url.scheme not in {"http", "https"}
                    or not url.hostname
                    or url.username
                    or url.password
                    or url.fragment
                    or url.query
                ):
                    raise ValueError
            except ValueError as exc:
                raise ConfigError(
                    "Web targets must be HTTP(S) URLs without credentials/query/fragment"
                ) from exc
        else:
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise ConfigError(
                    "Network targets must be a single IP or a canonical CIDR"
                ) from exc
            if network.num_addresses > 256:
                raise ConfigError("Split network scope into targets of at most 256 addresses")
            value = str(network)
        scanners = item.get("scanners", ["vuln", "misconfig", "secret"])
        if (
            not isinstance(scanners, list)
            or not scanners
            or any(s not in ("vuln", "misconfig", "secret") for s in scanners)
        ):
            raise ConfigError("scanners must be a nonempty list of vuln, misconfig, secret")
        if kind == "sbom":
            if "scanners" in item and scanners != ["vuln"]:
                raise ConfigError("SBOM targets support only the vuln scanner")
            scanners = ["vuln"]
        if kind in {"web", "network"} and "scanners" in item:
            raise ConfigError("scanners is only supported for Trivy targets")
        ports = item.get("ports", Target.__dataclass_fields__["ports"].default)
        if "ports" in item and kind != "network":
            raise ConfigError("ports is only supported for network targets")
        if not isinstance(ports, str) or not re.fullmatch(r"\d+(-\d+)?(,\d+(-\d+)?)*", ports):
            raise ConfigError("ports must contain port numbers or ranges, separated by commas")
        for part in ports.split(","):
            nums = [int(n) for n in part.split("-")]
            if any(not 1 <= n <= 65535 for n in nums) or nums[0] > nums[-1]:
                raise ConfigError("Port ranges must be ascending and between 1 and 65535")
        host = item.get("host")
        if host is not None:
            host = string(host, "target.host")
            try:
                address = ipaddress.ip_address(host)
            except ValueError as exc:
                raise ConfigError("target.host must be a single IP address") from exc
            if kind == "network" and address not in ipaddress.ip_network(value):
                raise ConfigError("target.host must fall inside the target CIDR")
        criticality = _enum(item, "criticality", "target", CRITICALITIES)
        environment = _enum(item, "environment", "target", ENVIRONMENTS)
        data_classification = _enum(item, "data_classification", "target", DATA_CLASSIFICATIONS)
        tags = _tags(item.get("tags", []))
        trusts = _trusts(item.get("trusts", []))
        targets.append(
            Target(
                tid,
                kind,
                value,
                owner,
                read_schedule(item["schedule"]) if "schedule" in item else schedule,
                tuple(sorted(set(scanners))),
                ports,
                host,
                criticality,
                environment,
                tags,
                data_classification,
                trusts,
            )
        )
    known = {target.id for target in targets}
    for target in targets:
        unknown = set(target.trusts) - known
        if unknown:
            raise ConfigError(
                f"target.trusts names unknown target(s): {', '.join(sorted(unknown))}"
            )
    raw_templates = engines.get("nuclei_templates", [])
    if not isinstance(raw_templates, list):
        raise ConfigError("nuclei_templates must be a list of approved local template files")
    templates = tuple(str(local_path(t, base, "template")) for t in raw_templates)
    if any(t.engine == "nuclei" for t in targets):
        if not templates or any(not Path(t).is_file() for t in templates):
            raise ConfigError("Web targets require existing, approved nuclei_templates files")
    return Config(
        state_dir,
        schedule,
        tuple(targets),
        offline,
        integer(agent.get("timeout_seconds", 1800), "timeout_seconds", 1, 86400),
        integer(agent.get("max_output_mb", 64), "max_output_mb", 1, 1024),
        *(
            string(engines.get(name, name), f"engines.{name}")
            for name in ("trivy", "nuclei", "nmap")
        ),
        templates,
        integer(engines.get("rate_limit", 5), "rate_limit", 1, 100),
        {
            severity: integer(policy.get(f"{severity.lower()}_days", default), severity, 1, 3650)
            for severity, default in (("CRITICAL", 7), ("HIGH", 30), ("MEDIUM", 90), ("LOW", 180))
        },
        integer(agent.get("max_db_age_hours", 168), "max_db_age_hours", 1, 8760),
    )
