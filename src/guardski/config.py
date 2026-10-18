from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import tomllib
from dataclasses import asdict, dataclass, field
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


def number(value: object, name: str, low: float, high: float) -> float:
    if type(value) not in (int, float) or isinstance(value, bool) or not low <= value <= high:
        raise ConfigError(f"{name} must be a number between {low} and {high}")
    return float(value)


def _str_list(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"{name} must be a list")
    return tuple(string(item, name) for item in value)


def _choice(value: object, name: str, allowed: tuple[str, ...]) -> str:
    text = string(value, name)
    if text not in allowed:
        raise ConfigError(f"{name} must be one of: {', '.join(allowed)}")
    return text


def _endpoint_host(endpoint: str) -> str:
    host = urlsplit(endpoint).hostname
    if not host:
        raise ConfigError("endpoint must be an absolute URL")
    return host


def _is_loopback_or_private(host: str) -> bool:
    if host in {"localhost"}:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private


def read_model(data: dict) -> ModelConfig:
    keys(
        data,
        {
            "provider",
            "endpoint",
            "model_id",
            "temperature",
            "max_tokens",
            "input_token_budget",
            "structured_output",
            "grammar_path",
            "repair_turns",
            "timeout_seconds",
            "max_retries",
            "circuit_breaker_threshold",
            "circuit_breaker_cooldown_seconds",
        },
        "model",
    )
    return ModelConfig(
        provider=_choice(data.get("provider", "stub"), "model.provider", ("openai", "stub")),
        endpoint=string(data.get("endpoint", "http://127.0.0.1:11434/v1"), "model.endpoint"),
        model_id=string(data.get("model_id", "stub"), "model.model_id"),
        temperature=number(data.get("temperature", 0), "model.temperature", 0, 2),
        max_tokens=integer(data.get("max_tokens", 4096), "model.max_tokens", 1, 1024000),
        input_token_budget=integer(
            data.get("input_token_budget", 24000), "model.input_token_budget", 1, 10000000
        ),
        structured_output=_choice(
            data.get("structured_output", "json_schema"),
            "model.structured_output",
            ("json_schema", "grammar", "prompt_only"),
        ),
        grammar_path=str(data.get("grammar_path", "")),
        repair_turns=integer(data.get("repair_turns", 1), "model.repair_turns", 0, 5),
        timeout_seconds=integer(data.get("timeout_seconds", 120), "model.timeout_seconds", 1, 3600),
        max_retries=integer(data.get("max_retries", 2), "model.max_retries", 0, 10),
        circuit_breaker_threshold=integer(
            data.get("circuit_breaker_threshold", 5),
            "model.circuit_breaker_threshold",
            1,
            1000,
        ),
        circuit_breaker_cooldown_seconds=integer(
            data.get("circuit_breaker_cooldown_seconds", 300),
            "model.circuit_breaker_cooldown_seconds",
            1,
            86400,
        ),
    )


def read_agent(data: dict) -> AgentConfig:
    keys(
        data,
        {
            "state_dir",
            "offline",
            "timeout_seconds",
            "max_output_mb",
            "max_db_age_hours",
            "reasoning_enabled",
            "discovery_enabled",
            "discovery_interval_seconds",
            "debounce_seconds",
            "max_tier",
            "mode",
            "max_memory_mb",
            "max_cpu_percent",
            "plan_ttl_hours",
            "max_auto_extend_hours",
            "max_hypotheses_open",
            "investigation_ttl_days",
            "max_tasks_per_cycle",
            "max_tasks_per_hour",
            "max_tasks_per_asset_per_hour",
            "task_ttl_minutes",
            "max_context_findings",
            "context_token_budget",
            "monitor_cooldown_seconds",
            "max_concurrency",
            "max_actions_per_minute",
        },
        "agent",
    )
    return AgentConfig(
        reasoning_enabled=boolean(data.get("reasoning_enabled", False), "reasoning_enabled"),
        discovery_enabled=boolean(data.get("discovery_enabled", False), "discovery_enabled"),
        discovery_interval_seconds=integer(
            data.get("discovery_interval_seconds", 3600),
            "discovery_interval_seconds",
            0,
            31536000,
        ),
        debounce_seconds=integer(data.get("debounce_seconds", 60), "debounce_seconds", 1, 86400),
        max_tier=_choice(data.get("max_tier", "A"), "agent.max_tier", ("A", "B", "C")),
        mode=_choice(data.get("mode", "transparent"), "agent.mode", ("transparent", "covert")),
        max_memory_mb=integer(data.get("max_memory_mb", 2048), "max_memory_mb", 1, 1048576),
        max_cpu_percent=integer(data.get("max_cpu_percent", 80), "max_cpu_percent", 1, 100),
        plan_ttl_hours=integer(data.get("plan_ttl_hours", 24), "plan_ttl_hours", 1, 8760),
        max_auto_extend_hours=integer(
            data.get("max_auto_extend_hours", 72), "max_auto_extend_hours", 1, 8760
        ),
        max_hypotheses_open=integer(
            data.get("max_hypotheses_open", 20), "max_hypotheses_open", 1, 100000
        ),
        investigation_ttl_days=integer(
            data.get("investigation_ttl_days", 90), "investigation_ttl_days", 1, 3650
        ),
        max_tasks_per_cycle=integer(
            data.get("max_tasks_per_cycle", 25), "max_tasks_per_cycle", 1, 100000
        ),
        max_tasks_per_hour=integer(
            data.get("max_tasks_per_hour", 100), "max_tasks_per_hour", 1, 1000000
        ),
        max_tasks_per_asset_per_hour=integer(
            data.get("max_tasks_per_asset_per_hour", 10),
            "max_tasks_per_asset_per_hour",
            1,
            100000,
        ),
        task_ttl_minutes=integer(data.get("task_ttl_minutes", 60), "task_ttl_minutes", 1, 10080),
        max_context_findings=integer(
            data.get("max_context_findings", 400), "max_context_findings", 1, 100000
        ),
        context_token_budget=integer(
            data.get("context_token_budget", 24000), "context_token_budget", 1, 10000000
        ),
        monitor_cooldown_seconds=integer(
            data.get("monitor_cooldown_seconds", 1800), "monitor_cooldown_seconds", 1, 86400
        ),
        max_concurrency=integer(data.get("max_concurrency", 5), "max_concurrency", 1, 1000),
        max_actions_per_minute=integer(
            data.get("max_actions_per_minute", 60), "max_actions_per_minute", 1, 100000
        ),
    )


def read_graph(data: dict) -> GraphConfig:
    keys(data, {"include_out_of_scope", "max_nodes"}, "graph")
    return GraphConfig(
        include_out_of_scope=boolean(
            data.get("include_out_of_scope", False), "include_out_of_scope"
        ),
        max_nodes=integer(data.get("max_nodes", 5000), "graph.max_nodes", 1, 10000000),
    )


def read_intel(data: dict, base: Path) -> IntelConfig:
    keys(data, {"max_age_hours", "kev_path", "epss_path", "nvd_path", "osv_path"}, "intel")

    def feed(key: str) -> str:
        raw = data.get(key, "")
        if not raw:
            return ""
        if "://" in raw:
            raise ConfigError(f"intel.{key} must be a local path; a URL is not allowed")
        path = local_path(raw, base, f"intel.{key}")
        if not path.is_file():
            raise ConfigError(f"intel.{key} does not exist: {path}")
        return str(path)

    return IntelConfig(
        max_age_hours=integer(data.get("max_age_hours", 168), "intel.max_age_hours", 1, 87600),
        kev_path=feed("kev_path"),
        epss_path=feed("epss_path"),
        nvd_path=feed("nvd_path"),
        osv_path=feed("osv_path"),
    )


def read_monitor(data: dict) -> MonitorConfig:
    keys(
        data,
        {
            "anomaly_latency_multiplier",
            "anomaly_error_rate",
            "anomaly_max_response_bytes",
            "baseline_probes",
        },
        "monitor",
    )
    return MonitorConfig(
        anomaly_latency_multiplier=number(
            data.get("anomaly_latency_multiplier", 10), "anomaly_latency_multiplier", 1, 1000
        ),
        anomaly_error_rate=number(data.get("anomaly_error_rate", 0.5), "anomaly_error_rate", 0, 1),
        anomaly_max_response_bytes=integer(
            data.get("anomaly_max_response_bytes", 10485760),
            "anomaly_max_response_bytes",
            1,
            1073741824,
        ),
        baseline_probes=integer(data.get("baseline_probes", 5), "baseline_probes", 1, 1000),
    )


def read_notify(data: dict) -> NotifyConfig:
    keys(
        data,
        {
            "notifiers",
            "webhook_url",
            "webhook_timeout_seconds",
            "syslog_format",
            "cef_vendor",
            "cef_product",
            "cef_version",
        },
        "notify",
    )
    notifiers = _str_list(data.get("notifiers", ["log"]), "notify.notifiers")
    for name in notifiers:
        if name not in ("log", "webhook", "syslog"):
            raise ConfigError(f"notify.notifiers must be a subset of log, webhook, syslog: {name}")
    return NotifyConfig(
        notifiers=notifiers,
        webhook_url=str(data.get("webhook_url", "")),
        webhook_timeout_seconds=integer(
            data.get("webhook_timeout_seconds", 10), "webhook_timeout_seconds", 1, 300
        ),
        syslog_format=_choice(
            data.get("syslog_format", "rfc5424"), "syslog_format", ("rfc5424", "cef")
        ),
        cef_vendor=str(data.get("cef_vendor", "Guardski")),
        cef_product=str(data.get("cef_product", "Guardski")),
        cef_version=str(data.get("cef_version", "0.1.0")),
    )


def read_credentials(data: dict) -> CredentialsConfig:
    keys(data, {"safeski_command", "allow_env", "allow_file"}, "credentials")
    return CredentialsConfig(
        safeski_command=string(
            data.get("safeski_command", "safeski"), "credentials.safeski_command"
        ),
        allow_env=boolean(data.get("allow_env", True), "credentials.allow_env"),
        allow_file=boolean(data.get("allow_file", True), "credentials.allow_file"),
    )


def read_roe(data: dict) -> RoeConfig:
    keys(data, {"path", "public_keys"}, "roe")
    return RoeConfig(
        path=string(data.get("path", "roe.signed.toml"), "roe.path"),
        public_keys=_str_list(data.get("public_keys", []), "roe.public_keys"),
    )


def read_signing(data: dict) -> SigningConfig:
    keys(data, {"provider", "private_key_path"}, "signing")
    return SigningConfig(
        provider=_choice(data.get("provider", "file"), "signing.provider", ("file",)),
        private_key_path=str(data.get("private_key_path", "")),
    )


def read_rbac(data: dict) -> RbacConfig:
    keys(data, {"roles"}, "rbac")
    raw = data.get("roles", {})
    if not isinstance(raw, dict):
        raise ConfigError("rbac.roles must be a table of public keys")
    roles = {}
    for role, values in raw.items():
        if not isinstance(values, list):
            raise ConfigError(f"rbac.roles.{role} must be a list of public keys")
        roles[role] = tuple(string(item, f"rbac.roles.{role}") for item in values)
    return RbacConfig(roles=roles)


def read_retention(data: dict) -> RetentionConfig:
    keys(
        data,
        {
            "plans_days",
            "investigations_days",
            "actions_days",
            "artifacts_days",
            "facts_days",
            "tasks_days",
            "notifications_days",
            "intel_days",
        },
        "retention",
    )
    config = RetentionConfig(
        plans_days=integer(data.get("plans_days", 430), "plans_days", 1, 36500),
        investigations_days=integer(
            data.get("investigations_days", 430), "investigations_days", 1, 36500
        ),
        actions_days=integer(data.get("actions_days", 400), "actions_days", 1, 36500),
        artifacts_days=integer(data.get("artifacts_days", 430), "artifacts_days", 1, 36500),
        facts_days=integer(data.get("facts_days", 400), "facts_days", 1, 36500),
        tasks_days=integer(data.get("tasks_days", 90), "tasks_days", 1, 36500),
        notifications_days=integer(
            data.get("notifications_days", 30), "notifications_days", 1, 36500
        ),
        intel_days=integer(data.get("intel_days", 30), "intel_days", 1, 36500),
    )
    if config.plans_days < config.actions_days + 30:
        raise ConfigError("plans_days must be >= actions_days + 30")
    if config.artifacts_days < config.actions_days:
        raise ConfigError("artifacts_days must be >= actions_days")
    if config.investigations_days < config.plans_days:
        raise ConfigError("investigations_days must be >= plans_days")
    return config


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
    udp: bool = False
    udp_ports: str = "53,123,161,500"
    os_detection: bool = False
    discovery: bool = False

    @property
    def engine(self) -> str:
        return {"web": "nuclei", "network": "nmap"}.get(self.kind, "trivy")


@dataclass(frozen=True)
class ModelConfig:
    provider: str = "stub"
    endpoint: str = "http://127.0.0.1:11434/v1"
    model_id: str = "stub"
    temperature: float = 0.0
    max_tokens: int = 4096
    input_token_budget: int = 24000
    structured_output: str = "json_schema"
    grammar_path: str = ""
    repair_turns: int = 1
    timeout_seconds: int = 120
    max_retries: int = 2
    circuit_breaker_threshold: int = 5
    circuit_breaker_cooldown_seconds: int = 300


@dataclass(frozen=True)
class AgentConfig:
    reasoning_enabled: bool = False
    discovery_enabled: bool = False
    discovery_interval_seconds: int = 3600
    debounce_seconds: int = 60
    max_tier: str = "A"
    mode: str = "transparent"
    max_memory_mb: int = 2048
    max_cpu_percent: int = 80
    plan_ttl_hours: int = 24
    max_auto_extend_hours: int = 72
    max_hypotheses_open: int = 20
    investigation_ttl_days: int = 90
    max_tasks_per_cycle: int = 25
    max_tasks_per_hour: int = 100
    max_tasks_per_asset_per_hour: int = 10
    task_ttl_minutes: int = 60
    max_context_findings: int = 400
    context_token_budget: int = 24000
    monitor_cooldown_seconds: int = 1800
    max_concurrency: int = 5
    max_actions_per_minute: int = 60


@dataclass(frozen=True)
class GraphConfig:
    include_out_of_scope: bool = False
    max_nodes: int = 5000


@dataclass(frozen=True)
class IntelConfig:
    max_age_hours: int = 168
    kev_path: str = ""
    epss_path: str = ""
    nvd_path: str = ""
    osv_path: str = ""


@dataclass(frozen=True)
class MonitorConfig:
    anomaly_latency_multiplier: float = 10.0
    anomaly_error_rate: float = 0.5
    anomaly_max_response_bytes: int = 10485760
    baseline_probes: int = 5


@dataclass(frozen=True)
class NotifyConfig:
    notifiers: tuple[str, ...] = ("log",)
    webhook_url: str = ""
    webhook_timeout_seconds: int = 10
    syslog_format: str = "rfc5424"
    cef_vendor: str = "Guardski"
    cef_product: str = "Guardski"
    cef_version: str = "0.1.0"


@dataclass(frozen=True)
class CredentialsConfig:
    safeski_command: str = "safeski"
    allow_env: bool = True
    allow_file: bool = True


@dataclass(frozen=True)
class SigningConfig:
    provider: str = "file"
    private_key_path: str = ""


@dataclass(frozen=True)
class RbacConfig:
    roles: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RoeConfig:
    path: str = "roe.signed.toml"
    public_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class RetentionConfig:
    plans_days: int = 430
    investigations_days: int = 430
    actions_days: int = 400
    artifacts_days: int = 430
    facts_days: int = 400
    tasks_days: int = 90
    notifications_days: int = 30
    intel_days: int = 30


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
    model: ModelConfig = ModelConfig()
    agent: AgentConfig = AgentConfig()
    graph: GraphConfig = GraphConfig()
    intel: IntelConfig = IntelConfig()
    monitor: MonitorConfig = MonitorConfig()
    notify: NotifyConfig = NotifyConfig()
    credentials: CredentialsConfig = CredentialsConfig()
    signing: SigningConfig = SigningConfig()
    rbac: RbacConfig = RbacConfig()
    roe: RoeConfig = RoeConfig()
    retention: RetentionConfig = RetentionConfig()

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
    keys(
        data,
        {
            "agent",
            "schedule",
            "engines",
            "policy",
            "targets",
            "model",
            "graph",
            "intel",
            "roe",
            "monitor",
            "notify",
            "credentials",
            "signing",
            "rbac",
            "retention",
        },
        "top-level",
    )
    agent = data.get("agent", {})
    engines = data.get("engines", {})
    policy = data.get("policy", {})
    keys(engines, {"trivy", "nuclei", "nmap", "nuclei_templates", "rate_limit"}, "engines")
    keys(policy, {"critical_days", "high_days", "medium_days", "low_days"}, "policy")
    agent_config = read_agent(agent)
    model = read_model(data.get("model", {}))
    graph = read_graph(data.get("graph", {}))
    monitor = read_monitor(data.get("monitor", {}))
    notify = read_notify(data.get("notify", {}))
    credentials = read_credentials(data.get("credentials", {}))
    roe = read_roe(data.get("roe", {}))
    retention = read_retention(data.get("retention", {}))
    signing = read_signing(data.get("signing", {}))
    rbac = read_rbac(data.get("rbac", {}))
    base = path.parent
    intel = read_intel(data.get("intel", {}), base)
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
                "udp",
                "udp_ports",
                "os_detection",
                "discovery",
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
        udp = boolean(item.get("udp", False), "target.udp")
        os_detection = boolean(item.get("os_detection", False), "target.os_detection")
        discovery = boolean(item.get("discovery", False), "target.discovery")
        udp_ports = item.get("udp_ports", Target.__dataclass_fields__["udp_ports"].default)
        if not isinstance(udp_ports, str) or not re.fullmatch(
            r"\d+(-\d+)?(,\d+(-\d+)?)*", udp_ports
        ):
            raise ConfigError("udp_ports must contain port numbers or ranges")
        if (udp or os_detection or discovery or "udp_ports" in item) and kind != "network":
            raise ConfigError("udp/os_detection/discovery apply only to network targets")
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
                udp,
                udp_ports,
                os_detection,
                discovery,
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
    config = Config(
        state_dir=state_dir,
        schedule=schedule,
        targets=tuple(targets),
        offline=offline,
        timeout_seconds=integer(agent.get("timeout_seconds", 1800), "timeout_seconds", 1, 86400),
        max_output_mb=integer(agent.get("max_output_mb", 64), "max_output_mb", 1, 1024),
        trivy=string(engines.get("trivy", "trivy"), "engines.trivy"),
        nuclei=string(engines.get("nuclei", "nuclei"), "engines.nuclei"),
        nmap=string(engines.get("nmap", "nmap"), "engines.nmap"),
        templates=templates,
        rate_limit=integer(engines.get("rate_limit", 5), "rate_limit", 1, 100),
        sla_days={
            severity: integer(policy.get(f"{severity.lower()}_days", default), severity, 1, 3650)
            for severity, default in (("CRITICAL", 7), ("HIGH", 30), ("MEDIUM", 90), ("LOW", 180))
        },
        max_db_age_hours=integer(agent.get("max_db_age_hours", 168), "max_db_age_hours", 1, 8760),
        model=model,
        agent=agent_config,
        graph=graph,
        intel=intel,
        monitor=monitor,
        notify=notify,
        credentials=credentials,
        signing=signing,
        rbac=rbac,
        roe=roe,
        retention=retention,
    )
    _validate(config)
    return config


def _validate(config: Config) -> None:
    """Cross-block validation that no single reader can perform alone (SPEC §10)."""
    endpoint = config.model.endpoint
    scheme = urlsplit(endpoint).scheme
    host = _endpoint_host(endpoint)
    private = _is_loopback_or_private(host)
    if scheme == "http" and not private:
        raise ConfigError("model.endpoint must use https:// for a non-loopback host")
    if config.offline and not private:
        raise ConfigError("model.endpoint must be loopback or private while offline = true")
    if config.model.provider == "openai" and not private and scheme != "https":
        raise ConfigError("model.endpoint must use https:// for a public host")
    if config.notify.webhook_url:
        webhook = urlsplit(config.notify.webhook_url)
        if webhook.scheme != "https" and not _is_loopback_or_private(webhook.hostname or ""):
            raise ConfigError("notify.webhook_url must use https:// for a non-loopback host")
    if config.agent.discovery_enabled and not config.agent.reasoning_enabled:
        raise ConfigError("discovery_enabled requires reasoning_enabled = true")
    if config.agent.context_token_budget > config.model.input_token_budget:
        raise ConfigError("agent.context_token_budget must be <= model.input_token_budget")
    if config.model.structured_output == "grammar":
        if not config.model.grammar_path or not Path(config.model.grammar_path).is_file():
            raise ConfigError("structured_output = grammar requires a readable grammar_path")


STARTER_CONFIG = """\
# Guardski configuration. Schedules use UTC; relative paths resolve against this file.
# Validate with: guardski --config guardski.toml check

[agent]
state_dir = ".guardski"
offline = false
timeout_seconds = 1800
max_output_mb = 64
max_db_age_hours = 168

[schedule]
cron = "0 2 * * *"
run_on_start = true

[engines]
trivy = "trivy"
nuclei = "nuclei"
nmap = "nmap"
rate_limit = 5
nuclei_templates = []

# Organizational SLAs, not deadlines prescribed by any framework.
[policy]
critical_days = 7
high_days = 30
medium_days = 90
low_days = 180

[[targets]]
id = "working-tree"
kind = "filesystem"
value = "."
owner = "security"
scanners = ["vuln", "misconfig", "secret"]

# Add only targets you are authorized to scan. Examples:
#
# [[targets]]
# id = "linux-host"
# kind = "rootfs"
# value = "/mnt/host"
# owner = "platform"
# scanners = ["vuln", "misconfig"]
#
# [[targets]]
# id = "office-net"
# kind = "network"
# value = "10.0.0.0/24"
# owner = "network"
# ports = "22,80,443"
# discovery = true

# Optional: an OpenAI-compatible local model instead of the deterministic stub.
# [model]
# provider = "openai"
# endpoint = "http://127.0.0.1:11434/v1"
# model_id = "qwen3:8b"
"""


def write_starter(path: Path, force: bool = False) -> Path:
    """Write a commented starter configuration that loads without edits."""
    target = Path(path).expanduser()
    if target.exists() and not force:
        raise FileExistsError(f"{target} already exists; pass --force to overwrite")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(STARTER_CONFIG)
    return target
