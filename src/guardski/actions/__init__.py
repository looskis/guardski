from __future__ import annotations

from dataclasses import dataclass, field

HARD_STOP_CLASSES = (
    "destructive",
    "exfiltration",
    "credential_spray",
    "persistence",
)


@dataclass(frozen=True)
class ActionSpec:
    id: str
    tier: str
    parameter_schema: dict
    discoverable: bool
    reversible: bool
    hard_stop_class: str | None = None


def _spec(id, tier, schema, discoverable, reversible, hard_stop=None):
    return ActionSpec(id, tier, schema, discoverable, reversible, hard_stop)


CATALOG: dict[str, dict] = {}


def _register(spec: ActionSpec) -> None:
    CATALOG[spec.id] = {
        "tier": spec.tier,
        "parameter_schema": spec.parameter_schema,
        "discoverable": spec.discoverable,
        "reversible": spec.reversible,
        "hard_stop_class": spec.hard_stop_class,
    }


OBJECT = {"type": "object"}
SCHEMAS = {
    "recon.nmap_rescan": {
        "type": "object",
        "required": ["ports"],
        "properties": {"ports": {"type": "string"}, "service_detection": {"type": "boolean"}},
        "additionalProperties": False,
    },
    "recon.nuclei_targeted": {
        "type": "object",
        "required": ["targets"],
        "properties": {
            "targets": {"type": "array", "items": {"type": "string"}},
            "template_ids": {"type": "array", "items": {"type": "string"}},
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        "additionalProperties": False,
    },
    "recon.http_fingerprint": {
        "type": "object",
        "required": ["url"],
        "properties": {"url": {"type": "string"}, "method": {"enum": ["GET", "HEAD"]}},
        "additionalProperties": False,
    },
    "recon.tls_inspect": {
        "type": "object",
        "required": ["host", "port"],
        "properties": {"host": {"type": "string"}, "port": {"type": "integer"}},
        "additionalProperties": False,
    },
    "recon.sbom_match": {
        "type": "object",
        "required": ["package"],
        "properties": {
            "asset_id": {"type": "string"},
            "asset_ids": {"type": "array", "items": {"type": "string"}},
            "package": {"type": "string"},
            "version": {"type": "string"},
        },
        "additionalProperties": False,
    },
    "recon.auth_check": {
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string"},
            "credential_id": {"type": "string"},
            "credential": {"type": "object"},
        },
        "additionalProperties": False,
    },
    "recon.package_inventory": {
        "type": "object",
        "required": ["method"],
        "properties": {
            "asset_id": {"type": "string"},
            "method": {"enum": ["ssh", "winrm"]},
            "credential": {"type": "object"},
        },
        "additionalProperties": False,
    },
    "confirm.reachability": {
        "type": "object",
        "required": ["addr", "port"],
        "properties": {"addr": {"type": "string"}, "port": {"type": "integer"}},
        "additionalProperties": False,
    },
    "confirm.banner": {
        "type": "object",
        "required": ["addr", "port"],
        "properties": {"addr": {"type": "string"}, "port": {"type": "integer"}},
        "additionalProperties": False,
    },
    "confirm.http_status": {
        "type": "object",
        "required": ["url", "path"],
        "properties": {"url": {"type": "string"}, "path": {"type": "string"}},
        "additionalProperties": False,
    },
}
RECON_SPECS = (
    _spec("recon.nmap_rescan", "A", OBJECT, True, True),
    _spec("recon.nuclei_targeted", "A", OBJECT, True, True),
    _spec("recon.http_fingerprint", "A", OBJECT, True, True),
    _spec("recon.tls_inspect", "A", OBJECT, True, True),
    _spec("recon.sbom_match", "A", OBJECT, True, True),
    _spec("recon.auth_check", "A", OBJECT, True, True),
    _spec("recon.package_inventory", "A", OBJECT, True, True),
    _spec("confirm.reachability", "A", OBJECT, False, True),
    _spec("confirm.banner", "A", OBJECT, False, True),
    _spec("confirm.http_status", "A", OBJECT, False, True),
)

for _action in RECON_SPECS:
    _register(_action)

PROVE_SPECS = (
    _spec("prove.ssrf_canary", "B", OBJECT, True, True),
    _spec("prove.auth_bypass_read", "B", OBJECT, True, True),
    _spec("prove.marker_write", "B", OBJECT, True, True),
    _spec("prove.default_credential", "B", OBJECT, True, True),
)

for _action in PROVE_SPECS:
    _register(_action)

for _action_id, _schema in SCHEMAS.items():
    if _action_id in CATALOG:
        CATALOG[_action_id]["parameter_schema"] = _schema


@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    tier: str
    targets: tuple[str, ...] = ()
    asset_ids: tuple[str, ...] = ()
    parameters: dict = field(default_factory=dict)
    intensity: int = 1
    credential_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    plan_id: str | None = None
    step_ordinal: int | None = None
    task_id: str | None = None


@dataclass(frozen=True)
class ActionResult:
    status: str
    detail: str = ""
    facts: tuple = ()
