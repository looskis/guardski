from __future__ import annotations

from dataclasses import dataclass

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
