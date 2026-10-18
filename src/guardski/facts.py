from __future__ import annotations

from dataclasses import dataclass

from . import ids
from .redact import redact

# Asset facts are single, deterministic, hashed observations produced by deterministic
# code (a scanner or an action) — never by the model (SPEC §4.1.2). The model may read
# facts; it can never author one. Only typed constructors exist, so there is no
# `record_fact(kind, arbitrary_dict)` entry point reachable from reasoning/.

DAYS = 86400

# Bounded lifetime per kind (SPEC §4.1.2). A changed value is a new content-addressed row,
# so expiry only hides stale-but-unchanged observations.
TTL_SECONDS: dict[str, int] = {
    "service_banner": 7 * DAYS,
    "tls_certificate": 7 * DAYS,
    "http_metadata": 7 * DAYS,
    "auth_result": 7 * DAYS,
    "reachability": 3600,
    "service_binding": 30 * DAYS,
    "sbom_component": 30 * DAYS,
}

KNOWN_KINDS = tuple(TTL_SECONDS)


@dataclass(frozen=True)
class Fact:
    asset_id: str
    kind: str
    subject: str
    value: dict
    provenance: dict
    artifact_hash: str
    observed_at: float
    expires_at: float | None
    source_run_id: str | None = None
    source_action_id: str | None = None
    redacted: int = 0

    @property
    def id(self) -> str:
        return ids.fact_id(self.asset_id, self.kind, self.subject, self.value)


def _make(
    kind: str,
    asset_id: str,
    subject: str,
    value: dict,
    *,
    provenance: dict,
    artifact_hash: str,
    observed_at: float,
    source_run_id: str | None = None,
    source_action_id: str | None = None,
    ttl_seconds: int | None = None,
) -> Fact:
    if kind not in TTL_SECONDS:
        raise ValueError(f"Unknown fact kind: {kind}")
    if bool(source_run_id) == bool(source_action_id):
        raise ValueError("A fact must cite exactly one of source_run_id / source_action_id")
    if not artifact_hash:
        raise ValueError("A fact must carry an artifact hash")
    clean, redactions = redact(value)
    ttl = TTL_SECONDS[kind] if ttl_seconds is None else ttl_seconds
    return Fact(
        asset_id=asset_id,
        kind=kind,
        subject=subject,
        value=clean,
        provenance=provenance,
        artifact_hash=artifact_hash,
        observed_at=observed_at,
        expires_at=observed_at + ttl,
        source_run_id=source_run_id,
        source_action_id=source_action_id,
        redacted=1 if redactions else 0,
    )


def record_banner(
    asset_id: str,
    subject: str,
    *,
    source_run_id: str,
    artifact_hash: str,
    observed_at: float,
    product: str = "",
    version: str = "",
    banner_sha256: str = "",
    extra: dict | None = None,
) -> Fact:
    value = {"product": product, "version": version, "banner_sha256": banner_sha256}
    if extra:
        value.update(extra)
    return _make(
        "service_banner",
        asset_id,
        subject,
        value,
        provenance={"origin": "scanner", "run_id": source_run_id},
        artifact_hash=artifact_hash,
        observed_at=observed_at,
        source_run_id=source_run_id,
    )


def record_binding(
    asset_id: str,
    subject: str,
    *,
    package: str,
    installed_version: str,
    artifact_hash: str,
    observed_at: float,
    source_run_id: str | None = None,
    source_action_id: str | None = None,
    process: str = "",
    evidence_hash: str = "",
) -> Fact:
    return _make(
        "service_binding",
        asset_id,
        subject,
        {
            "package": package,
            "installed_version": installed_version,
            "process": process,
            "evidence_hash": evidence_hash,
        },
        provenance={"origin": "action" if source_action_id else "scanner"},
        artifact_hash=artifact_hash,
        observed_at=observed_at,
        source_run_id=source_run_id,
        source_action_id=source_action_id,
    )


def record_tls_certificate(
    asset_id: str,
    subject: str,
    *,
    source_run_id: str | None = None,
    source_action_id: str | None = None,
    artifact_hash: str,
    observed_at: float,
    cert_subject: str = "",
    issuer: str = "",
    not_before: float | None = None,
    not_after: float | None = None,
    sha256: str = "",
) -> Fact:
    return _make(
        "tls_certificate",
        asset_id,
        subject,
        {
            "subject": cert_subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "sha256": sha256,
        },
        provenance={"origin": "action" if source_action_id else "scanner"},
        artifact_hash=artifact_hash,
        observed_at=observed_at,
        source_run_id=source_run_id,
        source_action_id=source_action_id,
    )


def record_http_metadata(
    asset_id: str,
    subject: str,
    *,
    source_action_id: str,
    artifact_hash: str,
    observed_at: float,
    status: int | None = None,
    server: str = "",
    title: str = "",
    header_hash: str = "",
) -> Fact:
    return _make(
        "http_metadata",
        asset_id,
        subject,
        {"status": status, "server": server, "title": title, "header_hash": header_hash},
        provenance={"origin": "action", "action_id": source_action_id},
        artifact_hash=artifact_hash,
        observed_at=observed_at,
        source_action_id=source_action_id,
    )


def record_reachability(
    asset_id: str,
    subject: str,
    *,
    source_action_id: str,
    artifact_hash: str,
    observed_at: float,
    tcp_connect: bool,
    latency_ms: float | None = None,
) -> Fact:
    return _make(
        "reachability",
        asset_id,
        subject,
        {"tcp_connect": tcp_connect, "latency_ms": latency_ms},
        provenance={"origin": "action", "action_id": source_action_id},
        artifact_hash=artifact_hash,
        observed_at=observed_at,
        source_action_id=source_action_id,
    )


def record_auth_result(
    asset_id: str,
    subject: str,
    *,
    credential_id: str,
    source_action_id: str,
    artifact_hash: str,
    observed_at: float,
    authenticated: bool,
    role_hint: str = "",
) -> Fact:
    return _make(
        "auth_result",
        asset_id,
        subject,
        {
            "credential_id": credential_id,
            "authenticated": authenticated,
            "role_hint": role_hint,
        },
        provenance={"origin": "action", "action_id": source_action_id},
        artifact_hash=artifact_hash,
        observed_at=observed_at,
        source_action_id=source_action_id,
    )


def record_sbom_component(
    asset_id: str,
    *,
    purl: str,
    version: str = "",
    source: str = "",
    artifact_hash: str,
    observed_at: float,
    source_run_id: str | None = None,
    source_action_id: str | None = None,
    subject: str | None = None,
) -> Fact:
    return _make(
        "sbom_component",
        asset_id,
        subject or asset_id,
        {"purl": purl, "version": version, "source": source},
        provenance={"origin": "action" if source_action_id else "scanner"},
        artifact_hash=artifact_hash,
        observed_at=observed_at,
        source_run_id=source_run_id,
        source_action_id=source_action_id,
    )
