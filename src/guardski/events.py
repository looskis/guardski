from __future__ import annotations

# Event-kind registry: the audit chain is the evidence source, so every kind has a fixed
# name and a set of required payload fields. `Store.event` validates before writing, which
# keeps the chain queryable by metrics and analysis. New kinds are added here, never
# invented at a call site.

PHASE0_FIELDS: dict[str, tuple[str, ...]] = {
    "schedule_configured": ("target_id", "next_run", "config_digest"),
    "schedule_removed": ("target_id",),
    "scan_started": ("run_id", "target_id", "config_digest"),
    "scan_finished": ("run_id", "status", "finding_count", "artifact_hashes"),
    "scan_interrupted": ("run_id",),
    "finding_reopened": ("finding_id", "run_id"),
    "finding_triaged": ("finding_id", "status", "reason"),
    "schema_migrated": ("from_version", "to_version"),
}

AGENTIC_FIELDS: dict[str, tuple[str, ...]] = {
    # reasoning / plans
    "plan_generated": (
        "plan_id",
        "scope",
        "context_digest",
        "graph_digest",
        "model_id",
        "prompt_sha256",
        "builder_version",
    ),
    "plan_reused": ("plan_id", "context_digest", "model_id"),
    "plan_validation_failed": ("scope", "reasons"),
    "plan_generation_failed": ("error_kind", "model_id", "attempt_count"),
    "plan_approved": ("plan_id", "actor", "context_digest"),
    "plan_rejected": ("plan_id", "actor", "reason"),
    "plan_revalidated": ("plan_id", "actor"),
    "plan_stale": ("plan_id", "reason"),
    "plan_not_approved": ("plan_id", "check"),
    "plan_dry_run": ("plan_id", "dry_run_digest"),
    "plan_dry_run_approved": ("plan_id", "actor", "dry_run_digest"),
    "plan_superseded": ("plan_id", "superseded_by"),
    # model resilience
    "model_call_failed": ("model_id", "endpoint_host", "error_kind", "attempt_count"),
    "model_circuit_tripped": ("model_id", "endpoint_host"),
    "model_circuit_reset": ("model_id",),
    "model_degraded": ("model_id",),
    "model_probe": ("model_id", "features"),
    "context_overflow": ("context_digest", "estimated_tokens", "budget"),
    "redaction_applied": ("source", "kind", "count"),
    # facts / discovery
    "fact_recorded": ("fact_id", "asset_id", "kind"),
    "fact_rejected": ("asset_id", "kind", "reason"),
    "scope_anomaly": ("addr", "target_id"),
    "scan_task_proposed": ("task_id", "action_id", "target_id"),
    "scan_task_authorized": ("task_id", "action_id", "roe_id"),
    "scan_task_denied": ("task_id", "reason_code"),
    "scan_task_completed": ("task_id", "state"),
    "scan_task_expired": ("task_id",),
    "task_budget_exhausted": ("scope", "denied"),
    "discovery_cycle_finished": ("scope",),
    "discovery_dry_run": ("scope", "context_digest"),
    "hypothesis_opened": ("investigation_id", "scope"),
    "hypothesis_confirmed": ("investigation_id",),
    "hypothesis_refuted": ("investigation_id",),
    "hypothesis_blocked": ("investigation_id", "reason"),
    "hypothesis_abandoned": ("investigation_id", "actor", "reason"),
    # intel / ingestion
    "intel_imported": ("source", "source_version", "sha256", "records"),
    "intel_relevant": ("source", "cve"),
    "findings_imported": ("target_id", "tool", "count"),
    "assets_imported": ("count",),
    "identity_imported": ("count",),
    # actions / policy
    "action_authorized": ("action_id", "roe_id", "targets"),
    "action_denied": ("action_id", "reason_code"),
    "action_started": ("action_id",),
    "action_completed": ("action_id", "status"),
    "action_deconflicted": ("action_id", "conflicting_action_id"),
    "abort_requested": ("actor",),
    "monitor_anomaly": ("action_id", "signal_kind", "observed_value", "threshold", "aborted"),
    "finding_validated": ("finding_id",),
    "finding_refuted": ("finding_id",),
    "finding_exploit_confirmed": ("finding_id", "action_id"),
    "finding_cleanup_failed": ("finding_id", "action_id"),
    "finding_action_failed": ("finding_id", "action_id"),
    "finding_remediated": ("finding_id", "run_id"),
    "finding_unverified": ("finding_id", "blind_spot"),
    "cleanup_failed": ("action_id",),
    # governance / retention / notify
    "config_changed": ("actor",),
    "roe_loaded": ("roe_id", "sha256"),
    "roe_rejected": ("reason",),
    "credential_added": ("credential_id", "actor"),
    "credential_revoked": ("credential_id", "actor"),
    "notification_sent": ("notification_id", "kind", "severity"),
    "notification_failed": ("notification_id", "kind", "error"),
    "coverage_degraded": ("target_id",),
    "retention_purged": ("table", "count"),
    "retention_blocked": ("table", "reason"),
    "retention_archived": ("table", "count"),
}

EVENT_FIELDS: dict[str, tuple[str, ...]] = {**PHASE0_FIELDS, **AGENTIC_FIELDS}


class UnknownEventKind(ValueError):
    pass


def validate(kind: str, details: dict) -> None:
    """Raise if `kind` is unregistered or `details` is missing a required field."""
    if kind not in EVENT_FIELDS:
        raise UnknownEventKind(f"Unregistered event kind: {kind}")
    missing = [field for field in EVENT_FIELDS[kind] if field not in details]
    if missing:
        raise ValueError(f"Event {kind} is missing required field(s): {', '.join(missing)}")
