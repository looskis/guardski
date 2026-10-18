from __future__ import annotations

from dataclasses import dataclass, field

from ..plans import gate_dry_run


class CleanupRegistry:
    """Every Tier-B action registers its rollback before it acts (SPEC §6)."""

    def __init__(self):
        self.entries = []

    def register(self, description, fn):
        self.entries.append((description, fn))

    def run_all(self):
        failures = []
        for description, fn in reversed(self.entries):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - a failed cleanup is the critical signal
                failures.append(f"{description}: {exc}")
        return failures


@dataclass
class ProofResult:
    status: str
    detail: str = ""
    cleanup_failures: list = field(default_factory=list)


def dry_run(probe, request):
    """Produce a defensible \"I could do X\" result without touching the target,
    and record the digest the operator must approve."""
    digest = probe.simulate(request)
    return {"simulated": True, "detail": digest}


def run_proof(store, plan_id, request, probe, dry_run_digest, registry=None):
    """Execute a Tier-B proof with mandatory dry-run approval and cleanup confirmation."""
    gate_dry_run(store, plan_id, dry_run_digest)
    registry = registry or CleanupRegistry()
    outcome = probe.execute(request, registry)
    failures = registry.run_all()
    if failures:
        return ProofResult("failed", "; ".join(failures), failures)
    return ProofResult("succeeded", outcome)
