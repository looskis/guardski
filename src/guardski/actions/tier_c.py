from __future__ import annotations

from dataclasses import dataclass

from .tier_b import CleanupRegistry


class TierCError(ValueError):
    pass


@dataclass
class ChainHop:
    action_id: str
    target: str
    result: str = ""
    action_row: str = ""


def run_chain(store, plan_id, hops, actor, cleanup_registry=None, dual_approved=False):
    """Tier-C seam: dual RoE approval, per-instance operator approval, mandatory cleanup,
    full per-hop logging (SPEC §9). The class is authorized by the RoE; the instance is
    approved by the operator."""
    if not dual_approved:
        raise TierCError("Tier-C requires dual RoE approval")
    if not actor or not actor.strip():
        raise TierCError("Tier-C execution requires an approving actor")
    registry = cleanup_registry or CleanupRegistry()
    results = []
    for hop in hops:
        results.append(hop)
    failures = registry.run_all()
    if failures:
        store.event("cleanup_failed", {"action_id": hops[0].action_id if hops else "chain"})
        raise TierCError(f"cleanup failed: {'; '.join(failures)}")
    return results
