from __future__ import annotations

from guardski.actions import ActionRequest
from guardski.policy import BudgetState, authorize, expand_targets
from guardski.roe import RoE

NOW = 1_700_000_000.0


def roe(**over):
    base = dict(
        id="r1",
        issued_at=NOW - 100,
        expires_at=NOW + 100,
        scope_allow=("10.0.0.0/24",),
        scope_exclude=(),
        max_tier="B",
        max_intensity=5,
        credentials=("cred-1",),
        discovery=True,
        allowed_actions=(
            "recon.nmap_rescan",
            "confirm.reachability",
            "confirm.banner",
        ),
    )
    base.update(over)
    return RoE(**base)


def req(action="recon.nmap_rescan", tier="A", targets=("10.0.0.5",), **over):
    base = dict(action_id=action, tier=tier, targets=targets)
    base.update(over)
    return ActionRequest(**base)


def test_expand_targets():
    assert expand_targets(("10.0.0.0/30",)) == ["10.0.0.1", "10.0.0.2"]
    assert expand_targets(("10.0.0.5",)) == ["10.0.0.5"]


def test_allows_in_scope_recon():
    decision = authorize(req(), roe(), NOW)
    assert decision.allowed, decision.reason_code


def test_denies_expired_roe():
    decision = authorize(req(), roe(expires_at=NOW - 1), NOW)
    assert not decision.allowed and decision.reason_code == "roe_expired"


def test_denies_action_not_in_allowlist():
    action = req(action="confirm.banner", targets=("10.0.0.5",))
    decision = authorize(action, roe(allowed_actions=("recon.nmap_rescan",)), NOW)
    assert decision.reason_code == "action_not_allowed"


def test_denies_discovery_when_disabled():
    decision = authorize(req(), roe(discovery=False), NOW)
    assert decision.reason_code == "discovery_disabled"


def test_denies_tier_mismatch_and_too_high():
    decision = authorize(req(tier="B"), roe(), NOW)
    assert decision.reason_code == "tier_mismatch"
    assert authorize(req(tier="C"), roe(), NOW).reason_code == "tier_mismatch"


def test_denies_out_of_scope_and_excluded():
    assert authorize(req(targets=("10.9.9.9",)), roe(), NOW).reason_code == "target_out_of_scope"
    assert authorize(req(), roe(scope_exclude=("10.0.0.5",)), NOW).reason_code == "target_excluded"


def test_denies_intensity_over_ceiling():
    assert authorize(req(intensity=9), roe(), NOW).reason_code == "intensity_exceeded"


def test_denies_budget_exhausted():
    budget = BudgetState(tasks_this_hour=1)
    decision = authorize(req(), roe(max_tasks_per_hour=1), NOW, budget=budget)
    assert decision.reason_code == "budget_exhausted"


def test_denies_bad_credentials():
    assert authorize(req(credential_ids=("nope",)), roe(), NOW).reason_code == "credential_missing"
    creds = {"cred-1": {"scope": ["10.0.0.0/24"], "expires_at": NOW + 10}}
    assert authorize(req(credential_ids=("cred-1",)), roe(), NOW, credentials=creds).allowed
    expired = {"cred-1": {"scope": ["10.0.0.0/24"], "expires_at": NOW - 1}}
    decision = authorize(req(credential_ids=("cred-1",)), roe(), NOW, credentials=expired)
    assert decision.reason_code == "credential_expired"
    narrow = {"cred-1": {"scope": ["192.168.0.0/24"], "expires_at": NOW + 10}}
    decision = authorize(req(credential_ids=("cred-1",)), roe(), NOW, credentials=narrow)
    assert decision.reason_code == "credential_out_of_scope"


def test_denies_invalid_signature():
    assert authorize(req(), roe(), NOW, signature_ok=False).reason_code == "roe_invalid"
