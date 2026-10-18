from __future__ import annotations

from guardski.actions.monitor import ExecutionMonitor, Signal
from guardski.credentials import add_credential, list_credentials, metadata, revoke_credential
from guardski.notify import NotificationEvent, notify


def test_monitor_aborts_on_latency_spike(config):
    monitor = ExecutionMonitor(config.monitor, config.agent)
    for _ in range(5):
        monitor.observe(Signal(latency_ms=100.0))
    assert not monitor.should_abort()
    for _ in range(3):
        monitor.observe(Signal(latency_ms=5000.0))
    assert monitor.should_abort()
    assert monitor.abort_reason() == "latency"


def test_monitor_aborts_on_unavailability_and_size(config):
    monitor = ExecutionMonitor(config.monitor, config.agent)
    monitor.observe(Signal(latency_ms=10.0))
    monitor.observe(Signal(reachable=False))
    assert monitor.abort_reason() == "unavailable"


def test_monitor_baseline_not_enforced_early(config):
    monitor = ExecutionMonitor(config.monitor, config.agent)
    monitor.observe(Signal(latency_ms=1.0))
    monitor.observe(Signal(latency_ms=100000.0))
    assert not monitor.should_abort()


def test_notify_records_and_covert_suppresses(config, store):
    event = NotificationEvent(
        kind="plan_generated",
        severity="info",
        summary="s",
        details={},
        actor="agent",
        timestamp=1.0,
    )
    assert notify(store, config, event)
    rows = store.db.execute("SELECT COUNT(*) FROM notifications").fetchone()[0]
    assert rows == 1
    # Covert suppression now requires a signed RoE, not agent.mode alone (#8).
    from guardski.roe import RoE

    info = NotificationEvent(
        kind="plan_generated",
        severity="info",
        summary="s",
        details={},
        actor="agent",
        timestamp=2.0,
    )
    covert_roe = RoE(id="r", issued_at=0, expires_at=10000, mode="covert")
    notify(store, config, info, roe=covert_roe, now=5.0)
    assert store.db.execute("SELECT COUNT(*) FROM notifications").fetchone()[0] == 1


def test_credentials_metadata_lifecycle(config, store):
    import os

    from guardski.credentials import resolve_credential

    add_credential(
        store,
        "cred-1",
        "password",
        ["10.0.0.0/24"],
        "operator",
        "env:GUARDSKI_TEST_CRED",
        role="admin",
    )
    assert list_credentials(store)[0]["id"] == "cred-1"
    assert metadata(store)["cred-1"]["ref"] == "env:GUARDSKI_TEST_CRED"
    assert metadata(store)["cred-1"]["scope"] == ["10.0.0.0/24"]
    os.environ["GUARDSKI_TEST_CRED"] = "s3cret"
    assert resolve_credential(store, config, "cred-1") == "s3cret"
    revoke_credential(store, "cred-1", "operator")
    assert list_credentials(store) == []
    assert store.verify_events()
