from __future__ import annotations

import threading
import time

from .providers import ModelError, build_provider
from .reasoning.agent import generate_plan
from .reasoning.discovery import run_cycle
from .store import Store


def start_heartbeat(config, stop):
    """Keep the daemon heartbeat current while a model call blocks the main loop (§4.2)."""

    def loop():
        beat = Store(config.state_dir)
        try:
            while not stop.wait(5):
                beat.heartbeat()
        finally:
            beat.close()

    thread = threading.Thread(target=loop, name="guardski-heartbeat", daemon=True)
    thread.start()
    return thread


class ReasoningRunner:
    """Services queued plan requests and the scheduled discovery cycle inside the daemon."""

    def __init__(self, config, store, sleep=time.sleep):
        self.config = config
        self.store = store
        self.sleep = sleep
        self.provider = build_provider(config, store, sleep=sleep)
        self.last_discovery = 0.0
        self.last_purge = 0.0

    def tick(self, now=None, stop=None):
        now = time.time() if now is None else now
        self._service_requests(now)
        interval = self.config.agent.discovery_interval_seconds
        if self.config.agent.discovery_enabled and interval > 0:
            if now - self.last_discovery >= interval:
                self.last_discovery = now
                self._discover(now)
        self._claim_tasks(now, stop)
        if now - self.last_purge >= 3600:
            self.last_purge = now
            self._purge(now)

    def _service_requests(self, now):
        rows = self.store.db.execute(
            "SELECT * FROM plan_requests WHERE state='queued' ORDER BY created_at LIMIT 1"
        ).fetchall()
        for row in rows:
            self.store.db.execute(
                "UPDATE plan_requests SET state='running', claimed_at=? WHERE id=?",
                (now, row["id"]),
            )
            self.store.db.commit()
            try:
                outcome = generate_plan(
                    self.store,
                    self.config,
                    self.provider,
                    now=now,
                    scope=row["scope"] or "all",
                )
                self.store.db.execute(
                    "UPDATE plan_requests SET state='done', finished_at=?, plan_id=? WHERE id=?",
                    (now, outcome.get("plan_id"), row["id"]),
                )
            except Exception as exc:  # noqa: BLE001 - a failed request is recorded, not fatal
                self.store.db.execute(
                    "UPDATE plan_requests SET state='failed', finished_at=?, error=? WHERE id=?",
                    (now, str(exc), row["id"]),
                )
            self.store.db.commit()

    def _discover(self, now):
        try:
            run_cycle(self.store, self.config, self.provider, now=now)
        except ModelError:
            return

    def _claim_tasks(self, now, stop):
        if not self.config.agent.discovery_enabled:
            return
        from pathlib import Path

        from .actions.recon import claim_and_run
        from .roe import load_roe

        path = Path(self.config.roe.path)
        if not path.is_file():
            return
        try:
            roe = load_roe(path)
        except Exception:  # noqa: BLE001 - an unreadable RoE blocks action, not the daemon
            return
        claim_and_run(self.store, self.config, roe, stop=stop, now=now)

    def _purge(self, now):
        from .retention import purge

        purge(self.store, self.config, now)
