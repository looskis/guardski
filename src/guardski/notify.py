from __future__ import annotations

import json
import logging
import time
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from typing import Protocol

log = logging.getLogger("guardski")


@dataclass(frozen=True)
class NotificationEvent:
    kind: str
    severity: str
    summary: str
    details: dict
    actor: str
    timestamp: float


class Notifier(Protocol):
    name: str

    def notify(self, event: NotificationEvent) -> None: ...


class LogNotifier:
    name = "log"

    def notify(self, event: NotificationEvent) -> None:
        log.info("notify kind=%s severity=%s summary=%s", event.kind, event.severity, event.summary)


class WebhookNotifier:
    name = "webhook"

    def __init__(self, url: str, timeout_seconds: int) -> None:
        self.url = url
        self.timeout = timeout_seconds

    def notify(self, event: NotificationEvent) -> None:
        payload = json.dumps(asdict(event)).encode()
        request = urllib.request.Request(
            self.url, data=payload, headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(request, timeout=self.timeout)


class SyslogNotifier:
    name = "syslog"

    def notify(self, event: NotificationEvent) -> None:
        try:
            import syslog as syslog_module

            syslog_module.syslog(f"{event.severity}: {event.kind}: {event.summary}")
        except (ImportError, OSError):  # pragma: no cover - platform dependent
            log.warning("syslog unavailable; dropped %s", event.kind)


def build_notifiers(config) -> list[Notifier]:
    notifiers: list[Notifier] = []
    for name in config.notify.notifiers:
        if name == "log":
            notifiers.append(LogNotifier())
        elif name == "webhook":
            notifiers.append(
                WebhookNotifier(config.notify.webhook_url, config.notify.webhook_timeout_seconds)
            )
        elif name == "syslog":
            notifiers.append(SyslogNotifier())
    return notifiers


COVERT_ALLOWED = {"critical"}


def notify(store, config, event: NotificationEvent, notifiers=None) -> bool:
    delivered = True
    if config.agent.mode == "covert" and event.severity not in COVERT_ALLOWED:
        return True
    handlers = notifiers if notifiers is not None else build_notifiers(config)
    notification_id = str(uuid.uuid4())
    for handler in handlers:
        try:
            handler.notify(event)
            store.db.execute(
                """INSERT INTO notifications
                (id, created_at, kind, severity, summary, details_json, actor, delivered,
                 delivered_at, notifier) VALUES (?,?,?,?,?,?,?,1,?,?)""",
                (
                    notification_id,
                    event.timestamp,
                    event.kind,
                    event.severity,
                    event.summary,
                    json.dumps(event.details),
                    event.actor,
                    time.time(),
                    handler.name,
                ),
            )
        except Exception as exc:  # noqa: BLE001 - a notifier must never crash the agent
            delivered = False
            store.db.execute(
                """INSERT INTO notifications
                (id, created_at, kind, severity, summary, details_json, actor, delivered,
                 delivered_at, notifier) VALUES (?,?,?,?,?,?,?,0,?,?)""",
                (
                    notification_id,
                    event.timestamp,
                    event.kind,
                    event.severity,
                    event.summary,
                    json.dumps(event.details),
                    event.actor,
                    time.time(),
                    handler.name,
                ),
            )
            log.warning("notifier %s failed: %s", handler.name, exc)
    store.db.commit()
    return delivered
