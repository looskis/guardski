from __future__ import annotations

import json
import logging
import time
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
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


SYSLOG_FACILITY = 1  # user
CEF_SEVERITY = {"info": "3", "warning": "6", "critical": "9"}


def rfc5424(event: NotificationEvent, host: str = "-") -> str:
    severity = {"critical": 2, "warning": 4, "info": 6}.get(event.severity, 6)
    priority = SYSLOG_FACILITY * 8 + severity
    timestamp = datetime.fromtimestamp(event.timestamp, UTC).isoformat()
    structured = f'[guardski@32473 kind="{event.kind}" severity="{event.severity}"]'
    return f"<{priority}>1 {timestamp} {host} guardski - {event.kind} {structured} {event.summary}"


def cef(event: NotificationEvent, vendor: str, product: str, version: str) -> str:
    severity = CEF_SEVERITY.get(event.severity, "3")
    extensions = " ".join(f"{k}={v}" for k, v in sorted(event.details.items()))
    return (
        f"CEF:0|{vendor}|{product}|{version}|{event.kind}|{event.summary}|{severity}|"
        f"msg={event.summary} suser={event.actor} {extensions}"
    )


class SyslogNotifier:
    name = "syslog"

    def __init__(self, config) -> None:
        self.format = getattr(config, "syslog_format", "rfc5424")
        self.vendor = getattr(config, "cef_vendor", "Guardski")
        self.product = getattr(config, "cef_product", "Guardski")
        self.version = getattr(config, "cef_version", "0.1.0")

    def render(self, event: NotificationEvent) -> str:
        if self.format == "cef":
            return cef(event, self.vendor, self.product, self.version)
        return rfc5424(event)

    def notify(self, event: NotificationEvent) -> None:
        message = self.render(event)
        try:
            import syslog as syslog_module

            syslog_module.syslog(message)
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
            notifiers.append(SyslogNotifier(config.notify))
    return notifiers


COVERT_ALLOWED = {"critical"}


def effective_mode(config, roe=None, now=None):
    """Covert mode requires a signed RoE that enables it and has not expired (#8).

    `agent.mode` alone no longer suppresses notifications.
    """
    now = time.time() if now is None else now
    if roe is not None and getattr(roe, "mode", "transparent") == "covert":
        expires = getattr(roe, "mode_expires_at", None)
        if expires is None or now < expires:
            return "covert"
    return "transparent"


def notify(store, config, event: NotificationEvent, notifiers=None, roe=None, now=None) -> bool:
    delivered = True
    if effective_mode(config, roe, now) == "covert" and event.severity not in COVERT_ALLOWED:
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
