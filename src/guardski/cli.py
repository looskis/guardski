from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import signal
import sys
from datetime import datetime
from pathlib import Path
from threading import Event

from . import __version__
from .agent import run
from .config import load_config
from .evidence import export_bundle, verify_bundle
from .store import STATUSES, Store


def emit(value: object) -> None:
    print(json.dumps(value, indent=2))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="On-premises security scanning and evidence")
    root.add_argument("--version", action="version", version=f"Guardski {__version__}")
    root.add_argument("--config", type=Path, default=Path("guardski.toml"))
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="Validate configuration and required scanner availability")
    commands.add_parser("run", help="Run the persistent scheduler")
    scan = commands.add_parser("scan", help="Scan configured targets once")
    scan.add_argument("--target")
    commands.add_parser("status", help="Show target coverage and daemon health")
    commands.add_parser(
        "health", help="Exit successfully only while the daemon heartbeat is current"
    )
    history = commands.add_parser("history", help="Show recent scan runs")
    history.add_argument("--limit", type=int, default=50)
    findings = commands.add_parser("findings", help="Show findings with ownership and SLA status")
    findings.add_argument("--overdue", action="store_true")
    findings.add_argument("--status", choices=STATUSES)
    triage = commands.add_parser("triage", help="Record a remediation decision and audit event")
    triage.add_argument("finding_id")
    triage.add_argument("--status", choices=STATUSES, required=True)
    triage.add_argument("--actor", required=True)
    triage.add_argument("--reason", required=True)
    triage.add_argument("--owner")
    triage.add_argument("--risk-until", help="ISO 8601 timestamp with timezone")
    export = commands.add_parser("export", help="Export a consistent, checksummed evidence bundle")
    export.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify", help="Verify an evidence bundle (no config required)")
    verify.add_argument("bundle", type=Path)
    commands.add_parser("verify-audit", help="Verify the local audit hash chain")
    commands.add_parser(
        "gate", help="Fail for coverage gaps, overdue issues, or open HIGH/CRITICAL issues"
    )
    return root


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    store = None
    try:
        if args.command == "verify":
            emit(verify_bundle(args.bundle))
            return 0
        config = load_config(args.config)
        if args.command == "check":
            required = sorted({t.engine for t in config.targets})
            engines = {name: shutil.which(getattr(config, name)) for name in required}
            emit(
                {
                    "config_valid": True,
                    "config_digest": config.digest,
                    "engines": engines,
                    "targets": len(config.targets),
                    "schedule_timezone": "UTC",
                }
            )
            return 0 if all(engines.values()) else 1
        store = Store(config.state_dir)
        if args.command in {"run", "scan"}:
            stop = Event()
            previous = {
                sig: signal.signal(sig, lambda *_: stop.set())
                for sig in (signal.SIGINT, signal.SIGTERM)
            }
            try:
                results = run(
                    config, store, stop, args.command == "scan", getattr(args, "target", None)
                )
                if args.command == "scan":
                    emit(results)
                    return (
                        1
                        if stop.is_set() or any(r["status"] != "succeeded" for r in results)
                        else 0
                    )
                return 0
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
        if args.command == "status":
            emit({"daemon_healthy": store.healthy(), "targets": store.coverage(config)})
        elif args.command == "health":
            return 0 if store.healthy() else 1
        elif args.command == "history":
            if not 1 <= args.limit <= 10000:
                raise ValueError("--limit must be between 1 and 10000")
            emit(store.history(args.limit))
        elif args.command == "findings":
            findings = store.list_findings()
            emit(
                [
                    f
                    for f in findings
                    if (not args.overdue or f["overdue"])
                    and (not args.status or f["effective_status"] == args.status)
                ]
            )
        elif args.command == "triage":
            risk_until = None
            if args.risk_until:
                expiration = datetime.fromisoformat(args.risk_until.replace("Z", "+00:00"))
                if expiration.tzinfo is None:
                    raise ValueError("--risk-until requires an explicit timezone")
                risk_until = expiration.timestamp()
            store.triage(
                args.finding_id, args.status, args.actor, args.reason, args.owner, risk_until
            )
            emit({"finding_id": args.finding_id, "status": args.status, "recorded": True})
        elif args.command == "export":
            emit(export_bundle(config, store, args.output.resolve()))
        elif args.command == "verify-audit":
            emit({"verified": True, "audit_chain_head": store.verify_events()})
        elif args.command == "gate":
            coverage = [c for c in store.coverage(config) if c["needs_attention"]]
            findings = [
                f
                for f in store.list_findings()
                if f["effective_status"] in {"open", "in_progress"}
                and (f["severity"] in {"HIGH", "CRITICAL"} or f["overdue"])
            ]
            emit(
                {
                    "passed": not coverage and not findings,
                    "coverage_gaps": coverage,
                    "blocking_findings": findings,
                }
            )
            return 1 if coverage or findings else 0
        return 0
    except Exception as exc:
        print(f"guardski: {exc}", file=sys.stderr)
        return 2
    finally:
        if store:
            store.close()
