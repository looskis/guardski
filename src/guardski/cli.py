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
from . import cmdb as cmdb_mod
from . import compliance as compliance_mod
from . import credentials as credentials_mod
from . import identity as identity_mod
from . import ingest as ingest_mod
from . import intel as intel_mod
from . import metrics as metrics_mod
from . import plans as plans_mod
from . import roe as roe_mod
from .config import load_config
from .evidence import export_bundle, sign_bundle, verify_bundle, verify_bundle_signature
from .providers import build_provider
from .reasoning.agent import generate_plan
from .reasoning.discovery import run_cycle
from .scheduler import run
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
    verify.add_argument("--signature", type=Path)
    verify.add_argument("--public-key", type=Path)
    signbundle = commands.add_parser("sign-bundle", help="Sign an evidence bundle (Ed25519)")
    signbundle.add_argument("bundle", type=Path)
    signbundle.add_argument("--key", required=True, type=Path)
    commands.add_parser("verify-audit", help="Verify the local audit hash chain")
    commands.add_parser(
        "gate", help="Fail for coverage gaps, overdue issues, or open HIGH/CRITICAL issues"
    )
    plan = commands.add_parser("plan", help="Generate an exploitation plan from the graph")
    plan.add_argument("--scope")
    plan.add_argument("--wait", action="store_true")
    commands.add_parser("plans", help="List generated plans")
    show_plan = commands.add_parser("show-plan", help="Show a plan, narrative, and steps")
    show_plan.add_argument("plan_id")
    show_context = commands.add_parser("show-context", help="Show the bundle/prompt the model saw")
    show_context.add_argument("plan_id")
    discover = commands.add_parser("discover", help="Run one discovery cycle")
    discover.add_argument("--scope")
    discover.add_argument("--dry-run", action="store_true")
    inv = commands.add_parser("investigations", help="List long-lived hypotheses")
    inv.add_argument("--status", default="open")
    commands.add_parser("facts", help="List recorded asset facts")
    commands.add_parser("tasks", help="List proposed discovery tasks")
    intel = commands.add_parser("intel", help="Offline vulnerability intelligence")
    intel.add_argument("action", choices=["import", "status", "fetch"])
    intel.add_argument("file", nargs="?")
    intel.add_argument("--kind", choices=["kev", "epss", "nvd", "osv"])
    intel.add_argument("--actor")
    intel.add_argument("--url")
    intel.add_argument("--output")
    intel.add_argument("--sha256")
    ingest = commands.add_parser("ingest", help="Import external findings")
    ingest.add_argument("format", choices=["sarif", "code-scanning", "dependabot"])
    ingest.add_argument("file")
    ingest.add_argument("--target", required=True)
    ingest.add_argument("--actor", required=True)
    commands.add_parser("model-probe", help="Record model runtime capabilities")
    approve = commands.add_parser("approve-plan", help="Approve a generated plan")
    approve.add_argument("plan_id")
    approve.add_argument("--actor", required=True)
    approve.add_argument("--valid-for")
    approve.add_argument("--signature", type=Path)
    reject = commands.add_parser("reject-plan", help="Reject a plan with a reason")
    reject.add_argument("plan_id")
    reject.add_argument("--actor", required=True)
    reject.add_argument("--reason", required=True)
    revalidate = commands.add_parser("revalidate-plan", help="Re-check a plan's cited evidence")
    revalidate.add_argument("plan_id")
    revalidate.add_argument("--actor", default="agent")
    dryrun = commands.add_parser("approve-dry-run", help="Approve a Tier-B dry run")
    dryrun.add_argument("plan_id")
    dryrun.add_argument("--actor", required=True)
    dryrun.add_argument("--signature", type=Path)
    roe = commands.add_parser("roe", help="Rules of engagement")
    roe.add_argument("action", choices=["verify"])
    roe.add_argument("file")
    cred = commands.add_parser("credential", help="Manage credential metadata")
    cred.add_argument("action", choices=["add", "list", "revoke"])
    cred.add_argument("credential_id", nargs="?")
    cred.add_argument("--kind")
    cred.add_argument("--scope", action="append", default=[])
    cred.add_argument("--ref")
    cred.add_argument("--actor")
    cred.add_argument("--signature", type=Path)
    report = commands.add_parser("report", help="Render a compliance report pack")
    report.add_argument("--framework", choices=["pci", "ctem", "soc2"], required=True)
    report.add_argument("--output", required=True)
    metrics_cmd = commands.add_parser("metrics", help="Discovery efficacy metrics")
    metrics_cmd.add_argument("--since", type=float)
    sign_cmd = commands.add_parser("sign", help="Sign a message with the operator key")
    sign_cmd.add_argument("message")
    sign_cmd.add_argument("--key", required=True, type=Path)
    assets_cmd = commands.add_parser("assets", help="Import offline asset metadata (CMDB)")
    assets_cmd.add_argument("action", choices=["import"])
    assets_cmd.add_argument("file")
    assets_cmd.add_argument("--actor", required=True)
    identity_cmd = commands.add_parser(
        "identity", help="Import offline identity data (Entra ID/AD)"
    )
    identity_cmd.add_argument("action", choices=["import"])
    identity_cmd.add_argument("file")
    identity_cmd.add_argument("--actor", required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    store = None
    try:
        if args.command == "verify":
            result = verify_bundle(args.bundle)
            if args.signature and args.public_key:
                result.update(
                    verify_bundle_signature(
                        args.bundle,
                        args.signature.read_text(),
                        args.public_key.read_text().strip(),
                    )
                )
            emit(result)
            return 0
        if args.command == "sign-bundle":
            emit(sign_bundle(args.bundle, args.key.read_text().strip()))
            return 0
        if args.command == "sign":
            from .signing import FileSigner

            signer = FileSigner(args.key.read_text().strip())
            emit(
                {
                    "fingerprint": signer.fingerprint(),
                    "signature": signer.sign(args.message.encode()),
                }
            )
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
        elif args.command == "model-probe":
            store.event(
                "model_probe",
                {
                    "model_id": config.model.model_id,
                    "features": {"structured_output": config.model.structured_output},
                },
            )
            emit({"model_id": config.model.model_id, "endpoint": config.model.endpoint})
        elif args.command == "facts":
            emit(store.list_facts())
        elif args.command == "tasks":
            emit(
                [
                    dict(row)
                    for row in store.db.execute("SELECT * FROM scan_tasks ORDER BY created_at")
                ]
            )
        elif args.command == "investigations":
            emit(
                [
                    dict(row)
                    for row in store.db.execute(
                        "SELECT * FROM investigations WHERE status=? ORDER BY created_at",
                        (args.status,),
                    )
                ]
            )
        elif args.command == "plans":
            emit(
                [
                    dict(row)
                    for row in store.db.execute(
                        "SELECT id, created_at, scope, status, context_digest FROM plans "
                        "ORDER BY created_at DESC"
                    )
                ]
            )
        elif args.command == "show-plan":
            row = store.db.execute("SELECT * FROM plans WHERE id=?", (args.plan_id,)).fetchone()
            if row is None:
                raise ValueError("Unknown plan")
            emit(
                {
                    "status": row["status"],
                    "context_digest": row["context_digest"],
                    "plan": json.loads(row["data_json"]),
                }
            )
        elif args.command == "show-context":
            row = store.db.execute(
                "SELECT bundle_json, prompt_json FROM plans WHERE id=?", (args.plan_id,)
            ).fetchone()
            if row is None:
                raise ValueError("Unknown plan")
            emit({"bundle": json.loads(row["bundle_json"]), "prompt": row["prompt_json"]})
        elif args.command in ("plan", "discover"):
            if not config.agent.reasoning_enabled:
                raise ValueError("reasoning_enabled must be true to plan or discover")
            provider = build_provider(config, store)
            if args.command == "discover":
                emit(
                    run_cycle(
                        store, config, provider, scope=args.scope or "all", dry_run=args.dry_run
                    )
                )
            else:
                emit(generate_plan(store, config, provider, scope=args.scope or "all"))
        elif args.command == "intel":
            if args.action == "status":
                emit(intel_mod.status(store))
            elif args.action == "fetch":
                if not args.kind or not args.url or not args.output:
                    raise ValueError("intel fetch requires --kind, --url, and --output")
                emit(intel_mod.fetch(args.kind, args.url, args.output, args.sha256))
            else:
                if not args.file or not args.kind or not args.actor:
                    raise ValueError("intel import requires a file, --kind, and --actor")
                emit(intel_mod.import_feed(store, config, Path(args.file), args.kind, args.actor))
        elif args.command == "ingest":
            if args.format == "dependabot":
                emit(
                    ingest_mod.import_dependabot(
                        store, config, Path(args.file), args.target, args.actor
                    )
                )
            else:
                emit(
                    ingest_mod.import_sarif(
                        store, config, Path(args.file), args.target, args.actor
                    )
                )
        elif args.command == "approve-plan":
            ttl = int(args.valid_for) if args.valid_for else config.agent.plan_ttl_hours
            signature = args.signature.read_text().strip() if args.signature else None
            emit(
                plans_mod.approve(
                    store,
                    args.plan_id,
                    args.actor,
                    ttl_hours=ttl,
                    config=config,
                    signature=signature,
                )
            )
        elif args.command == "reject-plan":
            emit(plans_mod.reject(store, args.plan_id, args.actor, args.reason))
        elif args.command == "revalidate-plan":
            emit(
                plans_mod.revalidate(
                    store,
                    args.plan_id,
                    args.actor,
                    ttl_hours=config.agent.plan_ttl_hours,
                    max_auto_extend_hours=config.agent.max_auto_extend_hours,
                )
            )
        elif args.command == "approve-dry-run":
            signature = args.signature.read_text().strip() if args.signature else None
            emit(
                plans_mod.approve_dry_run(
                    store, args.plan_id, args.actor, config=config, signature=signature
                )
            )
        elif args.command == "roe":
            parsed = roe_mod.load_roe(Path(args.file))
            emit(
                {
                    "roe_id": parsed.id,
                    "max_tier": parsed.max_tier,
                    "discovery": parsed.discovery,
                    "digest": parsed.digest,
                }
            )
        elif args.command == "credential":
            if args.action == "list":
                emit(credentials_mod.list_credentials(store))
            elif args.action == "add":
                if not args.kind or not args.scope or not args.actor or not args.ref:
                    raise ValueError("credential add requires --kind, --scope, --ref, and --actor")
                credentials_mod.add_credential(
                    store,
                    args.credential_id,
                    args.kind,
                    args.scope,
                    args.actor,
                    args.ref,
                    config=config,
                    signature=args.signature.read_text().strip() if args.signature else None,
                )
                emit({"added": args.credential_id})
            else:
                credentials_mod.revoke_credential(
                    store,
                    args.credential_id,
                    args.actor,
                    config=config,
                    signature=args.signature.read_text().strip() if args.signature else None,
                )
                emit({"revoked": args.credential_id})
        elif args.command == "report":
            emit(compliance_mod.write_report(store, config, args.framework, args.output))
        elif args.command == "assets":
            emit(cmdb_mod.import_assets(store, args.file, args.actor))
        elif args.command == "identity":
            emit(identity_mod.import_identities(store, args.file, args.actor))
        elif args.command == "metrics":
            emit(metrics_mod.report(store, config, since=args.since))
        return 0
    except Exception as exc:
        print(f"guardski: {exc}", file=sys.stderr)
        return 2
    finally:
        if store:
            store.close()
