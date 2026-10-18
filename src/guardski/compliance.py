from __future__ import annotations

import json
import time
from pathlib import Path

FRAMEWORKS = {
    "pci": {
        "pci-11.4": "Testing after significant change",
        "pci-11.2": "Vulnerability scanning of infrastructure",
    },
    "ctem": {
        "ctem-scope": "Scope and asset inventory",
        "ctem-validate": "Validate exposure",
    },
    "soc2": {
        "cc7.1": "Detect configuration changes and vulnerabilities",
        "cc4.1": "Monitoring and evaluation of controls",
    },
}


def build_report(store, config, framework, now=None):
    now = time.time() if now is None else now
    if framework not in FRAMEWORKS:
        raise ValueError(f"Unknown framework: {framework}")
    chain_head = store.verify_events()
    coverage = store.coverage(config)
    findings = store.list_findings(now)
    feeds = [
        dict(row)
        for row in store.db.execute(
            "SELECT source, source_version, sha256, imported_at FROM intel_feeds WHERE current=1"
        )
    ]
    open_findings = [f for f in findings if f["effective_status"] in ("open", "in_progress")]
    gaps = [c for c in coverage if c["needs_attention"]]
    controls = []
    for control_id, description in FRAMEWORKS[framework].items():
        claim = "covered" if not gaps else "gap"
        controls.append(
            {
                "control": control_id,
                "description": description,
                "claim": claim,
                "evidence": {
                    "coverage_complete_targets": sum(
                        1 for c in coverage if not c["needs_attention"]
                    ),
                    "coverage_gaps": [c["target_id"] for c in gaps],
                    "open_findings": len(open_findings),
                    "intel_feeds": [feed["source"] for feed in feeds],
                },
            }
        )
    return {
        "framework": framework,
        "generated_at": now,
        "audit_chain_head": chain_head,
        "coverage": coverage,
        "open_findings": len(open_findings),
        "controls": controls,
        "note": "A view over evidence, not a new source of truth; a claim whose check "
        "never ran is a gap.",
    }


def write_report(store, config, framework, output_dir, now=None):
    report = build_report(store, config, framework, now)
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{framework}-report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True))
    return {"path": str(path), "audit_chain_head": report["audit_chain_head"]}
