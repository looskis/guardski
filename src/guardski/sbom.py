from __future__ import annotations

import json
import time
import uuid
from pathlib import Path


def generate(store, asset_id=None):
    rows = store.list_facts(asset_id=asset_id, kind="sbom_component")
    components = []
    for fact in rows:
        value = fact["value"]
        purl = value.get("purl") or "pkg:generic/unknown"
        components.append(
            {
                "type": "library",
                "name": purl.split("/")[-1] or purl,
                "version": value.get("version", ""),
                "purl": purl,
                "bom-ref": fact["id"],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "component": {
                "type": "application",
                "name": asset_id or "guardski-estate",
            },
        },
        "components": components,
    }


def write(store, output, asset_id=None):
    path = Path(output)
    document = generate(store, asset_id)
    path.write_text(json.dumps(document, indent=2, sort_keys=True))
    return {"path": str(path), "components": len(document["components"])}
