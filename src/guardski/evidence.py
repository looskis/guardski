from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path

from .config import Config
from .store import Store


def sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def export_bundle(config: Config, store: Store, output: Path, sign_key: str | None = None) -> dict:
    if output.exists():
        raise ValueError(f"Evidence output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="evidence-", dir=config.state_dir) as temporary:
        root = Path(temporary)
        backup_path = root / "guardski.sqlite3"
        backup = sqlite3.connect(backup_path)
        try:
            store.db.backup(backup)
        finally:
            backup.close()
        snapshot = Store(root)
        try:
            chain_head = snapshot.verify_events()
            files: dict[str, bytes | Path] = {}

            def add_json(name: str, data: object):
                files[name] = json.dumps(data, indent=2).encode()

            add_json("config.json", config.snapshot())
            add_json("findings.json", snapshot.list_findings())
            add_json("coverage.json", snapshot.coverage(config))
            add_json("events.json", snapshot.audit_events())
            runs = [
                dict(row) for row in snapshot.db.execute("SELECT * FROM runs ORDER BY started_at")
            ]
            add_json("runs.json", runs)
            for run in runs:
                if not run["artifact_dir"]:
                    continue
                metadata = json.loads(run["metadata_json"])
                directory = config.state_dir / run["artifact_dir"]
                for name, expected in metadata.get("artifact_hashes", {}).items():
                    path = directory / name
                    if sha256_file(path) != expected:
                        raise ValueError(f"Stored scan artifact has changed: {path}")
                    files[f"reports/{run['id']}/{name}"] = path
            add_json(
                "bundle.json",
                {
                    "format_version": 1,
                    "created_at": time.time(),
                    "audit_chain_head": chain_head,
                    "note": "Local integrity hashes are not a signature or proof against "
                    "administrator tampering. Retain this bundle and its hash in an "
                    "independently controlled archive.",
                },
            )
        finally:
            snapshot.close()
        # The backup is self-contained after closing all connections and checkpointing WAL.
        files["guardski.sqlite3"] = backup_path
        manifest = {
            name: sha256_file(content)
            if isinstance(content, Path)
            else hashlib.sha256(content).hexdigest()
            for name, content in files.items()
        }
        files["manifest.json"] = json.dumps(manifest, indent=2).encode()
        staged = root / "bundle.zip"
        with zipfile.ZipFile(staged, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in sorted(files.items()):
                if isinstance(content, Path):
                    archive.write(content, name)
                else:
                    archive.writestr(name, content)
        # Exclusive creation avoids overwriting an independently produced evidence bundle.
        with output.open("xb") as target, staged.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)
    result = {
        "path": str(output.resolve()),
        "sha256": sha256_file(output),
        "audit_chain_head": chain_head,
    }
    if sign_key:
        result.update(sign_bundle(output, sign_key))
    return result


def verify_bundle(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Evidence bundle contains duplicate file names")
        manifest = json.loads(archive.read("manifest.json"))
        if set(manifest) != set(names) - {"manifest.json"}:
            raise ValueError("Evidence bundle file list does not match manifest")
        for name, digest in manifest.items():
            with archive.open(name) as source:
                if hashlib.file_digest(source, "sha256").hexdigest() != digest:
                    raise ValueError(f"Evidence checksum mismatch: {name}")
        events = json.loads(archive.read("events.json"))
        previous = "0" * 64
        for event in events:
            digest = hashlib.sha256((previous + event["payload"]).encode()).hexdigest()
            if event["previous_hash"] != previous or event["hash"] != digest:
                raise ValueError("Evidence audit chain mismatch")
            previous = digest
        bundle = json.loads(archive.read("bundle.json"))
        if bundle["audit_chain_head"] != previous:
            raise ValueError("Evidence audit chain head mismatch")
    return {
        "verified": True,
        "files": len(manifest),
        "audit_chain_head": previous,
        "sha256": sha256_file(path),
    }


def sign_bundle(path: Path, private_key_hex: str) -> dict:
    """Produce a detached Ed25519 signature over the bundle's SHA-256 (SPEC §8.1)."""
    from .signing import sign

    digest = sha256_file(path)
    signature = sign(private_key_hex, bytes.fromhex(digest))
    signature_path = Path(str(path) + ".sig")
    signature_path.write_text(signature + "\n")
    return {"bundle": str(path), "signature": str(signature_path), "sha256": digest}


def verify_bundle_signature(path: Path, signature_hex: str, public_key_hex: str) -> dict:
    from .signing import fingerprint, verify

    digest = sha256_file(path)
    ok = verify(public_key_hex, signature_hex.strip(), bytes.fromhex(digest))
    return {"verified": ok, "fingerprint": fingerprint(public_key_hex)}
