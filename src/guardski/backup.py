from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import zipfile
from pathlib import Path


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def backup(config, output):
    output = Path(output)
    if output.exists():
        raise ValueError(f"Backup output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=config.state_dir) as temporary:
        root = Path(temporary)
        snapshot = root / "guardski.sqlite3"
        source = sqlite3.connect(config.state_dir / "guardski.sqlite3")
        destination = sqlite3.connect(snapshot)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        files = {
            "guardski.sqlite3": snapshot,
            "config.json": json.dumps(config.snapshot(), indent=2).encode(),
        }
        for name in ("artifacts", "intel"):
            base = config.state_dir / name
            if base.exists():
                for item in base.rglob("*"):
                    if item.is_file():
                        files[f"{name}/{item.relative_to(base)}"] = item
        manifest = {
            name: _sha(content)
            if isinstance(content, Path)
            else hashlib.sha256(content).hexdigest()
            for name, content in files.items()
        }
        files["manifest.json"] = json.dumps(manifest, indent=2).encode()
        with zipfile.ZipFile(output, "x", zipfile.ZIP_DEFLATED) as archive:
            for name, content in sorted(files.items()):
                if isinstance(content, Path):
                    archive.write(content, name)
                else:
                    archive.writestr(name, content)
    return {"path": str(output), "sha256": _sha(output)}


def restore(input_path, state_dir, force=False):
    state = Path(state_dir)
    if state.exists() and any(state.iterdir()) and not force:
        raise ValueError("Refusing to restore over a non-empty state directory (use --force)")
    state.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(input_path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        for name, digest in manifest.items():
            if name.startswith(("/", "..")) or ".." in Path(name).parts:
                raise ValueError(f"Unsafe path in backup: {name}")
            if hashlib.sha256(archive.read(name)).hexdigest() != digest:
                raise ValueError(f"Backup checksum mismatch: {name}")
        archive.extractall(state)
    return {"restored": str(state), "files": len(manifest)}
