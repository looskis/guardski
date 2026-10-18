from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import shutil
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from threading import Event

from .config import Config, Target
from .scanners import run_scanner
from .store import Store

log = logging.getLogger("guardski")


@contextmanager
def agent_lock(state_dir: Path):
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state_dir / "agent.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(
                "Another Guardski scan or daemon is using this state directory"
            ) from exc
        try:
            yield lock.fileno()
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def cleanup_work(config: Config) -> None:
    work_root = config.state_dir / "work"
    if work_root.exists():
        for item in work_root.iterdir():
            if item.is_dir() and not item.is_symlink():
                shutil.rmtree(item)


def scan_target(
    config: Config, target: Target, store: Store, stop: Event, lease_fd: int | None = None
) -> dict:
    run_id = str(uuid.uuid4())
    work = config.state_dir / "work" / run_id
    work.mkdir(parents=True, mode=0o700)
    store.start(run_id, target, config)
    log.info("scan_started target=%s run=%s engine=%s", target.id, run_id, target.engine)
    findings, metadata, error = [], {}, None
    last_heartbeat = 0.0

    def heartbeat():
        nonlocal last_heartbeat
        if time.monotonic() - last_heartbeat > 5:
            store.heartbeat()
            last_heartbeat = time.monotonic()

    try:
        findings, metadata = run_scanner(config, target, work, stop, heartbeat, lease_fd)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        log.error("scan_failed target=%s run=%s error=%s", target.id, run_id, error)
        if (work / "engine.json").exists():
            metadata = json.loads((work / "engine.json").read_text())
    finally:
        # Failed/partial raw reports can also contain credentials; do not retain them.
        for name in (
            "raw.json",
            "raw.jsonl",
            "raw.xml",
            "stdout.log",
            "empty.yaml",
            "empty.ignore",
        ):
            (work / name).unlink(missing_ok=True)
    status = "failed" if error else "succeeded"
    summary = {
        "run_id": run_id,
        "target_id": target.id,
        "status": status,
        "finding_count": len(findings),
        "error": error,
        "config_digest": config.digest,
        "metadata": metadata,
    }
    (work / "scan.json").write_text(json.dumps(summary, indent=2))
    (work / "config.json").write_text(json.dumps(config.snapshot(), indent=2))
    metadata["artifact_hashes"] = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in work.iterdir() if p.is_file()
    }
    destination = config.state_dir / "reports" / run_id
    destination.parent.mkdir(mode=0o700, exist_ok=True)
    work.rename(destination)
    store.finish(
        run_id,
        target,
        config,
        findings,
        metadata,
        str(destination.relative_to(config.state_dir)),
        error,
    )
    if not error:
        log.info("scan_finished target=%s run=%s findings=%d", target.id, run_id, len(findings))
    return summary


def run(
    config: Config, store: Store, stop: Event, once: bool = False, target_id: str | None = None
) -> list[dict]:
    targets = {target.id: target for target in config.targets}
    if target_id and target_id not in targets:
        raise ValueError(f"Unknown target: {target_id}")
    with agent_lock(config.state_dir) as lease_fd:
        store.recover(config.state_dir)
        cleanup_work(config)
        store.sync_jobs(config, time.time())
        store.heartbeat()
        try:
            if once:
                results = []
                for target in config.targets:
                    if stop.is_set():
                        break
                    if target_id is None or target.id == target_id:
                        results.append(scan_target(config, target, store, stop, lease_fd))
                # Manual scans do not move the recurring schedule.
                return results
            while not stop.is_set():
                store.heartbeat()
                for tid in store.due(time.time()):
                    if stop.is_set():
                        break
                    scan_target(config, targets[tid], store, stop, lease_fd)
                    if not stop.is_set():
                        # Coalesce missed runs; schedule from completion, with no catch-up burst.
                        store.advance(targets[tid], time.time())
                stop.wait(1)
            return []
        finally:
            store.heartbeat(running=False)
