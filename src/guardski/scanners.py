from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

from defusedxml import ElementTree

from .config import SEVERITIES, Config, Target


class ScanError(RuntimeError):
    pass


@dataclass(frozen=True)
class Finding:
    rule: str
    category: str
    severity: str
    title: str
    location: str
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    reference: str = ""

    def fingerprint(self, target: Target) -> str:
        # Versions are deliberately excluded so a package upgrade does not reset its SLA.
        identity = [
            target.id,
            target.kind,
            target.value,
            self.rule,
            self.category,
            self.location,
            self.package,
        ]
        return hashlib.sha256(json.dumps(identity).encode()).hexdigest()


def severity(value: str) -> str:
    value = value.upper()
    return value if value in SEVERITIES else "UNKNOWN"


def parse_trivy(data: dict) -> list[Finding]:
    if not isinstance(data, dict) or data.get("SchemaVersion") != 2:
        raise ScanError("Unsupported or missing Trivy report schema")
    if not isinstance(data.get("Results", []), list):
        raise ScanError("Invalid Trivy Results")
    findings = []
    for result in data.get("Results", []):
        location = str(result.get("Target", ""))
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(
                Finding(
                    vuln["VulnerabilityID"],
                    "vulnerability",
                    severity(vuln.get("Severity", "UNKNOWN")),
                    vuln.get("Title") or vuln["VulnerabilityID"],
                    location,
                    vuln.get("PkgName", ""),
                    vuln.get("InstalledVersion", ""),
                    vuln.get("FixedVersion", ""),
                    vuln.get("PrimaryURL", ""),
                )
            )
        for misconfig in result.get("Misconfigurations") or []:
            if misconfig.get("Status") != "FAIL":
                continue
            findings.append(
                Finding(
                    misconfig["ID"],
                    "misconfiguration",
                    severity(misconfig.get("Severity", "UNKNOWN")),
                    misconfig.get("Title", misconfig["ID"]),
                    location,
                    reference=misconfig.get("PrimaryURL", ""),
                )
            )
        for secret in result.get("Secrets") or []:
            # Persist the rule and location, never the matched secret or surrounding source.
            secret.pop("Match", None)
            secret.pop("Code", None)
            findings.append(
                Finding(
                    secret["RuleID"],
                    "secret",
                    severity(secret.get("Severity", "UNKNOWN")),
                    secret.get("Title", secret["RuleID"]),
                    f"{location}:{secret.get('StartLine', 0)}",
                )
            )
    return findings


def parse_nuclei(text: str) -> tuple[list[Finding], list[dict]]:
    findings, reports = [], []
    for line in text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        info = item["info"]
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]
        findings.append(
            Finding(
                item["template-id"],
                "service_check",
                severity(info.get("severity", "UNKNOWN")),
                info.get("name", item["template-id"]),
                item.get("matched-at") or item.get("host", ""),
                reference=references[0] if references else "",
            )
        )
        for field in ("request", "response", "curl-command", "extracted-results"):
            item.pop(field, None)
        reports.append(item)
    return findings, reports


def parse_nmap(text: str) -> tuple[list[Finding], dict]:
    root = ElementTree.fromstring(text)
    finished = root.find("runstats/finished")
    if root.tag != "nmaprun" or finished is None or finished.get("exit") != "success":
        raise ScanError("Nmap did not report successful completion")
    findings = []
    host_inventory = []
    services = []
    for host in root.findall("host"):
        if host.get("timedout") == "true":
            raise ScanError("Nmap timed out on a host; coverage is incomplete")
        address = host.find("address")
        if address is None:
            continue
        addr = address.get("addr")
        status = host.find("status")
        hostname = ""
        for name in host.findall("hostnames/hostname"):
            if name.get("name"):
                hostname = name.get("name")
                break
        os_match = host.find("os/osmatch")
        os_name = os_match.get("name", "") if os_match is not None else ""
        host_inventory.append(
            {
                "addr": addr,
                "hostname": hostname,
                "os": os_name,
                "state": status.get("state", "up") if status is not None else "up",
            }
        )
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            details = dict(service.attrib) if service is not None else {}
            endpoint = f"{addr}:{port.get('portid')}/{port.get('protocol')}"
            services.append(
                {
                    "addr": addr,
                    "port": int(port.get("portid")),
                    "proto": port.get("protocol"),
                    "name": details.get("name", ""),
                    "product": details.get("product", ""),
                    "version": details.get("version", ""),
                }
            )
            findings.append(
                Finding(
                    f"open-{port.get('protocol')}-{port.get('portid')}",
                    "inventory",
                    "INFO",
                    "Open service: "
                    + " ".join(details.get(k, "") for k in ("name", "product", "version")).strip(),
                    endpoint,
                    installed_version=details.get("version", ""),
                )
            )
    hosts = root.find("runstats/hosts")
    return findings, {
        "hosts": dict(hosts.attrib) if hosts is not None else {},
        "host_inventory": host_inventory,
        "services": services,
    }


def filter_host_inventory(hosts, services, discovery):
    """Without a discovery pass, Nmap -Pn reports every address as up; only keep hosts
    with an observed service so dead addresses don't become assets."""
    if discovery:
        return hosts
    open_hosts = {service["addr"] for service in services}
    return [host for host in hosts if host.get("addr") in open_hosts]


def _nmap_discovery(binary, target, work, env, config, stop, heartbeat, lease_fd):
    output = work / "discovery.xml"
    command = [binary, "-sn", "-R", "-oX", str(output)]
    if ipaddress.ip_network(target.value).version == 6:
        command.append("-6")
    command.append(target.value)
    execute(
        command,
        work,
        env,
        min(config.timeout_seconds, 600),
        config.max_output_mb * 1024 * 1024,
        stop,
        heartbeat,
        lease_fd,
    )
    if not output.is_file():
        raise ScanError("Nmap discovery produced no report")
    _, metadata = parse_nmap(output.read_text())
    output.unlink(missing_ok=True)
    return [host for host in metadata.get("host_inventory", []) if host.get("state") == "up"]


def prepare_environment(config: Config) -> dict[str, str]:
    home = config.state_dir / "engine-home"
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = {
        key: value for key, value in os.environ.items() if not key.startswith(("TRIVY_", "NUCLEI_"))
    }
    # Credential inputs are allowed, but never included in command lines or evidence.
    for name in ("TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_TOKEN"):
        if name in os.environ:
            env[name] = os.environ[name]
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / "config"),
        XDG_CACHE_HOME=str(home / "cache"),
        DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD="true",
        DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD="true",
        DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD="true",
        DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD="true",
        DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD="true",
    )
    return env


def database_evidence(config: Config) -> dict:
    database = config.state_dir / "cache" / "db"
    try:
        metadata = json.loads((database / "metadata.json").read_text())
        updated = datetime.fromisoformat(metadata["UpdatedAt"].replace("Z", "+00:00"))
        if updated.tzinfo is None:
            raise ValueError("Database timestamp has no timezone")
        age_hours = (datetime.now(UTC) - updated).total_seconds() / 3600
        if age_hours > config.max_db_age_hours or age_hours < -1:
            raise ScanError(
                "Trivy vulnerability database is stale or has a future timestamp; "
                "refresh the database and check the system clock"
            )
        with (database / "trivy.db").open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
    except (OSError, ValueError, KeyError) as exc:
        raise ScanError(f"Cannot verify vulnerability database provenance: {exc}") from exc
    result = {"metadata": metadata, "sha256": digest, "age_hours": age_hours}
    java_metadata = config.state_dir / "cache" / "java-db" / "metadata.json"
    if java_metadata.is_file():
        result["java_metadata"] = json.loads(java_metadata.read_text())
    return result


def command(config: Config, target: Target, work: Path) -> tuple[list[str], Path]:
    binary = getattr(config, target.engine)
    if target.engine == "trivy":
        output = work / "raw.json"
        subcommand = {"filesystem": "fs", "archive": "image"}.get(target.kind, target.kind)
        cmd = [
            binary,
            subcommand,
            "--config",
            str(work / "empty.yaml"),
            "--cache-dir",
            str(config.state_dir / "cache"),
            "--format",
            "json",
            "--output",
            str(output),
            "--exit-code",
            "0",
            "--no-progress",
            "--disable-telemetry",
            "--skip-version-check",
            "--offline-scan",
            "--skip-check-update",
            "--skip-vex-repo-update",
            "--ignorefile",
            str(work / "empty.ignore"),
            "--timeout",
            f"{config.timeout_seconds}s",
        ]
        if target.kind != "sbom":
            cmd += [
                "--scanners",
                ",".join(target.scanners),
                "--secret-config",
                str(work / "empty.yaml"),
            ]
        if target.kind in {"filesystem", "rootfs"}:
            cmd += ["--skip-dirs", str(config.state_dir)]
        if config.offline:
            cmd += ["--skip-db-update", "--skip-java-db-update"]
        if target.kind == "archive":
            cmd += ["--input", target.value]
        elif target.kind == "image":
            cmd += ["--image-src", "remote", "--", target.value]
        else:
            cmd += ["--", target.value]
    elif target.engine == "nuclei":
        output = work / "raw.jsonl"
        cmd = [
            binary,
            "-u",
            target.value,
            "-config",
            str(work / "empty.yaml"),
            "-jsonl",
            "-output",
            str(output),
            "-no-color",
            "-no-stdin",
            "-disable-update-check",
            "-no-interactsh",
            "-disable-unsigned-templates",
            "-disable-redirects",
            "-omit-raw",
            "-stats-json",
            "-stats-interval",
            "1",
            "-type",
            "http,ssl,tcp,dns",
            "-exclude-tags",
            "dos,fuzz,bruteforce,intrusive",
            "-rate-limit",
            str(config.rate_limit),
            "-concurrency",
            "2",
            "-bulk-size",
            "2",
            "-timeout",
            "10",
            "-retries",
            "1",
        ]
        for template in config.templates:
            cmd += ["-t", template]
    else:
        output = work / "raw.xml"
        cmd = [
            binary,
            "-sT",
            "-sV",
            "--version-light",
            "-Pn",
            "-R",
            "-T3",
            "--max-rate",
            str(config.rate_limit),
            "--max-retries",
            "1",
            "--host-timeout",
            "120s",
            "--open",
        ]
        if target.os_detection:
            cmd += ["-O", "--osscan-limit"]
        if target.udp:
            cmd += ["-sU", "-p", f"T:{target.ports},U:{target.udp_ports}"]
        else:
            cmd += ["-p", target.ports]
        cmd += ["-oX", str(output)]
        if ipaddress.ip_network(target.value).version == 6:
            cmd += ["-6"]
        cmd += [target.value]
    return cmd, output


def terminate(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except ProcessLookupError:
        pass
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def execute(
    cmd: list[str],
    work: Path,
    env: dict[str, str],
    timeout: int,
    max_bytes: int,
    stop: Event,
    heartbeat: Callable[[], None],
    lease_fd: int | None = None,
) -> None:
    deadline = time.monotonic() + timeout
    with (work / "stdout.log").open("wb") as stdout, (work / "stderr.log").open("wb") as stderr:
        process = subprocess.Popen(
            cmd,
            cwd=work,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
            pass_fds=() if lease_fd is None else (lease_fd,),
        )
        try:
            while True:
                heartbeat()
                if stop.is_set():
                    raise ScanError("Scan interrupted by shutdown")
                if time.monotonic() >= deadline:
                    raise ScanError(f"Scanner exceeded {timeout}s timeout")
                if sum(p.stat().st_size for p in work.iterdir() if p.is_file()) > max_bytes:
                    raise ScanError("Scanner output exceeded configured size limit")
                if process.poll() is not None:
                    break
                stop.wait(0.2)
            if process.returncode:
                raise ScanError(
                    f"{Path(cmd[0]).name} exited with code {process.returncode}; see stderr.log"
                )
        finally:
            if process.poll() is None:
                terminate(process)


def run_scanner(
    config: Config,
    target: Target,
    work: Path,
    stop: Event,
    heartbeat: Callable[[], None],
    lease_fd: int | None = None,
) -> tuple[list[Finding], dict]:
    (work / "empty.yaml").write_text("{}\n")
    (work / "empty.ignore").write_text("")
    env = prepare_environment(config)
    binary = shutil.which(getattr(config, target.engine))
    if not binary:
        raise ScanError(f"Required scanner is not installed: {getattr(config, target.engine)}")
    version_flag = "-version" if target.engine == "nuclei" else "--version"
    try:
        version = subprocess.run(
            [binary, version_flag],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
            pass_fds=() if lease_fd is None else (lease_fd,),
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise ScanError(f"Unable to read {target.engine} version: {exc}") from exc
    cmd, output = command(config, target, work)
    cmd[0] = binary
    metadata = {
        "engine": target.engine,
        "engine_version": (version.stdout + version.stderr).strip()[:4000],
        "command": cmd,
        "templates": {},
    }
    if target.engine == "nuclei":
        metadata["templates"] = {
            p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in config.templates
        }
    (work / "engine.json").write_text(json.dumps(metadata, indent=2))
    discovered = []
    if target.engine == "nmap" and target.discovery:
        discovered = _nmap_discovery(binary, target, work, env, config, stop, heartbeat, lease_fd)
        if not discovered:
            metadata["host_inventory"] = []
            metadata["services"] = []
            (work / "report.json").write_text(json.dumps({"inventory": [], "hosts": {}}, indent=2))
            (work / "stdout.log").unlink(missing_ok=True)
            return [], metadata
    execute(
        cmd,
        work,
        env,
        config.timeout_seconds,
        config.max_output_mb * 1024 * 1024,
        stop,
        heartbeat,
        lease_fd,
    )
    if not output.is_file():
        raise ScanError("Scanner completed without writing a report")
    raw = output.read_text()
    if target.engine == "trivy":
        report = json.loads(raw)
        findings = parse_trivy(report)
        if "vuln" in target.scanners:
            metadata["database"] = database_evidence(config)
    elif target.engine == "nuclei":
        findings, report = parse_nuclei(raw)
        stats = []
        for line in (work / "stderr.log").read_text(errors="replace").splitlines():
            try:
                item = json.loads(line)
                if "requests" in item and "templates" in item:
                    stats.append(item)
            except (ValueError, TypeError):
                continue
        if not stats or int(stats[-1]["templates"]) < 1 or int(stats[-1]["requests"]) < 1:
            raise ScanError("Nuclei did not confirm template execution; coverage is unverified")
        metadata["statistics"] = stats[-1]
        if int(stats[-1].get("errors", 0)):
            raise ScanError("Nuclei reported request errors; coverage is incomplete")
    else:
        findings, inventory = parse_nmap(raw)
        metadata.update(inventory)
        metadata["host_inventory"] = filter_host_inventory(
            metadata.get("host_inventory", []), metadata.get("services", []), target.discovery
        )
        if discovered:
            known = {host["addr"] for host in discovered}
            for host in metadata["host_inventory"]:
                if host["addr"] not in known:
                    discovered.append(host)
            metadata["host_inventory"] = discovered
        report = {"inventory": [asdict(f) for f in findings], **inventory}
        report["host_inventory"] = metadata["host_inventory"]
    (work / "report.json").write_text(json.dumps(report, indent=2))
    # stdout can duplicate findings, including secrets. Keep only the sanitized report.
    output.unlink()
    (work / "stdout.log").unlink(missing_ok=True)
    return findings, metadata
