from __future__ import annotations

import os
import re
import subprocess
import tempfile

PACKAGE_SCRIPT = (
    "if command -v dpkg-query >/dev/null 2>&1; then "
    "dpkg-query -W -f='${Package}\\t${Version}\\n'; "
    "elif command -v rpm >/dev/null 2>&1; then "
    "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'; fi"
)
LISTENER_SCRIPT = "ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null"
PROCESS_SCRIPT = "ps -eo comm=,args= 2>/dev/null"

_LISTENER = re.compile(
    r"(?:LISTEN\s+\d+\s+\d+\s+)?(?P<addr>[0-9a-fA-F:.\[\]]+):(?P<port>\d+)\s+.*?"
    r'(?:users:\(\("(?P<proc>[^"]+)"|pid=(?P<pid>\d+))'
)


def _ssh_run(host, secret, username, script, timeout=30):
    handle = tempfile.NamedTemporaryFile("w", delete=False)
    try:
        handle.write(secret if secret.endswith("\n") else secret + "\n")
        handle.close()
        os.chmod(handle.name, 0o600)
        command = [
            "ssh",
            "-i",
            handle.name,
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            f"ConnectTimeout={min(timeout, 10)}",
            f"{username}@{host}" if username else host,
            script,
        ]
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    finally:
        os.unlink(handle.name)
    if result.returncode != 0:
        raise RuntimeError(f"ssh inventory failed: {result.stderr.strip()[:200]}")
    return result.stdout


def parse_packages(text):
    packages = []
    for line in text.splitlines():
        if "\t" not in line:
            continue
        name, _, version = line.partition("\t")
        name, version = name.strip(), version.strip()
        if name and version:
            packages.append({"purl": f"pkg:generic/{name}", "version": version})
    return packages


def parse_listeners(text):
    bindings = []
    for line in text.splitlines():
        match = _LISTENER.search(line)
        if not match:
            continue
        bindings.append(
            {
                "addr": match.group("addr"),
                "port": int(match.group("port")),
                "proto": "tcp",
                "process": match.group("proc") or "",
            }
        )
    return bindings


def collect_ssh(host, secret, username=""):
    packages = parse_packages(_ssh_run(host, secret, username, PACKAGE_SCRIPT))
    listeners = parse_listeners(_ssh_run(host, secret, username, LISTENER_SCRIPT))
    return {"packages": packages, "bindings": listeners}
