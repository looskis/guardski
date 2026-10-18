from __future__ import annotations

import base64
import hashlib
import socket
import ssl
import time
import urllib.request
from email.utils import parsedate_to_datetime

from . import ActionRequest, ActionResult


class Transport:
    def reachability(self, addr: str, port: int) -> dict:
        start = time.monotonic()
        try:
            with socket.create_connection((addr, port), timeout=5):
                return {"tcp_connect": True, "latency_ms": (time.monotonic() - start) * 1000}
        except OSError:
            return {"tcp_connect": False, "latency_ms": (time.monotonic() - start) * 1000}

    def banner(self, addr: str, port: int) -> dict:
        try:
            with socket.create_connection((addr, port), timeout=5) as sock:
                sock.settimeout(3)
                raw = sock.recv(512)
            return {"raw": raw.decode("utf-8", "replace"), "bytes": len(raw)}
        except OSError:
            return {"raw": "", "bytes": 0}

    def http_status(self, url: str, path: str) -> dict:
        target = url.rstrip("/") + (path or "/")
        try:
            with urllib.request.urlopen(target, timeout=10) as response:
                return {"status": response.status, "server": response.headers.get("Server", "")}
        except urllib.error.HTTPError as exc:
            return {"status": exc.code, "server": ""}
        except OSError:
            return {"status": None, "server": ""}

    def tls_inspect(self, host: str, port: int) -> dict:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
                    cert = tls.getpeercert()
        except (OSError, ssl.SSLError):
            return {}
        return {
            "subject": str(cert.get("subject", "")),
            "issuer": str(cert.get("issuer", "")),
            "not_before": _epoch(cert.get("notBefore")),
            "not_after": _epoch(cert.get("notAfter")),
            "sha256": hashlib.sha256(der or b"").hexdigest(),
        }

    def auth_check(self, url: str, credential: dict) -> dict:
        if not credential:
            return {"authenticated": False, "role_hint": "", "status": None}
        user = credential.get("username", "")
        token = f"{user}:{credential.get('value', '')}".encode()
        header = "Basic " + base64.b64encode(token).decode()
        request = urllib.request.Request(url, headers={"Authorization": header})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return {
                    "authenticated": response.status < 400,
                    "role_hint": credential.get("role", ""),
                    "status": response.status,
                }
        except urllib.error.HTTPError as exc:
            return {"authenticated": False, "role_hint": "", "status": exc.code}
        except OSError:
            return {"authenticated": False, "role_hint": "", "status": None}

    def package_inventory(self, host: str, method: str, credential: dict) -> dict:
        if method == "ssh":
            from .. import inventory

            return inventory.collect_ssh(
                host, credential.get("value", ""), credential.get("username", "")
            )
        raise NotImplementedError("winrm requires an operator-supplied transport")


def _epoch(stamp: str | None) -> float | None:
    if not stamp:
        return None
    try:
        return parsedate_to_datetime(stamp).timestamp()
    except (TypeError, ValueError):
        return None


def _credential(request, secrets):
    if secrets:
        for credential_id in request.credential_ids:
            value = secrets.get(credential_id)
            if value:
                return {
                    "username": request.parameters.get("username", ""),
                    "value": value,
                    "role": request.parameters.get("role", ""),
                }
    return request.parameters.get("credential") or {}


def run_reachability(transport: Transport, request: ActionRequest, secrets=None) -> ActionResult:
    addr = str(request.parameters.get("addr") or (request.targets[0] if request.targets else ""))
    port = int(request.parameters.get("port", 0))
    result = transport.reachability(addr, port)
    return ActionResult(
        status="succeeded",
        detail="reachable" if result.get("tcp_connect") else "unreachable",
        facts=(("reachability", addr, port, result),),
    )


def run_banner(transport: Transport, request: ActionRequest, secrets=None) -> ActionResult:
    addr = str(request.parameters.get("addr") or (request.targets[0] if request.targets else ""))
    port = int(request.parameters.get("port", 0))
    result = transport.banner(addr, port)
    return ActionResult("succeeded", "banner", facts=(("service_banner", addr, port, result),))


def run_http_status(transport: Transport, request: ActionRequest, secrets=None) -> ActionResult:
    url = str(request.parameters.get("url") or (request.targets[0] if request.targets else ""))
    path = str(request.parameters.get("path", "/"))
    result = transport.http_status(url, path)
    return ActionResult("succeeded", "http", facts=(("http_metadata", url, path, result),))


def run_tls_inspect(transport: Transport, request: ActionRequest, secrets=None) -> ActionResult:
    host = str(request.parameters.get("host") or (request.targets[0] if request.targets else ""))
    port = int(request.parameters.get("port", 443))
    result = transport.tls_inspect(host, port)
    return ActionResult(
        "succeeded" if result else "failed",
        "tls" if result else "no_certificate",
        facts=(("tls_certificate", host, port, result),) if result else (),
    )


def run_auth_check(transport: Transport, request: ActionRequest, secrets=None) -> ActionResult:
    url = str(request.parameters.get("url") or (request.targets[0] if request.targets else ""))
    credential = _credential(request, secrets)
    result = transport.auth_check(url, credential)
    return ActionResult(
        "succeeded",
        "authenticated" if result.get("authenticated") else "unauthenticated",
        facts=(("auth_result", url, 0, result),),
    )


def run_package_inventory(
    transport: Transport, request: ActionRequest, secrets=None
) -> ActionResult:
    asset_id = request.asset_ids[0] if request.asset_ids else ""
    host = str(
        request.parameters.get("addr") or (request.targets[0] if request.targets else asset_id)
    )
    method = str(request.parameters.get("method", "ssh"))
    if method not in ("ssh", "winrm"):
        return ActionResult("failed", "unknown_method")
    credential = _credential(request, secrets)
    result = transport.package_inventory(host, method, credential)
    facts = ()
    for package in result.get("packages", []):
        facts += (("sbom_component", asset_id, 0, package),)
    for binding in result.get("bindings", []):
        subject = f"{binding.get('addr')}:{binding.get('port')}/{binding.get('proto', 'tcp')}"
        value = dict(binding, subject=subject)
        facts += (("service_binding", binding.get("addr", ""), binding.get("port", 0), value),)
    return ActionResult("succeeded", "inventory", facts=facts)
