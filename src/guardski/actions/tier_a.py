from __future__ import annotations

import socket
import time
import urllib.request

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


def run_reachability(transport: Transport, request: ActionRequest) -> ActionResult:
    addr = str(request.parameters.get("addr") or (request.targets[0] if request.targets else ""))
    port = int(request.parameters.get("port", 0))
    result = transport.reachability(addr, port)
    return ActionResult(
        status="succeeded",
        detail="reachable" if result.get("tcp_connect") else "unreachable",
        facts=(("reachability", addr, port, result),),
    )


def run_banner(transport: Transport, request: ActionRequest) -> ActionResult:
    addr = str(request.parameters.get("addr") or (request.targets[0] if request.targets else ""))
    port = int(request.parameters.get("port", 0))
    result = transport.banner(addr, port)
    return ActionResult("succeeded", "banner", facts=(("service_banner", addr, port, result),))


def run_http_status(transport: Transport, request: ActionRequest) -> ActionResult:
    url = str(request.parameters.get("url") or (request.targets[0] if request.targets else ""))
    path = str(request.parameters.get("path", "/"))
    result = transport.http_status(url, path)
    return ActionResult("succeeded", "http", facts=(("http_metadata", url, path, result),))
