from __future__ import annotations

import base64
import hashlib
import http.server
import threading
import time
import urllib.error
import urllib.request
import uuid


class _Canary(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):  # noqa: N802 - http.server API
        _Canary.hits.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"canary")

    def log_message(self, *args):  # noqa: D401 - silence test server
        return


def _start_canary():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Canary)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


class Prover:
    """Built-in safe proof actions (SPEC §6): canary-only SSRF, hashed reads, markers,
    and a single credential check. No real data is stored or exfiltrated."""

    def __init__(self, timeout=10):
        self.timeout = timeout

    def prove(self, action_id, request, secrets=None):
        params = request.parameters
        if action_id == "prove.ssrf_canary":
            return self.ssrf(params)
        if action_id == "prove.auth_bypass_read":
            return self.read(params)
        if action_id == "prove.marker_write":
            return self.marker(params)
        if action_id == "prove.default_credential":
            return self.credential(params, secrets)
        return {"status": "failed", "detail": "unknown_action"}

    def ssrf(self, params):
        url = params.get("url", "")
        param = params.get("param", "url")
        if not url:
            return {"status": "failed", "detail": "missing_url"}
        _Canary.hits = []
        server, port = _start_canary()
        try:
            canary = f"http://127.0.0.1:{port}/canary-{uuid.uuid4().hex}"
            separator = "&" if "?" in url else "?"
            target = f"{url}{separator}{param}={canary}"
            try:
                urllib.request.urlopen(target, timeout=self.timeout)
            except (urllib.error.HTTPError, OSError):
                pass
            time.sleep(0.5)
            hit = bool(_Canary.hits)
        finally:
            server.shutdown()
            server.server_close()
        return {
            "status": "succeeded" if hit else "failed",
            "detail": "ssrf_canary_hit" if hit else "no_canary_hit",
        }

    def read(self, params):
        url = params.get("url", "")
        headers = params.get("headers") or {}
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read()
            return {
                "status": "succeeded",
                "detail": f"read sha256={hashlib.sha256(body).hexdigest()} bytes={len(body)}",
            }
        except urllib.error.HTTPError as exc:
            return {"status": "failed", "detail": f"http_{exc.code}"}
        except OSError as exc:
            return {"status": "failed", "detail": str(exc)[:100]}

    def marker(self, params):
        url = params.get("url", "")
        token = f"guardski-{uuid.uuid4().hex}"
        try:
            create = urllib.request.Request(url, data=token.encode(), method="POST")
            with urllib.request.urlopen(create, timeout=self.timeout) as response:
                created = response.status
            delete = urllib.request.Request(f"{url.rstrip('/')}/{token}", method="DELETE")
            try:
                with urllib.request.urlopen(delete, timeout=self.timeout) as response:
                    removed = response.status
            except urllib.error.HTTPError as exc:
                removed = exc.code
            return {
                "status": "succeeded" if removed < 400 else "failed",
                "detail": f"created={created} cleanup_status={removed}",
            }
        except (urllib.error.HTTPError, OSError) as exc:
            return {"status": "failed", "detail": str(exc)[:100]}

    def credential(self, params, secrets):
        url = params.get("url", "")
        credential_id = params.get("credential_id", "")
        value = (secrets or {}).get(credential_id)
        if not value:
            return {"status": "failed", "detail": "missing_credential"}
        token = base64.b64encode(value.encode()).decode()
        request = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return {
                    "status": "succeeded" if response.status < 400 else "failed",
                    "detail": f"http_{response.status}",
                }
        except urllib.error.HTTPError as exc:
            return {"status": "failed", "detail": f"http_{exc.code}"}
        except OSError as exc:
            return {"status": "failed", "detail": str(exc)[:100]}
