from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request

from . import GenerationRequest, GenerationResult, ModelError, ModelTimeout, prompt_sha256


class OpenAIProvider:
    """One OpenAI-compatible HTTP client; the endpoint URL points anywhere (SPEC §4.2)."""

    name = "openai"

    def __init__(self, model) -> None:
        self.model = model
        self.url = model.endpoint.rstrip("/") + "/chat/completions"

    def generate(self, request: GenerationRequest) -> GenerationResult:
        messages = [{"role": "system", "content": request.system}]
        messages += [{"role": m.role, "content": m.content} for m in request.messages]
        body = {
            "model": self.model.model_id,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.structured_output in ("json_schema", "grammar"):
            body["response_format"] = {"type": "json_object"}
        data = json.dumps(body).encode()
        http_request = urllib.request.Request(
            self.url, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(http_request, timeout=request.timeout_seconds) as response:
                payload = json.loads(response.read().decode())
        except TimeoutError as exc:
            raise ModelTimeout() from exc
        except urllib.error.HTTPError as exc:
            raise ModelError(f"model endpoint returned HTTP {exc.code}", error_kind="http") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ModelError(f"model endpoint unreachable: {exc}", error_kind="network") from exc
        raw = payload["choices"][0]["message"]["content"]
        try:
            content = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise ModelError("model did not return JSON", error_kind="invalid_json") from exc
        if not isinstance(content, dict):
            raise ModelError("model returned non-object JSON", error_kind="invalid_json")
        return GenerationResult(
            content=content,
            model_id=payload.get("model", self.model.model_id),
            prompt_sha256=prompt_sha256(request),
            raw_sha256=hashlib.sha256(raw.encode()).hexdigest(),
            usage=payload.get("usage", {}),
            latency_ms=int(payload.get("latency_ms", 0)),
            finish_reason=payload["choices"][0].get("finish_reason", "stop"),
        )
