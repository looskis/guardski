from __future__ import annotations

import hashlib
import json

from . import GenerationRequest, GenerationResult, ModelTimeout, prompt_sha256


class StubProvider:
    """Deterministic fixture provider for tests; the default in CI (SPEC §4.2)."""

    name = "stub"

    def __init__(
        self,
        mode: str = "ok",
        payload: dict | None = None,
        responses: list | None = None,
        model_id: str = "stub",
        latency_ms: int = 1,
    ) -> None:
        self.mode = mode
        self.payload = (
            payload
            if payload is not None
            else {
                "narrative": "stub plan",
                "citations": [],
                "steps": [],
                "hypotheses": [],
                "assumptions": [],
            }
        )
        self.responses = list(responses) if responses is not None else None
        self.model_id = model_id
        self.latency_ms = latency_ms

    def generate(self, request: GenerationRequest) -> GenerationResult:
        if self.mode == "timeout":
            raise ModelTimeout()
        if self.responses is not None:
            content = self.responses.pop(0)
        elif self.mode == "invalid":
            content = {"__bad__": True}
        elif self.mode == "garbage":
            content = {"not": "a plan"}
        else:
            content = self.payload
        if not isinstance(content, dict):
            content = {"value": content}
        return GenerationResult(
            content=content,
            model_id=self.model_id,
            prompt_sha256=prompt_sha256(request),
            raw_sha256=hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest(),
            usage={"prompt_tokens": 0, "completion_tokens": 0},
            latency_ms=self.latency_ms,
            finish_reason="stop",
        )
