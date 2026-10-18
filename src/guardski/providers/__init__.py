from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from . import _schema

# The model provider is the only component allowed to make a model call (SPEC §4.2).
# Output is an untrusted proposal: it is structurally validated and, at most once,
# repaired on syntax. Semantic/policy errors are never repaired here.


@dataclass(frozen=True)
class Message:
    role: str
    content: str


@dataclass(frozen=True)
class GenerationRequest:
    system: str
    messages: tuple[Message, ...]
    schema: dict
    max_tokens: int
    temperature: float = 0.0
    timeout_seconds: int = 120
    input_token_budget: int = 24000
    structured_output: str = "json_schema"
    grammar: str | None = None
    repair_turns: int = 1


@dataclass(frozen=True)
class GenerationResult:
    content: dict
    model_id: str
    prompt_sha256: str
    raw_sha256: str
    usage: dict
    latency_ms: int
    finish_reason: str
    repaired: bool = False


class ModelError(RuntimeError):
    def __init__(self, message: str, *, error_kind: str = "error") -> None:
        super().__init__(message)
        self.error_kind = error_kind


class ModelTimeout(ModelError):
    def __init__(self, message: str = "model call timed out") -> None:
        super().__init__(message, error_kind="timeout")


class ModelCircuitOpen(ModelError):
    def __init__(self, message: str = "model circuit breaker is open") -> None:
        super().__init__(message, error_kind="circuit_open")


class ModelSchemaError(ModelError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("model output failed schema validation", error_kind="schema_invalid")
        self.errors = errors


class ModelProvider(Protocol):
    name: str

    def generate(self, request: GenerationRequest) -> GenerationResult: ...


def render_prompt(request: GenerationRequest) -> str:
    lines = [request.system, ""]
    for message in request.messages:
        lines.append(f"[{message.role}]")
        lines.append(message.content)
    return "\n".join(lines)


def prompt_sha256(request: GenerationRequest) -> str:
    return hashlib.sha256(render_prompt(request).encode()).hexdigest()


class ResilientProvider:
    """Wraps a raw provider with timeout, retry, a persisted breaker, and one repair turn."""

    BACKOFF = (1, 4, 16)

    def __init__(self, provider: ModelProvider, model, store=None, sleep: Callable | None = None):
        self._provider = provider
        self._model = model
        self._store = store
        self._sleep = sleep or time.sleep
        self.name = provider.name
        self._failures = 0
        self._opened_at: float | None = None

    # -- circuit breaker state (persisted in `runtime` when a store is present) --

    def _load_state(self) -> tuple[str, int, float | None]:
        if self._store is not None:
            row = self._store.circuit_state()
            return row["state"], row["failures"], row["opened_at"]
        return ("open" if self._opened_at else "closed"), self._failures, self._opened_at

    def _save_state(self, state: str, failures: int, opened_at: float | None) -> None:
        self._failures = failures
        self._opened_at = opened_at
        if self._store is not None:
            self._store.set_circuit(state, failures, opened_at)

    def _check_open(self) -> None:
        state, failures, opened_at = self._load_state()
        if state == "open" and opened_at is not None:
            if time.time() - opened_at < self._model.circuit_breaker_cooldown_seconds:
                raise ModelCircuitOpen()
            # cooldown elapsed: half-open, allow one attempt
            self._save_state("half_open", failures, opened_at)

    def _record_success(self) -> None:
        state, _, _ = self._load_state()
        if state != "closed":
            self._save_state("closed", 0, None)
            if self._store is not None:
                self._store.event("model_circuit_reset", {"model_id": self._model.model_id})

    def _record_failure(self, error_kind: str, endpoint_host: str, attempts: int) -> None:
        state, failures, _ = self._load_state()
        failures += 1
        if self._store is not None:
            self._store.event(
                "model_call_failed",
                {
                    "model_id": self._model.model_id,
                    "endpoint_host": endpoint_host,
                    "error_kind": error_kind,
                    "attempt_count": attempts,
                },
            )
        if failures >= self._model.circuit_breaker_threshold:
            self._save_state("open", failures, time.time())
            if self._store is not None:
                self._store.event(
                    "model_circuit_tripped",
                    {"model_id": self._model.model_id, "endpoint_host": endpoint_host},
                )
                self._store.event("model_degraded", {"model_id": self._model.model_id})
        else:
            self._save_state(state if state != "closed" else "closed", failures, None)

    # -- generation ------------------------------------------------------------

    def generate(self, request: GenerationRequest) -> GenerationResult:
        self._check_open()
        result = self._attempt(request)
        errors = _schema.validate(result.content, request.schema)
        if errors and request.repair_turns > 0:
            repaired_request = _with_repair(request, errors)
            result = self._attempt(repaired_request)
            errors = _schema.validate(result.content, request.schema)
            result = _replace(result, repaired=True)
        if errors:
            self._record_failure("schema_invalid", "", 1)
            raise ModelSchemaError(errors)
        self._record_success()
        return result

    def _attempt(self, request: GenerationRequest) -> GenerationResult:
        attempts = 0
        last: Exception | None = None
        while attempts <= self._model.max_retries:
            attempts += 1
            try:
                return self._provider.generate(request)
            except ModelTimeout as exc:
                last = exc
            except ModelError as exc:
                last = exc
            if attempts <= self._model.max_retries:
                self._sleep(self.BACKOFF[min(attempts - 1, len(self.BACKOFF) - 1)])
        assert last is not None
        self._record_failure(getattr(last, "error_kind", "error"), "", attempts)
        raise last


def _replace(result: GenerationResult, **changes) -> GenerationResult:
    data = {
        "content": result.content,
        "model_id": result.model_id,
        "prompt_sha256": result.prompt_sha256,
        "raw_sha256": result.raw_sha256,
        "usage": result.usage,
        "latency_ms": result.latency_ms,
        "finish_reason": result.finish_reason,
        "repaired": result.repaired,
    }
    data.update(changes)
    return GenerationResult(**data)


def _with_repair(request: GenerationRequest, errors: list[str]) -> GenerationRequest:
    note = (
        "Your previous reply was invalid. Fix these fields and reply with JSON only:\n"
        + "\n".join(errors)
    )
    return GenerationRequest(
        system=request.system,
        messages=request.messages + (Message("user", note),),
        schema=request.schema,
        max_tokens=request.max_tokens,
        temperature=request.temperature,
        timeout_seconds=request.timeout_seconds,
        input_token_budget=request.input_token_budget,
        structured_output=request.structured_output,
        grammar=request.grammar,
        repair_turns=0,
    )


def build_provider(config, store=None, sleep: Callable | None = None) -> ResilientProvider:
    if config.model.provider == "stub":
        from .stub import StubProvider

        raw: ModelProvider = StubProvider(model_id=config.model.model_id)
    else:
        from .openai import OpenAIProvider

        raw = OpenAIProvider(config.model)
    return ResilientProvider(raw, config.model, store=store, sleep=sleep)
