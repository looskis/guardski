from __future__ import annotations

import time
from dataclasses import replace

import pytest

from guardski.providers import (
    GenerationResult,
    Message,
    ModelCircuitOpen,
    ModelSchemaError,
    ModelTimeout,
    ResilientProvider,
    prompt_sha256,
)

SCHEMA = {
    "type": "object",
    "required": ["narrative"],
    "properties": {"narrative": {"type": "string"}},
    "additionalProperties": True,
}


def request():
    from guardski.providers import GenerationRequest

    return GenerationRequest(
        system="be terse",
        messages=(Message("user", "plan"),),
        schema=SCHEMA,
        max_tokens=64,
    )


class Flaky:
    name = "flaky"

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def generate(self, req):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return GenerationResult(
            content=outcome,
            model_id="flaky",
            prompt_sha256=prompt_sha256(req),
            raw_sha256="x",
            usage={},
            latency_ms=0,
            finish_reason="stop",
        )


def model_with(config, **overrides):
    return replace(config.model, provider="openai", **overrides)


def test_ok_result_passes_schema(config):
    raw = Flaky([{"narrative": "hi"}])
    provider = ResilientProvider(raw, model_with(config), sleep=lambda _: None)
    result = provider.generate(request())
    assert result.content == {"narrative": "hi"}
    assert result.repaired is False


def test_retry_then_success(config):
    raw = Flaky([ModelTimeout(), {"narrative": "ok"}])
    provider = ResilientProvider(raw, model_with(config, max_retries=2), sleep=lambda _: None)
    assert provider.generate(request()).content == {"narrative": "ok"}
    assert raw.calls == 2


def test_repair_turn_fixes_syntax(config):
    raw = Flaky([{"wrong": 1}, {"narrative": "fixed"}])
    provider = ResilientProvider(raw, model_with(config, max_retries=0), sleep=lambda _: None)
    result = provider.generate(request())
    assert result.content == {"narrative": "fixed"}
    assert result.repaired is True


def test_persistent_schema_failure_raises(config):
    raw = Flaky([{"wrong": 1}, {"still": "wrong"}])
    provider = ResilientProvider(raw, model_with(config, max_retries=0), sleep=lambda _: None)
    with pytest.raises(ModelSchemaError):
        provider.generate(request())


def test_circuit_trips_and_is_persisted(config, store):
    model = model_with(config, max_retries=0, circuit_breaker_threshold=2)
    raw = Flaky([ModelTimeout(), ModelTimeout()])
    provider = ResilientProvider(raw, model, store=store, sleep=lambda _: None)
    for _ in range(2):
        with pytest.raises(ModelTimeout):
            provider.generate(request())
    assert store.circuit_state()["state"] == "open"
    with pytest.raises(ModelCircuitOpen):
        provider.generate(request())


def test_circuit_cooldown_resets(config, store):
    model = model_with(
        config, max_retries=0, circuit_breaker_threshold=1, circuit_breaker_cooldown_seconds=10
    )
    raw = Flaky([ModelTimeout()])
    provider = ResilientProvider(raw, model, store=store, sleep=lambda _: None)
    with pytest.raises(ModelTimeout):
        provider.generate(request())
    assert store.circuit_state()["state"] == "open"
    # simulate the cooldown having elapsed
    store.set_circuit("open", 1, time.time() - 100)
    raw.outcomes.append({"narrative": "back"})
    assert provider.generate(request()).content == {"narrative": "back"}
    assert store.circuit_state()["state"] == "closed"
