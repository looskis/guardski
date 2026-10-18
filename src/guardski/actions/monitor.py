from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Signal:
    latency_ms: float | None = None
    error: bool = False
    response_bytes: int = 0
    reachable: bool | None = None
    memory_mb: float | None = None
    cpu_percent: float | None = None


class ExecutionMonitor:
    """Watches one action for target distress and can trigger the kill switch (SPEC §5.4)."""

    def __init__(self, monitor_config, agent_config) -> None:
        self.cfg = monitor_config
        self.agent = agent_config
        self.latencies: list[float] = []
        self.error_window: list[bool] = []
        self.probes = 0
        self.peak_latency_streak = 0
        self.was_reachable = True
        self._abort = False
        self._reason: str | None = None

    def baseline_latency(self) -> float | None:
        sample = self.latencies[: self.cfg.baseline_probes]
        return sum(sample) / len(sample) if sample else None

    def _abort_with(self, reason: str) -> None:
        self._abort = True
        self._reason = reason

    def observe(self, signal: Signal) -> None:
        self.probes += 1
        if signal.latency_ms is not None:
            self.latencies.append(signal.latency_ms)
        self.error_window.append(signal.error)
        if self.probes > self.cfg.baseline_probes:
            baseline = self.baseline_latency()
            if (
                signal.latency_ms is not None
                and baseline
                and signal.latency_ms > self.cfg.anomaly_latency_multiplier * baseline
            ):
                self.peak_latency_streak += 1
            else:
                self.peak_latency_streak = 0
            if self.peak_latency_streak >= 3:
                self._abort_with("latency")
            recent = self.error_window[-self.cfg.baseline_probes :]
            if recent and sum(recent) / len(recent) > self.cfg.anomaly_error_rate:
                self._abort_with("error_rate")
        if signal.reachable is False and self.was_reachable:
            self._abort_with("unavailable")
        if signal.reachable is True:
            self.was_reachable = True
        if signal.response_bytes > self.cfg.anomaly_max_response_bytes:
            self._abort_with("response_size")
        if signal.memory_mb is not None and signal.memory_mb > self.agent.max_memory_mb:
            self._abort_with("memory")
        if signal.cpu_percent is not None and signal.cpu_percent > self.agent.max_cpu_percent:
            self._abort_with("cpu")

    def should_abort(self) -> bool:
        return self._abort

    def abort_reason(self) -> str | None:
        return self._reason
