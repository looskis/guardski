from __future__ import annotations

import threading
import time


class ConcurrencyLimiter:
    """Bounds in-flight actions by a semaphore and starts by a token bucket (SPEC §5.3)."""

    def __init__(
        self, max_concurrency: int, max_per_minute: int, sleep=time.sleep, monotonic=time.monotonic
    ) -> None:
        self.semaphore = threading.Semaphore(max(max_concurrency, 1))
        self.capacity = max(max_per_minute, 1)
        self.tokens = float(self.capacity)
        self.refill_rate = self.capacity / 60.0
        self._sleep = sleep
        self._monotonic = monotonic
        self._last = monotonic()
        self._lock = threading.Lock()
        self._peak = 0
        self._in_flight = 0

    def _refill(self) -> None:
        now = self._monotonic()
        elapsed = now - self._last
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self._last = now

    def acquire(self) -> None:
        self.semaphore.acquire()
        while True:
            with self._lock:
                self._refill()
                if self.tokens >= 1:
                    self.tokens -= 1
                    break
            self._sleep(0.05)
        with self._lock:
            self._in_flight += 1
            self._peak = max(self._peak, self._in_flight)

    def release(self) -> None:
        with self._lock:
            self._in_flight -= 1
        self.semaphore.release()

    @property
    def peak(self) -> int:
        return self._peak
