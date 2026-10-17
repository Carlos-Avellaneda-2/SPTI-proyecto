"""Capa 5 (Secure): rate limiting por cliente (algoritmo token bucket)."""
from __future__ import annotations

import threading
import time
from typing import Callable


class TokenBucketLimiter:
    def __init__(self, capacity: int = 10, refill_per_second: float = 0.2,
                 clock: Callable[[], float] = time.monotonic):
        self.capacity = capacity
        self.refill = refill_per_second
        self.clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, client_id: str) -> bool:
        now = self.clock()
        with self._lock:
            tokens, last = self._buckets.get(client_id, (float(self.capacity), now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill)
            if tokens >= 1:
                self._buckets[client_id] = (tokens - 1, now)
                return True
            self._buckets[client_id] = (tokens, now)
            return False
