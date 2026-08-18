"""Rate limiting and concurrency control.

Two independent limiters guard the gateway:

* a per-account token bucket, so one account's traffic cannot starve another and
  a runaway client cannot burn a mailbox's Gmail quota;
* a global semaphore capping in-flight upstream requests.

The bucket *fails fast* rather than queueing indefinitely. A client that exceeds
its budget gets a structured ``rate_limited`` error with ``retry_after_seconds``,
which is more useful to an agent than an unbounded stall -- and it means a flood
of tool calls cannot pin memory in a queue.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from ..errors import ErrorCode, GatewayError


@dataclass(slots=True)
class _Bucket:
    capacity: float
    refill_per_second: float
    tokens: float
    updated_at: float

    def take(self, amount: float, now: float) -> float | None:
        """Consume ``amount`` tokens; return None on success, else the wait time."""
        elapsed = max(0.0, now - self.updated_at)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.updated_at = now
        if self.tokens >= amount:
            self.tokens -= amount
            return None
        deficit = amount - self.tokens
        return deficit / self.refill_per_second if self.refill_per_second > 0 else float("inf")


class RateLimiter:
    """Per-key token bucket with a shared global concurrency cap."""

    def __init__(
        self,
        *,
        rate_per_minute: int,
        burst: int,
        max_concurrency: int,
    ) -> None:
        if rate_per_minute <= 0 or burst <= 0 or max_concurrency <= 0:
            raise GatewayError(ErrorCode.CONFIG_ERROR, "rate limits must be positive")
        self._refill = rate_per_minute / 60.0
        self._capacity = float(burst)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def acquire(self, key: str, *, cost: float = 1.0) -> None:
        """Charge ``cost`` against ``key``'s bucket or raise ``rate_limited``."""
        now = time.monotonic()
        async with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(
                    capacity=self._capacity,
                    refill_per_second=self._refill,
                    tokens=self._capacity,
                    updated_at=now,
                )
                self._buckets[key] = bucket
            wait = bucket.take(cost, now)

        if wait is not None:
            raise GatewayError(
                ErrorCode.RATE_LIMITED,
                f"rate limit exceeded for '{key}'; retry in {wait:.1f}s",
                details={"key": key},
                retry_after_seconds=wait,
            )

    def concurrency(self) -> asyncio.Semaphore:
        return self._semaphore

    def snapshot(self, key: str) -> dict[str, float]:
        """Current bucket state, for status reporting."""
        bucket = self._buckets.get(key)
        if bucket is None:
            return {"tokens_available": self._capacity, "capacity": self._capacity}
        elapsed = max(0.0, time.monotonic() - bucket.updated_at)
        tokens = min(bucket.capacity, bucket.tokens + elapsed * bucket.refill_per_second)
        return {"tokens_available": round(tokens, 2), "capacity": bucket.capacity}
