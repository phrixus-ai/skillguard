"""Rate limiter — IP-based request throttling."""

from __future__ import annotations

import time
from collections import defaultdict


class RateLimiter:
    """Simple in-memory rate limiter."""

    def __init__(self, max_requests: int = 5, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed. Returns True if allowed."""
        now = time.time()
        # Clean old entries
        self._requests[key] = [
            t for t in self._requests[key]
            if now - t < self.window_seconds
        ]
        if len(self._requests[key]) >= self.max_requests:
            return False
        self._requests[key].append(now)
        return True

    def remaining(self, key: str) -> int:
        """How many requests remaining in current window."""
        now = time.time()
        active = [t for t in self._requests[key] if now - t < self.window_seconds]
        return max(0, self.max_requests - len(active))
