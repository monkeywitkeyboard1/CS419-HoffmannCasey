"""
Simple in-memory rate limiter.
Tracks login attempts per IP address per minute window.
"""

import time
from collections import defaultdict
from config import Config


class RateLimiter:
    def __init__(self):
        self._buckets = defaultdict(list)  # ip -> [timestamps]
        self._limit = Config.RATE_LIMIT_PER_MINUTE
        self._window = 60  # seconds

    def allow(self, ip: str) -> bool:
        """Return True if the IP is under the rate limit, False if exceeded."""
        now = time.time()
        cutoff = now - self._window

        # Remove old timestamps
        self._buckets[ip] = [t for t in self._buckets[ip] if t > cutoff]

        if len(self._buckets[ip]) >= self._limit:
            return False

        self._buckets[ip].append(now)
        return True
