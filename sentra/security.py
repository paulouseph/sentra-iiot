"""
security.py
-----------
Chapter 6 of the report flags that v1 left every route open: anyone who could
reach port 8000 could fire attack simulations or wipe the alert log. That is
fixed here with two small controls.

  * A shared API key on every state-changing route. Reads stay open so the
    dashboard works without a login flow, which keeps the demo usable, but
    nobody can inject traffic or delete evidence without the key.

  * A token-bucket rate limit on simulation, so the drill harness cannot be
    turned into the denial-of-service tool it simulates.

This is deliberately not a full OAuth2/JWT implementation. For a single-site
prototype a shared key that is actually enforced is worth more than an
elaborate scheme that is half-finished; the report's future-work section is
where RBAC belongs.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request, status

from .config import get_settings


async def require_api_key(x_api_key: str | None = Header(default=None)) -> str:
    """Dependency for mutating routes. Set SENTRA_API_KEY="" to disable."""
    expected = get_settings().api_key
    if not expected:
        return "anonymous"
    if x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "This action changes system state and needs an API key. "
                "Send it as the X-API-Key header."
            ),
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return "operator"


class RateLimiter:
    """Sliding-window limiter, keyed by client address."""

    def __init__(self, max_calls: int, per_seconds: float):
        self.max_calls = max_calls
        self.per_seconds = per_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        window = self._hits[key]
        while window and now - window[0] > self.per_seconds:
            window.popleft()
        if len(window) >= self.max_calls:
            retry = round(self.per_seconds - (now - window[0]), 1)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many simulations. Try again in {retry}s.",
                headers={"Retry-After": str(int(retry) + 1)},
            )
        window.append(now)


simulation_limiter = RateLimiter(max_calls=20, per_seconds=60)


async def limit_simulations(request: Request) -> None:
    simulation_limiter.check(request.client.host if request.client else "unknown")
