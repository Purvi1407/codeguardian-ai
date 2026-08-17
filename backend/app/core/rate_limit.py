"""
Phase 10 (Production Quality, item 85): basic rate limiting for the
expensive endpoints (/scan, /analyze, /validate — each clones a real
repo, and /validate additionally costs a real API call) so a single
client can't accidentally or deliberately hammer this service.

Deliberately a plain in-memory sliding-window counter, not a dependency
like slowapi or a Redis-backed limiter: this project has exactly one
process per deployment right now (see repo_processor.py and
feedback_store.py's own notes on Render's ephemeral filesystem — the
same "one process, no shared external state" reality applies here).
Reaching for a distributed rate limiter before there's more than one
process to coordinate across would be solving a problem this
deployment doesn't have yet.

Known, stated limitation: this resets on every process restart, and
does NOT coordinate across multiple worker processes/instances — a
deployment running with `uvicorn --workers 4` would allow up to 4x the
configured limit, since each worker keeps its own counters. Fine for a
single-instance deployment (this project's current one); would need a
shared store (Redis, etc.) to be correct under horizontal scaling. This
tradeoff is named directly rather than silently assumed away — see
README "Phase 10" design notes.
"""
import os
import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Only the expensive, external-resource-consuming endpoints are limited
# — /health and /stats/* are free, local reads and don't need gating.
RATE_LIMITED_PATHS = {"/scan", "/analyze", "/validate"}


def _requests_per_minute() -> int:
    return int(os.getenv("CODEGUARDIAN_RATE_LIMIT_PER_MINUTE", "10"))


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window limiter keyed on client IP. A client gets at most
    `_requests_per_minute()` requests to any RATE_LIMITED_PATHS endpoint
    within any trailing 60-second window."""

    def __init__(self, app):
        super().__init__(app)
        self._request_times: Dict[str, Deque[float]] = defaultdict(deque)

    def _client_key(self, request: Request) -> str:
        # request.client can be None in some test/proxy setups — fall
        # back to a shared bucket rather than crashing, which just means
        # rate limiting degrades to "shared across all such clients"
        # instead of per-IP in that edge case, not a failure.
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        if request.url.path not in RATE_LIMITED_PATHS:
            return await call_next(request)

        limit = _requests_per_minute()
        key = self._client_key(request)
        now = time.monotonic()
        window = self._request_times[key]

        while window and now - window[0] > 60:
            window.popleft()

        if len(window) >= limit:
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded: max {limit} requests/minute to this endpoint."},
            )

        window.append(now)
        return await call_next(request)
