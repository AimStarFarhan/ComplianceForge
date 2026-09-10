"""Security middleware: rate limiting, security headers, upload hardening.

Demo-scoped but production-shaped:
  - RateLimiter: per-IP sliding-window limiter (in-memory; swap for Redis
    when running multi-worker).
  - SecurityHeadersMiddleware: HSTS, nosniff, frame deny, referrer policy,
    CSP allowing the Vite dev origin.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class RateLimiter:
    """Sliding-window per-IP limiter. /login is tighter than the rest."""

    def __init__(
        self,
        default_limit: int = 120,
        default_window: int = 60,
        login_limit: int = 10,
        login_window: int = 60,
    ):
        self.default_limit = default_limit
        self.default_window = default_window
        self.login_limit = login_limit
        self.login_window = login_window
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def _check(self, key: tuple[str, str], limit: int, window: int) -> tuple[bool, float]:
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= limit:
            retry_after = window - (now - bucket[0])
            return False, max(retry_after, 0.1)
        bucket.append(now)
        return True, 0.0

    def check(self, path: str, client_ip: str) -> tuple[bool, float]:
        if path == "/login":
            return self._check(("login", client_ip), self.login_limit, self.login_window)
        return self._check(("api", client_ip), self.default_limit, self.default_window)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Applies rate limiting + security headers to every response."""

    def __init__(self, app, rate_limiter: RateLimiter | None = None):
        super().__init__(app)
        self.limiter = rate_limiter or RateLimiter()

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        allowed, retry_after = self.limiter.check(request.url.path, client_ip)
        if not allowed:
            return JSONResponse(
                {"detail": "Rate limit exceeded — too many requests. Slow down."},
                status_code=429,
                headers={"Retry-After": str(int(retry_after) + 1)},
            )
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        # localhost demo -> no HSTS/CSP upgrade needed; tighten for real domains
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data:; "
            "connect-src 'self' http://localhost:5173 http://127.0.0.1:5173"
        )
        return response


# ------------------------------------------------------------------ uploads
BLOCKED_UPLOAD_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".msi", ".com", ".scr",
    ".pif", ".vbs", ".js", ".jar", ".py", ".php", ".asp", ".aspx", ".jsp",
    ".html", ".htm", ".svg", ".pdf", ".zip", ".rar", ".7z", ".gz", ".iso",
}
ALLOWED_UPLOAD_EXTENSIONS = {".txt", ".cfg", ".conf", ".log", ".net"}

MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # keep in sync with routes_ingest


def upload_is_safe(filename: str, size_bytes: int) -> tuple[bool, str]:
    name = (filename or "").lower()
    ext = "." + name.rsplit(".", 1)[1] if "." in name else ""
    if ext in BLOCKED_UPLOAD_EXTENSIONS:
        return False, f"File type '{ext}' is not allowed. Upload raw CLI config text files only (.txt/.cfg)."
    if ext and ext not in ALLOWED_UPLOAD_EXTENSIONS and ext not in {".yaml", ".yml"}:
        return False, f"File type '{ext}' is not an accepted config format. Use .txt, .cfg, .conf, or .log."
    if size_bytes > MAX_UPLOAD_BYTES:
        return False, "Config file exceeds 2 MB limit."
    return True, ""
