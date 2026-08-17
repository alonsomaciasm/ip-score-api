import hashlib
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request
from app.config import settings


def key_func(request: Request) -> str:
    """
    Derives rate limit key from X-API-Key or fallback hashed remote IP.
    Ensures no raw IP is stored in rate limiting keys.
    """
    api_key = request.headers.get("X-API-Key")
    if api_key:
        hashed_key = hashlib.sha256(f"{settings.SALT_SECRET}:{api_key}".encode()).hexdigest()[:16]
        return f"rate:{hashed_key}"
    
    remote_ip = get_remote_address(request) or "127.0.0.1"
    hashed_ip = hashlib.sha256(f"{settings.SALT_SECRET}:{remote_ip}".encode()).hexdigest()[:16]
    return f"rate_ip:{hashed_ip}"


def get_limiter_storage_uri() -> str:
    """Detects if Redis is reachable for distributed rate limiting, falling back to memory storage."""
    if not settings.CACHE_ENABLED:
        return "memory://"
    try:
        from redis import Redis
        r = Redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.5)
        r.ping()
        r.close()
        return settings.REDIS_URL
    except Exception:
        return "memory://"


# Distributed Rate Limiting using Redis backend (with graceful in-memory fallback)
limiter = Limiter(
    key_func=key_func,
    storage_uri=get_limiter_storage_uri(),
    default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"]
)
