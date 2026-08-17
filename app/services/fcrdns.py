import socket
import asyncio
import time
import threading
from typing import Tuple, Optional
from app.security.logging import logger

VERIFIED_BOT_DOMAINS = [
    ".googlebot.com", ".google.com", ".search.msn.com",
    ".bing.com", ".yandex.com", ".yandex.net", ".baidu.com", ".baidu.jp"
]

_FCRDNS_CACHE: dict[str, tuple[float, bool, Optional[str]]] = {}
_FCRDNS_LOCK = threading.Lock()
_CACHE_TTL = 3600  # 1 hour TTL for DNS lookups


def _sync_fcrdns_check(ip_str: str) -> Tuple[bool, Optional[str]]:
    """Performs Forward-Confirmed Reverse DNS (FCrDNS) check synchronously with socket timeout protection and Lock-Free TTL caching."""
    now = time.time()
    cached = _FCRDNS_CACHE.get(ip_str)
    if cached:
        expire_at, is_valid, hostname = cached
        if now < expire_at:
            return is_valid, hostname
        else:
            _FCRDNS_CACHE.pop(ip_str, None)

    is_valid = False
    hostname = None

    try:
        socket.setdefaulttimeout(0.8)
        # 1. Reverse DNS (PTR lookup)
        host_tuple = socket.gethostbyaddr(ip_str)
        if host_tuple and host_tuple[0]:
            hostname = host_tuple[0]
            hostname_lower = hostname.lower()

            # Check if hostname belongs to known search engines
            is_known_bot_domain = any(hostname_lower.endswith(domain) for domain in VERIFIED_BOT_DOMAINS)

            if is_known_bot_domain:
                # 2. Forward DNS lookup to verify resolved IP matches original IP
                resolved_ip = socket.gethostbyname(hostname)
                if resolved_ip == ip_str:
                    is_valid = True
    except Exception:
        pass

    if len(_FCRDNS_CACHE) > 5000:
        _FCRDNS_CACHE.clear()
    _FCRDNS_CACHE[ip_str] = (now + _CACHE_TTL, is_valid, hostname)

    return is_valid, hostname


async def verify_fcrdns(ip_str: str, timeout_sec: float = 1.0) -> Tuple[bool, Optional[str]]:
    """Asynchronously verifies FCrDNS with timeout protection."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_sync_fcrdns_check, ip_str),
            timeout=timeout_sec
        )
    except asyncio.TimeoutError:
        logger.debug("FCrDNS lookup timed out", ip=ip_str)
        return False, None
    except Exception as exc:
        logger.debug("FCrDNS lookup error", error=str(exc))
        return False, None
