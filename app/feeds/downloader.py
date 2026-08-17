import hashlib
import httpx
from typing import Tuple, Optional
from app.config import settings
from app.security.logging import logger


def calculate_sha256(data: bytes) -> str:
    """Calculates SHA-256 checksum of raw byte data."""
    return hashlib.sha256(data).hexdigest()


async def fetch_feed_text(url: str, timeout: float = 15.0, expected_sha256: Optional[str] = None) -> Tuple[str, str]:
    """
    Downloads a plain text or raw feed from HTTP/HTTPS and verifies SHA-256 integrity.
    Returns a tuple of (content_text, sha256_checksum).
    """
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            raw_bytes = response.content
            calculated_hash = calculate_sha256(raw_bytes)
            
            if expected_sha256 and calculated_hash != expected_sha256:
                logger.error("Feed SHA-256 checksum mismatch!", url=url, expected=expected_sha256, got=calculated_hash)
                return "", ""
                
            return response.text, calculated_hash
    except Exception as exc:
        logger.warning("Failed to download data feed", url=url, error=str(exc))
        return "", ""


async def fetch_feed_json(url: str, timeout: float = 15.0, expected_sha256: Optional[str] = None) -> Tuple[dict, str]:
    """
    Downloads a JSON feed from HTTP/HTTPS and verifies SHA-256 integrity.
    Returns a tuple of (content_dict, sha256_checksum).
    """
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            raw_bytes = response.content
            calculated_hash = calculate_sha256(raw_bytes)
            
            if expected_sha256 and calculated_hash != expected_sha256:
                logger.error("JSON Feed SHA-256 checksum mismatch!", url=url, expected=expected_sha256, got=calculated_hash)
                return {}, ""
                
            return response.json(), calculated_hash
    except Exception as exc:
        logger.warning("Failed to download JSON feed", url=url, error=str(exc))
        return {}, ""
