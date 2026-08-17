import hashlib
import json
from typing import Optional
from redis.asyncio import Redis, from_url
from app.config import settings
from app.models.response import ScoreResponse
from app.security.logging import logger


class CacheService:
    def __init__(self):
        self._redis: Optional[Redis] = None

    async def connect(self):
        if not settings.CACHE_ENABLED:
            return
        try:
            self._redis = from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=2.0)
            await self._redis.ping()
            logger.info("Connected to Redis cache successfully")
        except Exception as exc:
            logger.warning("Redis connection failed. Running without external cache.", error=str(exc))
            self._redis = None

    async def close(self):
        if self._redis:
            await self._redis.close()

    def get_hashed_key(self, ip: str) -> str:
        """Generates a salt-rotated SHA-256 hashed cache key for PII Zero compliance with daily rotation."""
        import time
        date_str = time.strftime("%Y-%m-%d", time.gmtime())
        raw_key = f"{settings.SALT_SECRET}:{date_str}:{ip}"
        hashed = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        return f"ip_score:{hashed}"

    async def get_score(self, ip: str) -> Optional[ScoreResponse]:
        if not self._redis or not settings.CACHE_ENABLED:
            return None

        key = self.get_hashed_key(ip)
        try:
            cached_data = await self._redis.get(key)
            if cached_data:
                parsed_json = json.loads(cached_data)
                return ScoreResponse.model_validate(parsed_json)
        except Exception as exc:
            logger.warning("Cache fetch error", error=str(exc))
        return None

    async def set_score(self, ip: str, score_response: ScoreResponse, ttl: int = settings.CACHE_TTL_SECONDS):
        if not self._redis or not settings.CACHE_ENABLED:
            return

        key = self.get_hashed_key(ip)
        try:
            json_data = score_response.model_dump_json()
            await self._redis.set(key, json_data, ex=ttl)
        except Exception as exc:
            logger.warning("Cache write error", error=str(exc))

    async def get_scores_batch(self, ips: list[str]) -> dict[str, Optional[ScoreResponse]]:
        """Batch fetch scores using Redis Pipeline in a single RTT."""
        if not self._redis or not settings.CACHE_ENABLED or not ips:
            return {ip: None for ip in ips}

        keys = [self.get_hashed_key(ip) for ip in ips]
        res_map = {}
        try:
            pipe = self._redis.pipeline()
            for k in keys:
                pipe.get(k)
            raw_results = await pipe.execute()

            for ip, cached_data in zip(ips, raw_results):
                if cached_data:
                    parsed_json = json.loads(cached_data)
                    res_map[ip] = ScoreResponse.model_validate(parsed_json)
                else:
                    res_map[ip] = None
            return res_map
        except Exception as exc:
            logger.warning("Batch cache fetch error", error=str(exc))
            return {ip: None for ip in ips}

    async def set_scores_batch(self, items: list[tuple[str, ScoreResponse]], ttl: int = settings.CACHE_TTL_SECONDS):
        """Batch write scores using Redis Pipeline in a single RTT."""
        if not self._redis or not settings.CACHE_ENABLED or not items:
            return

        try:
            pipe = self._redis.pipeline()
            for ip, score_response in items:
                key = self.get_hashed_key(ip)
                json_data = score_response.model_dump_json()
                pipe.set(key, json_data, ex=ttl)
            await pipe.execute()
        except Exception as exc:
            logger.warning("Batch cache write error", error=str(exc))


cache_service = CacheService()
