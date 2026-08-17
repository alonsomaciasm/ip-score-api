import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Optional
import redis.asyncio as aioredis
from app.config import settings
from app.security.logging import logger


class SubnetVelocityTracker:
    def __init__(self):
        self._redis: Optional[aioredis.Redis] = None

    async def initialize(self):
        if settings.CACHE_ENABLED:
            try:
                self._redis = aioredis.from_url(
                    settings.REDIS_URL,
                    password=settings.REDIS_PASSWORD or None,
                    encoding="utf-8",
                    decode_responses=True,
                    socket_timeout=1.5
                )
                await self._redis.ping()
                logger.info("Initialized Subnet Velocity Tracker with Redis HyperLogLog")
            except Exception as exc:
                logger.warning("Subnet Velocity Tracker running in fallback mode (Redis unavailable)", error=str(exc))
                self._redis = None

    async def close(self):
        if self._redis:
            await self._redis.close()

    def get_subnet_prefix(self, ip_str: str) -> str:
        """Derives /24 subnet for IPv4 or /48 subnet for IPv6."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.version == 4:
                network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            else:
                network = ipaddress.ip_network(f"{ip_str}/48", strict=False)
            return str(network)
        except Exception:
            return ip_str

    def _hash_subnet(self, subnet_str: str) -> str:
        """Hashes subnet string using daily salt for PII Zero privacy."""
        today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        salted_str = f"{settings.SALT_SECRET}:{today_utc}:{subnet_str}"
        return hashlib.sha256(salted_str.encode("utf-8")).hexdigest()[:16]

    def _hash_ip(self, ip_str: str) -> str:
        today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        salted_str = f"{settings.SALT_SECRET}:{today_utc}:{ip_str}"
        return hashlib.sha256(salted_str.encode("utf-8")).hexdigest()[:16]

    async def check_and_record_velocity(self, ip_str: str, threshold: int = 10) -> tuple[bool, int]:
        """Records IP in subnet HyperLogLog and checks if distinct IPs count in subnet > threshold."""
        if not self._redis:
            return False, 1

        try:
            subnet_prefix = self.get_subnet_prefix(ip_str)
            subnet_hash = self._hash_subnet(subnet_prefix)
            ip_hash = self._hash_ip(ip_str)

            redis_key = f"subnet_vel:{subnet_hash}"

            # Add IP hash to Redis HyperLogLog
            await self._redis.pfadd(redis_key, ip_hash)
            await self._redis.expire(redis_key, 3600)  # 1 hour sliding window TTL

            # Get cardinality count
            cardinality = await self._redis.pfcount(redis_key)
            is_anomaly = cardinality >= threshold

            return is_anomaly, cardinality
        except Exception as exc:
            logger.debug("Subnet velocity check error", error=str(exc))
            return False, 1

    async def record_subnet_threat(self, ip_str: str) -> int:
        """Records a confirmed hostile IP (C2/Phishing) in the subnet threat HyperLogLog."""
        if not self._redis:
            return 1
        try:
            subnet_prefix = self.get_subnet_prefix(ip_str)
            subnet_hash = self._hash_subnet(subnet_prefix)
            ip_hash = self._hash_ip(ip_str)

            redis_key = f"subnet_threat:{subnet_hash}"
            await self._redis.pfadd(redis_key, ip_hash)
            await self._redis.expire(redis_key, 86400)  # 24h window
            return await self._redis.pfcount(redis_key)
        except Exception:
            return 1

    async def is_subnet_cluster_hostile(self, ip_str: str, threshold: int = 3) -> bool:
        """Returns True if the subnet has >= threshold distinct threat IPs in 24h."""
        if not self._redis:
            return False
        try:
            subnet_prefix = self.get_subnet_prefix(ip_str)
            subnet_hash = self._hash_subnet(subnet_prefix)
            redis_key = f"subnet_threat:{subnet_hash}"
            cardinality = await self._redis.pfcount(redis_key)
            return cardinality >= threshold
        except Exception:
            return False


subnet_velocity_tracker = SubnetVelocityTracker()
