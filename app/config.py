import json
from typing import Any
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Server settings
    PROJECT_NAME: str = "IP Reputation Score API"
    VERSION: str = "1.1.0"
    DEBUG: bool = False
    ENVIRONMENT: str = Field(default="production", description="Environment mode (development, staging, production)")
    API_PREFIX: str = "/api/v1"
    ALLOWED_ORIGINS: list[str] = Field(
        default=["*"],
        description="Allowed CORS origins list (specify exact origins in production)"
    )

    # Security & PII Zero
    SALT_SECRET: str = Field(
        default="change-me-in-production-super-secret-salt-key-32-chars!",
        description="Salt secret used for obfuscating IP addresses before caching"
    )
    JWT_SECRET: str = Field(
        default="change-me-in-production-jwt-secret-key-32-bytes-minimum!",
        description="Secret key or public key for verifying Bearer JWT tokens"
    )
    JWT_ALGORITHM: str = Field(
        default="HS256",
        description="JWT signing algorithm (HS256, RS256, EdDSA)"
    )
    
    # API Keys mapping (JSON string in .env or raw dict)
    API_KEYS: dict[str, list[str]] = Field(
        default={
            "sk_test_1234567890abcdef": ["score:read", "metrics:read"],
            "sk_admin_9876543210fedcba": ["score:read", "metrics:read", "admin:feeds"]
        },
        description="Mapping of API key to granted scopes"
    )

    @field_validator("API_KEYS", mode="before")
    @classmethod
    def parse_api_keys(cls, v: Any) -> dict[str, list[str]]:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                raise ValueError("API_KEYS env variable must be a valid JSON string mapping key -> scope list")
        return v

    ALLOW_PRIVATE_IPS_FOR_TESTING: bool = Field(
        default=False,
        description="Allow loopback/RFC1918 IPs (only for local dev/testing)"
    )

    # Cache Settings
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    REDIS_PASSWORD: str = Field(default="", description="Redis password if authentication is enabled")
    CACHE_TTL_SECONDS: int = Field(default=300, description="Default cache TTL (5 minutes)")
    CACHE_ENABLED: bool = Field(default=True)

    # Performance Tuning & Algorithmic Strategy
    MATCHING_STRATEGY: str = Field(
        default="v5_hybrid",
        description="Matching strategy: 'v5_hybrid', 'v5_pure', 'v4_bytecode', 'v3_standard'"
    )

    # L1 RAM Cache Settings
    L1_CACHE_MAX_SIZE: int = Field(default=10000, description="Maximum items in L1 RAM LRU cache")
    L1_CACHE_TTL_SECONDS: int = Field(default=300, description="L1 RAM cache TTL in seconds")
    FCRDNS_TIMEOUT_SECONDS: float = Field(default=1.0, description="Socket timeout for FCrDNS reverse DNS lookups")

    # Data Feeds & MaxMind Paths
    DATA_DIR: str = Field(default="./data")
    FEEDS_DIR: str = Field(default="./data/feeds")
    MAXMIND_ASN_DB_PATH: str = Field(default="./data/mmdb/GeoLite2-ASN.mmdb")
    MAXMIND_COUNTRY_DB_PATH: str = Field(default="./data/mmdb/GeoLite2-Country.mmdb")
    
    # Feeds Update Interval (in hours)
    FEED_UPDATE_INTERVAL_HOURS: int = Field(default=12)
    
    # Rate Limiting & Security Limits
    RATE_LIMIT_PER_MINUTE: int = Field(default=100, description="Requests per minute per API key")
    BATCH_MAX_SIZE: int = Field(default=50, description="Maximum IPs per batch scoring request")
    MAX_REQUEST_BODY_SIZE: int = Field(
        default=1_048_576,
        description="Maximum allowed request payload size in bytes (default 1 MB / 1,048,576 bytes)"
    )

    # Threat Intelligence Feeds URLs
    TOR_EXIT_NODES_URL: str = Field(default="https://check.torproject.org/torbulkexitlist")
    SPAMHAUS_DROP_URL: str = Field(default="https://www.spamhaus.org/drop/drop.txt")
    FIREHOL_L1_URL: str = Field(default="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset")
    AWS_IP_RANGES_URL: str = Field(default="https://ip-ranges.amazonaws.com/ip-ranges.json")
    GCP_IP_RANGES_URL: str = Field(default="https://www.gstatic.com/ipranges/cloud.json")
    APPLE_PRIVATE_RELAY_URL: str = Field(default="https://mask-api.icloud.com/egress-ip-ranges.csv")
    TEAM_CYMRU_BOGONS_URL: str = Field(default="https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt")
    CLOUDFLARE_IPS_V4_URL: str = Field(default="https://www.cloudflare.com/ips-v4")
    CLOUDFLARE_IPS_V6_URL: str = Field(default="https://www.cloudflare.com/ips-v6")
    FASTLY_IPS_URL: str = Field(default="https://api.fastly.com/public-ip-list")
    ABUSE_CH_C2_URL: str = Field(default="https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
    THREATFOX_C2_URL: str = Field(default="https://urlhaus.abuse.ch/downloads/hostfile/")
    OPENPHISH_URL: str = Field(default="https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt")
    PHISHING_IPSUM_URL: str = Field(default="https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt")
    OCI_IP_RANGES_URL: str = Field(default="https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json")
    DIGITALOCEAN_IP_RANGES_URL: str = Field(default="https://www.digitalocean.com/geo/google.csv")
    FIREHOL_DATACENTER_URL: str = Field(default="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/datacenter.netset")
    ALIBABA_IP_RANGES_URL: str = Field(default="https://raw.githubusercontent.com/ipverse/iptoasn-webservice/master/alibaba.netset")
    TENCENT_IP_RANGES_URL: str = Field(default="https://raw.githubusercontent.com/ipverse/iptoasn-webservice/master/tencent.netset")
    VULTR_IP_RANGES_URL: str = Field(default="https://raw.githubusercontent.com/ipverse/iptoasn-webservice/master/vultr.netset")
    TOR_RELAYS_URL: str = Field(default="https://check.torproject.org/exit-addresses")
    GREENSNOW_URL: str = Field(default="https://blocklist.greensnow.co/greensnow.txt")
    GEOLITE2_COUNTRY_URL: str = Field(default="https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb")
    GEOLITE2_ASN_URL: str = Field(default="https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb")


settings = Settings()
