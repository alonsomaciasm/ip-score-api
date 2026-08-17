from typing import Literal, Optional
from pydantic import BaseModel, Field


class Flags(BaseModel):
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    is_residential: bool = False
    is_mobile: bool = False
    is_abuse_listed: bool = False
    is_icloud_relay: bool = False
    is_botnet_c2: bool = False
    is_bogon: bool = False
    is_cdn_egress: bool = False
    is_tor_relay: bool = False


class NetworkInfo(BaseModel):
    asn: Optional[int] = Field(default=None, description="Autonomous System Number")
    asn_org: str = Field(default="Unknown", description="ASN Organization or ISP name")
    network_type: str = Field(default="unknown", description="Network classification (hosting, residential, mobile, business)")


class LocationInfo(BaseModel):
    country_code: Optional[str] = Field(default=None, description="ISO 3166-1 alpha-2 country code (e.g. MX, US, DE)")
    country_name: str = Field(default="Unknown", description="Country name")


class ScoreResponse(BaseModel):
    ip_version: Literal[4, 6] = Field(..., description="IP protocol version (4 or 6)")
    risk_score: int = Field(..., ge=0, le=100, description="Risk Score from 0 (clean) to 100 (critical risk)")
    risk_level: Literal["low", "medium", "high", "critical"] = Field(..., description="Risk level category")
    recommendation: Literal["allow", "flag", "challenge", "block"] = Field(..., description="Action recommendation")
    flags: Flags
    network: NetworkInfo
    location: LocationInfo
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence index (0.0 to 1.0)")
    signals_used: list[str] = Field(default_factory=list, description="List of positive risk signals evaluated")
    ttl_seconds: int = Field(default=300, description="Cache TTL in seconds")


class BatchItemResponse(BaseModel):
    ip: str = Field(..., description="Evaluated IP address (returned for correlation in batch response)")
    result: ScoreResponse


class BatchScoreResponse(BaseModel):
    total_evaluated: int
    results: list[BatchItemResponse]


class ErrorResponse(BaseModel):
    type: str = "https://errors.ipscore.api/generic-error"
    title: str
    status: int
    detail: str
    request_id: Optional[str] = None
    timestamp: str
