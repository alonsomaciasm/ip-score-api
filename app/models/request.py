import ipaddress
from typing import Union
from pydantic import BaseModel, Field, model_validator
from app.config import settings


class ScoreRequest(BaseModel):
    ip: str = Field(
        ...,
        description="IPv4 or IPv6 address to evaluate for risk score",
        examples=["185.220.101.5", "2001:db8::1"]
    )
    allow_private: bool = Field(
        default=False,
        description="Set to true to allow private/local RFC 1918 IPs for testing purposes"
    )

    @model_validator(mode="after")
    def validate_ip_address(self):
        clean_ip = self.ip.strip()
        try:
            parsed = ipaddress.ip_address(clean_ip)
        except ValueError:
            raise ValueError(f"Invalid IP address format: {clean_ip}")

        allow_priv = settings.ALLOW_PRIVATE_IPS_FOR_TESTING or self.allow_private

        if not allow_priv:
            if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved:
                raise ValueError(f"Private or reserved IP addresses ({clean_ip}) are not permitted for scoring")

        self.ip = str(parsed)
        return self

    @property
    def parsed_ip(self) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
        return ipaddress.ip_address(self.ip)


class BatchScoreRequest(BaseModel):
    ips: list[str] = Field(
        ...,
        min_length=1,
        max_length=settings.BATCH_MAX_SIZE,
        description=f"List of IP addresses to evaluate (max {settings.BATCH_MAX_SIZE} per batch)"
    )
    allow_private: bool = Field(
        default=False,
        description="Set to true to allow private/local RFC 1918 IPs in batch evaluation"
    )

    @model_validator(mode="after")
    def validate_ips_list(self):
        validated = []
        allow_priv = settings.ALLOW_PRIVATE_IPS_FOR_TESTING or self.allow_private
        for raw_ip in self.ips:
            clean_ip = raw_ip.strip()
            try:
                parsed = ipaddress.ip_address(clean_ip)
                if not allow_priv:
                    if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved:
                        continue
                validated.append(str(parsed))
            except ValueError:
                continue
        if not validated:
            raise ValueError("No valid IP addresses were provided in the batch request")
        self.ips = validated
        return self
