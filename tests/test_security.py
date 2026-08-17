import pytest
from app.security.logging import pii_scrubber_processor
from app.services.cache import cache_service


def test_pii_scrubber_redacts_ip():
    event_dict = {
        "event": "User logged in from IP 185.220.101.5 and IPv6 2001:db8::1",
        "user_id": 123,
        "ip": "185.220.101.5",
        "details": {"client_ip": "185.220.101.5", "action": "login"}
    }
    scrubbed = pii_scrubber_processor(None, "info", event_dict.copy())

    assert "185.220.101.5" not in str(scrubbed)
    assert "2001:db8::1" not in str(scrubbed)
    assert "[REDACTED_IP]" in scrubbed["event"]


def test_cache_hashed_key_privacy():
    raw_ip = "198.51.100.42"
    hashed_key = cache_service.get_hashed_key(raw_ip)

    assert raw_ip not in hashed_key
    assert hashed_key.startswith("ip_score:")
    assert len(hashed_key.split(":")[1]) == 64  # SHA-256 hex digest length
