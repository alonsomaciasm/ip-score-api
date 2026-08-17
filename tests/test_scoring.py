import pytest
import netaddr
from app.models.request import ScoreRequest
from app.services.scoring import ScoringEngine
from app.feeds.updater import feed_store


@pytest.mark.asyncio
async def test_tor_ip_scoring():
    request = ScoreRequest(ip="185.220.101.5")
    response = await ScoringEngine.calculate_score(request)

    assert response.ip_version == 4
    assert response.risk_score >= 90
    assert response.risk_level == "critical"
    assert response.recommendation == "block"
    assert response.flags.is_tor is True
    assert "tor_exit_list" in response.signals_used


@pytest.mark.asyncio
async def test_botnet_c2_scoring():
    feed_store.botnet_c2_ips = netaddr.IPSet(["198.51.100.22/32"])
    request = ScoreRequest(ip="198.51.100.22")
    response = await ScoringEngine.calculate_score(request)

    assert response.risk_score == 100
    assert response.risk_level == "critical"
    assert response.recommendation == "block"
    assert response.flags.is_botnet_c2 is True
    assert response.flags.is_abuse_listed is True
    assert "botnet_c2_server" in response.signals_used


@pytest.mark.asyncio
async def test_bogon_scoring():
    feed_store.bogon_ips = netaddr.IPSet(["192.0.2.0/24"])
    request = ScoreRequest(ip="192.0.2.5")
    response = await ScoringEngine.calculate_score(request)

    assert response.risk_score >= 95
    assert response.flags.is_bogon is True
    assert response.flags.is_proxy is True
    assert "bogon_unassigned_range" in response.signals_used


@pytest.mark.asyncio
async def test_cdn_egress_scoring():
    feed_store.cdn_ips = netaddr.IPSet(["104.16.0.0/12"])
    request = ScoreRequest(ip="104.16.1.1")
    response = await ScoringEngine.calculate_score(request)

    assert response.risk_score >= 10
    assert response.flags.is_cdn_egress is True
    assert "cdn_edge_egress" in response.signals_used


@pytest.mark.asyncio
async def test_apple_private_relay_scoring():
    feed_store.apple_relay_ips = netaddr.IPSet(["17.248.0.0/16"])
    request = ScoreRequest(ip="17.248.10.5")
    response = await ScoringEngine.calculate_score(request)

    assert response.risk_score == 15
    assert response.risk_level == "low"
    assert response.recommendation == "allow"
    assert response.flags.is_icloud_relay is True
    assert response.flags.is_vpn is True
    assert "icloud_private_relay" in response.signals_used


@pytest.mark.asyncio
async def test_datacenter_ip_scoring():
    request = ScoreRequest(ip="8.8.8.8")
    response = await ScoringEngine.calculate_score(request)

    assert response.risk_score >= 35
    assert response.flags.is_datacenter is True
    assert "datacenter_asn" in response.signals_used


@pytest.mark.asyncio
async def test_abuse_listed_ip_scoring():
    request = ScoreRequest(ip="198.51.100.10")
    response = await ScoringEngine.calculate_score(request)

    assert response.risk_score >= 70
    assert response.flags.is_abuse_listed is True
    assert "abuse_blocklist_listed" in response.signals_used


@pytest.mark.asyncio
async def test_clean_residential_ip_scoring():
    request = ScoreRequest(ip="203.0.113.50")
    response = await ScoringEngine.calculate_score(request)

    assert response.risk_score == 0
    assert response.risk_level == "low"
    assert response.recommendation == "allow"
    assert response.flags.is_tor is False
    assert response.flags.is_datacenter is False
    assert response.flags.is_botnet_c2 is False
    assert response.flags.is_bogon is False


@pytest.mark.asyncio
async def test_l1_ram_cache():
    from app.security.l1_cache import l1_cache
    ip = "198.51.100.99"
    request = ScoreRequest(ip=ip)
    
    # First call - cache miss
    resp1 = await ScoringEngine.calculate_score(request)
    cached_resp = l1_cache.get(ip)
    assert cached_resp is not None
    assert cached_resp.risk_score == resp1.risk_score

    # Second call - cache hit (<0.3ms)
    resp2 = await ScoringEngine.calculate_score(request)
    assert resp2.risk_score == resp1.risk_score


def test_oci_and_digitalocean_parsers():
    from app.feeds.parsers import parse_oci_ip_ranges, parse_digitalocean_ip_ranges

    oci_sample = {"regions": [{"cidrs": [{"cidr": "130.35.0.0/16"}, {"cidr": "140.80.0.0/16"}]}]}
    oci_ipset = parse_oci_ip_ranges(oci_sample)
    assert "130.35.10.5" in oci_ipset

    do_sample = "138.68.0.0/16,US,US-NY,New York,10001\n159.65.0.0/16,US,US-SFO,San Francisco,94101\n"
    do_ipset = parse_digitalocean_ip_ranges(do_sample)
    assert "138.68.50.1" in do_ipset


@pytest.mark.asyncio
async def test_location_country_scoring():
    request = ScoreRequest(ip="8.8.8.8")
    response = await ScoringEngine.calculate_score(request)

    assert hasattr(response, "location")
    assert response.location.country_name is not None
