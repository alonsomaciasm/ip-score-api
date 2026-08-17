import time
import asyncio
from app.models.request import ScoreRequest
from app.models.response import ScoreResponse, Flags, NetworkInfo, LocationInfo
from app.services.lookup import lookup_service, LookupResult
from app.services.overrides import overrides_store
from app.services.fcrdns import verify_fcrdns
from app.security.subnet_velocity import subnet_velocity_tracker
from app.security.l1_cache import l1_cache
from app.security.audit_stream import audit_stream
from app.feeds.updater import feed_store
from app.config import settings


class ScoringEngine:
    @staticmethod
    async def calculate_score(request: ScoreRequest) -> ScoreResponse:
        start_time = time.time()
        ip_str = request.ip

        # 0. Sub-millisecond L1 RAM LRU Cache check (< 0.3 ms)
        l1_hit = l1_cache.get(ip_str)
        if l1_hit:
            latency_ms = (time.time() - start_time) * 1000.0
            audit_stream.record_evaluation(
                risk_score=l1_hit.risk_score,
                risk_level=l1_hit.risk_level,
                recommendation=l1_hit.recommendation,
                signals_used=l1_hit.signals_used + ["l1_cache_hit"],
                network_type=l1_hit.network.network_type,
                latency_ms=latency_ms
            )
            return l1_hit

        parsed_ip = request.parsed_ip
        ip_version = parsed_ip.version  # 4 or 6

        lookup: LookupResult = lookup_service.lookup(ip_str)
        location = LocationInfo(country_code=lookup.country_code, country_name=lookup.country_name)

        # Check Overrides (Allowlist / Denylist by IP/CIDR/ASN)
        if overrides_store.is_allowlisted(ip_str, lookup.asn):
            resp = ScoreResponse(
                ip_version=ip_version,
                risk_score=0,
                risk_level="low",
                recommendation="allow",
                flags=Flags(
                    is_vpn=False, is_proxy=False, is_tor=False, is_datacenter=False,
                    is_residential=True, is_mobile=False, is_abuse_listed=False, is_icloud_relay=False,
                    is_tor_relay=False
                ),
                network=NetworkInfo(asn=lookup.asn, asn_org=lookup.asn_org or "Allowlisted Corporate Network", network_type="trusted"),
                location=location,
                confidence=1.0,
                signals_used=["custom_allowlist_override"],
                ttl_seconds=settings.CACHE_TTL_SECONDS
            )
            l1_cache.set(ip_str, resp)
            return resp

        if overrides_store.is_denylisted(ip_str, lookup.asn):
            resp = ScoreResponse(
                ip_version=ip_version,
                risk_score=100,
                risk_level="critical",
                recommendation="block",
                flags=Flags(
                    is_vpn=False, is_proxy=True, is_tor=False, is_datacenter=False,
                    is_residential=False, is_mobile=False, is_abuse_listed=True, is_icloud_relay=False,
                    is_botnet_c2=True, is_bogon=False, is_cdn_egress=False, is_tor_relay=False
                ),
                network=NetworkInfo(asn=lookup.asn, asn_org=lookup.asn_org or "Blocked Hostile Network", network_type="blocked"),
                location=location,
                confidence=1.0,
                signals_used=["custom_denylist_override"],
                ttl_seconds=settings.CACHE_TTL_SECONDS
            )
            l1_cache.set(ip_str, resp)
            return resp

        risk_score = 0
        signals_used: list[str] = []

        # 1. Selective FCrDNS check: only perform DNS reverse lookup if IP is in datacenter or unknown network
        # (avoiding 20-1000ms DNS socket delays on residential, mobile or known threat IPs)
        should_check_fcrdns = lookup.is_datacenter or (not lookup.is_residential and not lookup.is_mobile and not lookup.is_tor and not lookup.is_botnet_c2)

        if should_check_fcrdns:
            fcrdns_task = verify_fcrdns(ip_str)
            velocity_task = subnet_velocity_tracker.check_and_record_velocity(ip_str)
            (is_verified_bot, ptr_domain), (is_velocity_anomaly, _) = await asyncio.gather(fcrdns_task, velocity_task)
        else:
            is_verified_bot, ptr_domain = False, None
            is_velocity_anomaly, _ = await subnet_velocity_tracker.check_and_record_velocity(ip_str)

        if is_verified_bot:
            resp = ScoreResponse(
                ip_version=ip_version,
                risk_score=0,
                risk_level="low",
                recommendation="allow",
                flags=Flags(
                    is_vpn=False, is_proxy=False, is_tor=False, is_datacenter=lookup.is_datacenter,
                    is_residential=False, is_mobile=False, is_abuse_listed=False, is_icloud_relay=False,
                    is_tor_relay=False
                ),
                network=NetworkInfo(asn=lookup.asn, asn_org=lookup.asn_org, network_type="search_engine_bot"),
                location=location,
                confidence=1.0,
                signals_used=["verified_search_engine_bot"],
                ttl_seconds=settings.CACHE_TTL_SECONDS
            )
            l1_cache.set(ip_str, resp)
            return resp

        # 2. Evaluate Subnet Velocity Anomaly & Hostile Cluster Risk
        if is_velocity_anomaly:
            risk_score += 30
            signals_used.append("subnet_velocity_anomaly")

        if lookup.is_botnet_c2 or lookup.is_phishing:
            await subnet_velocity_tracker.record_subnet_threat(ip_str)

        is_cluster_hostile = await subnet_velocity_tracker.is_subnet_cluster_hostile(ip_str)
        if is_cluster_hostile:
            risk_score += 25
            signals_used.append("subnet_cluster_hostile")

        # 3. Evaluate Threat Recency Weighting (<6h active feed refresh)
        if (lookup.is_botnet_c2 or lookup.is_phishing) and feed_store.last_updated > 0:
            if (time.time() - feed_store.last_updated) < 21600:  # 6 hours
                risk_score += 20
                signals_used.append("recent_threat_activity")

        # 4. Evaluate Core Threat Rules
        if lookup.is_botnet_c2:
            risk_score += 100
            signals_used.append("botnet_c2_server")

        if lookup.is_phishing:
            risk_score += 95
            signals_used.append("active_phishing_host")

        if lookup.is_bogon:
            risk_score += 95
            signals_used.append("bogon_unassigned_range")

        if lookup.is_tor:
            risk_score += 90
            signals_used.append("tor_exit_list")

        if lookup.is_tor_relay and not lookup.is_tor:
            risk_score += 40
            signals_used.append("tor_relay_node")

        if lookup.is_greensnow:
            risk_score += 75
            signals_used.append("greensnow_threat_list")

        if lookup.is_abuse_listed and not lookup.is_greensnow:
            risk_score += 70
            signals_used.append("abuse_blocklist_listed")

        if lookup.is_proxy:
            risk_score += 75
            signals_used.append("known_proxy_range")

        if lookup.is_cdn_egress:
            risk_score += 10
            signals_used.append("cdn_edge_egress")

        if lookup.is_icloud_relay:
            risk_score += 15
            signals_used.append("icloud_private_relay")
        elif lookup.is_vpn:
            risk_score += 50
            signals_used.append("vpn_range")

        if lookup.is_datacenter and not lookup.is_icloud_relay:
            risk_score += 35
            signals_used.append("datacenter_asn")

        if lookup.is_edu_gov and not (lookup.is_tor or lookup.is_abuse_listed or lookup.is_botnet_c2):
            signals_used.append("trusted_educational_government_network")

        # Cap score between 0 and 100
        final_score = min(100, max(0, risk_score))

        # Determine Risk Level & Recommendation
        if final_score >= 85:
            risk_level = "critical"
            recommendation = "block"
        elif final_score >= 60:
            risk_level = "high"
            recommendation = "challenge"
        elif final_score >= 30:
            risk_level = "medium"
            recommendation = "flag"
        else:
            risk_level = "low"
            recommendation = "allow"

        # Calculate Adaptive Multi-Source Confidence Score (0.0 - 1.0)
        confidence = 0.50
        if lookup.mmdb_matched:
            confidence += 0.15
        if feed_store.last_updated > 0 and (time.time() - feed_store.last_updated) < 86400:
            confidence += 0.15

        # Independent threat correlation boost
        threat_signals = [s for s in signals_used if s not in ["trusted_educational_government_network", "cdn_edge_egress"]]
        if len(threat_signals) >= 2:
            confidence += 0.10
        if len(threat_signals) >= 3:
            confidence += 0.10

        if lookup.is_edu_gov:
            confidence = 1.0

        confidence = round(min(1.0, confidence), 2)

        # Build Flags
        flags = Flags(
            is_vpn=lookup.is_vpn,
            is_proxy=lookup.is_proxy or lookup.is_bogon or is_cluster_hostile,
            is_tor=lookup.is_tor,
            is_datacenter=lookup.is_datacenter,
            is_residential=lookup.is_residential,
            is_mobile=lookup.is_mobile,
            is_abuse_listed=lookup.is_abuse_listed or lookup.is_botnet_c2 or lookup.is_phishing or lookup.is_greensnow,
            is_icloud_relay=lookup.is_icloud_relay,
            is_botnet_c2=lookup.is_botnet_c2,
            is_bogon=lookup.is_bogon,
            is_cdn_egress=lookup.is_cdn_egress,
            is_tor_relay=lookup.is_tor_relay
        )

        # Build Network Info
        network = NetworkInfo(
            asn=lookup.asn,
            asn_org=lookup.asn_org,
            network_type=lookup.network_type
        )

        response = ScoreResponse(
            ip_version=ip_version,
            risk_score=final_score,
            risk_level=risk_level,
            recommendation=recommendation,
            flags=flags,
            network=network,
            location=location,
            confidence=confidence,
            signals_used=signals_used,
            ttl_seconds=settings.CACHE_TTL_SECONDS
        )

        latency_ms = (time.time() - start_time) * 1000.0
        audit_stream.record_evaluation(
            risk_score=final_score,
            risk_level=risk_level,
            recommendation=recommendation,
            signals_used=signals_used,
            network_type=network.network_type,
            latency_ms=latency_ms
        )

        # Store in L1 RAM LRU Cache for sub-millisecond repeated responses
        l1_cache.set(ip_str, response)
        return response
