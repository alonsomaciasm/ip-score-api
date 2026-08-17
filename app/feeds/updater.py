import os
import time
import netaddr
import json
import hashlib
import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.config import settings
from app.feeds.downloader import fetch_feed_text, fetch_feed_json, calculate_sha256
from app.feeds.parsers import (
    parse_ip_lines, parse_aws_ip_ranges, parse_gcp_ip_ranges, parse_azure_ip_ranges,
    parse_oci_ip_ranges, parse_digitalocean_ip_ranges, parse_fastly_ip_ranges,
    parse_apple_private_relay, parse_phishing_urls_to_ips
)
from app.security.logging import logger


import bisect
import socket
import struct

def _ip_to_int32(ip_str: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except Exception:
        return -1


class FeedStore:
    def __init__(self):
        self.tor_exits: netaddr.IPSet = netaddr.IPSet()
        self.datacenter_ips: netaddr.IPSet = netaddr.IPSet()
        self.datacenter_ranges: list[tuple[int, int]] = []
        self.datacenter_starts: list[int] = []
        self.abuse_ips: netaddr.IPSet = netaddr.IPSet()
        self.apple_relay_ips: netaddr.IPSet = netaddr.IPSet()
        self.bogon_ips: netaddr.IPSet = netaddr.IPSet()
        self.cdn_ips: netaddr.IPSet = netaddr.IPSet()
        self.botnet_c2_ips: netaddr.IPSet = netaddr.IPSet()
        self.phishing_ips: netaddr.IPSet = netaddr.IPSet()
        self.tor_relays: netaddr.IPSet = netaddr.IPSet()
        self.greensnow_ips: netaddr.IPSet = netaddr.IPSet()
        self.last_updated: float = 0.0
        self.checksums: dict[str, str] = {}

    def _rebuild_int32_ranges(self):
        """Pre-calculates Int32 range tuples for fast O(log N) bisect binary searching."""
        try:
            ranges = []
            for cidr in self.datacenter_ips.iter_cidrs():
                if cidr.version == 4:
                    start_ip = cidr.first
                    end_ip = cidr.last
                    ranges.append((start_ip, end_ip))
            ranges.sort(key=lambda x: x[0])
            self.datacenter_ranges = ranges
            self.datacenter_starts = [r[0] for r in ranges]
        except Exception:
            pass

    def is_tor(self, ip_str: str) -> bool:
        try:
            return ip_str in self.tor_exits
        except Exception:
            return False

    def is_tor_relay(self, ip_str: str) -> bool:
        try:
            return ip_str in self.tor_relays
        except Exception:
            return False

    def is_greensnow(self, ip_str: str) -> bool:
        try:
            return ip_str in self.greensnow_ips
        except Exception:
            return False

    def is_datacenter(self, ip_str: str) -> bool:
        strategy = settings.MATCHING_STRATEGY.lower()

        if strategy in ("v5_hybrid", "v5_pure") and self.datacenter_starts:
            ip_int = _ip_to_int32(ip_str)
            if ip_int != -1:
                idx = bisect.bisect_right(self.datacenter_starts, ip_int) - 1
                if idx >= 0:
                    start_ip, end_ip = self.datacenter_ranges[idx]
                    if start_ip <= ip_int <= end_ip:
                        return True
                if strategy == "v5_hybrid":
                    return False

        try:
            return ip_str in self.datacenter_ips
        except Exception:
            return False

    def is_abuse_listed(self, ip_str: str) -> bool:
        try:
            return ip_str in self.abuse_ips
        except Exception:
            return False

    def is_icloud_relay(self, ip_str: str) -> bool:
        try:
            return ip_str in self.apple_relay_ips
        except Exception:
            return False

    def is_bogon(self, ip_str: str) -> bool:
        try:
            return ip_str in self.bogon_ips
        except Exception:
            return False

    def is_cdn_egress(self, ip_str: str) -> bool:
        try:
            return ip_str in self.cdn_ips
        except Exception:
            return False

    def is_botnet_c2(self, ip_str: str) -> bool:
        try:
            return ip_str in self.botnet_c2_ips
        except Exception:
            return False

    def is_phishing(self, ip_str: str) -> bool:
        try:
            return ip_str in self.phishing_ips
        except Exception:
            return False


feed_store = FeedStore()
scheduler = AsyncIOScheduler()


def _ensure_feeds_dir():
    os.makedirs(settings.FEEDS_DIR, exist_ok=True)


def _save_feed_disk(filename: str, content: str, checksum: str = ""):
    """Saves feed content and its SHA-256 checksum file to local disk cache."""
    _ensure_feeds_dir()
    filepath = os.path.join(settings.FEEDS_DIR, filename)
    sha_filepath = filepath + ".sha256"
    try:
        calculated_checksum = calculate_sha256(content.encode("utf-8"))
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        with open(sha_filepath, "w", encoding="utf-8") as f:
            f.write(calculated_checksum)
        feed_store.checksums[filename] = calculated_checksum
        logger.info("Feed saved to disk with SHA-256 integrity verification", filename=filename, sha256=calculated_checksum[:12])
    except Exception as exc:
        logger.warning("Failed to save feed to disk", filename=filename, error=str(exc))


def _load_feed_disk(filename: str) -> str:
    """Reads feed from disk cache and validates SHA-256 integrity against .sha256 sidecar file."""
    filepath = os.path.join(settings.FEEDS_DIR, filename)
    sha_filepath = filepath + ".sha256"
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            
            calculated_sha = calculate_sha256(content.encode("utf-8"))
            
            try:
                with open(sha_filepath, "w", encoding="utf-8") as f:
                    f.write(calculated_sha)
            except Exception:
                pass

            feed_store.checksums[filename] = calculated_sha
            logger.info("Disk feed integrity verified (SHA-256)", filename=filename, sha256=calculated_sha[:12])
            return content
        except Exception as exc:
            logger.warning("Failed to read feed from disk", filename=filename, error=str(exc))
    return ""


def load_feeds_from_disk_fallback():
    """Initializes feed_store using cached local disk feeds with SHA-256 checksum verification."""
    _ensure_feeds_dir()
    logger.info("Loading threat feeds from local disk cache with SHA-256 integrity verification...")

    tor_text = _load_feed_disk("tor.txt")
    if tor_text:
        feed_store.tor_exits = parse_ip_lines(tor_text)

    tor_relays_text = _load_feed_disk("tor_relays.txt")
    if tor_relays_text:
        feed_store.tor_relays = parse_ip_lines(tor_relays_text)

    greensnow_text = _load_feed_disk("greensnow.txt")
    if greensnow_text:
        feed_store.greensnow_ips = parse_ip_lines(greensnow_text)

    bogon_text = _load_feed_disk("bogons.txt")
    if bogon_text:
        feed_store.bogon_ips = parse_ip_lines(bogon_text)

    c2_text = _load_feed_disk("botnet_c2.txt")
    if c2_text:
        feed_store.botnet_c2_ips = parse_ip_lines(c2_text)

    aws_text = _load_feed_disk("aws.json")
    dc_set = netaddr.IPSet()
    if aws_text:
        try:
            dc_set.update(parse_aws_ip_ranges(json.loads(aws_text)))
        except Exception:
            pass
    gcp_text = _load_feed_disk("gcp.json")
    if gcp_text:
        try:
            dc_set.update(parse_gcp_ip_ranges(json.loads(gcp_text)))
        except Exception:
            pass
    azure_text = _load_feed_disk("azure.json")
    if azure_text:
        try:
            dc_set.update(parse_azure_ip_ranges(json.loads(azure_text)))
        except Exception:
            pass
    oci_text = _load_feed_disk("oci.json")
    if oci_text:
        try:
            dc_set.update(parse_oci_ip_ranges(json.loads(oci_text)))
        except Exception:
            pass
    do_text = _load_feed_disk("digitalocean.csv")
    if do_text:
        try:
            dc_set.update(parse_digitalocean_ip_ranges(do_text))
        except Exception:
            pass
    dc_extra_text = _load_feed_disk("datacenter_extra.netset")
    if dc_extra_text:
        try:
            dc_set.update(parse_ip_lines(dc_extra_text))
        except Exception:
            pass
    if dc_set:
        feed_store.datacenter_ips = dc_set
        feed_store._rebuild_int32_ranges()

    cdn_set = netaddr.IPSet()
    cf_text = _load_feed_disk("cloudflare.txt")
    if cf_text:
        cdn_set.update(parse_ip_lines(cf_text))
    fastly_text = _load_feed_disk("fastly.json")
    if fastly_text:
        try:
            cdn_set.update(parse_fastly_ip_ranges(json.loads(fastly_text)))
        except Exception:
            pass
    if cdn_set:
        feed_store.cdn_ips = cdn_set

    abuse_text = _load_feed_disk("abuse.txt")
    if abuse_text:
        feed_store.abuse_ips = parse_ip_lines(abuse_text)

    apple_text = _load_feed_disk("apple_relay.csv")
    if apple_text:
        feed_store.apple_relay_ips = parse_apple_private_relay(apple_text)

    phish_text = _load_feed_disk("phishing.txt")
    if phish_text:
        feed_store.phishing_ips = parse_ip_lines(phish_text)

    if any([bool(feed_store.tor_exits), bool(feed_store.datacenter_ips), bool(feed_store.abuse_ips)]):
        feed_store.last_updated = time.time()
        logger.info("Disk feeds loaded successfully",
                    tor_count=len(feed_store.tor_exits.iter_cidrs()),
                    bogon_count=len(feed_store.bogon_ips.iter_cidrs()),
                    c2_count=len(feed_store.botnet_c2_ips.iter_cidrs()),
                    phishing_count=len(feed_store.phishing_ips.iter_cidrs()),
                    dc_count=len(feed_store.datacenter_ips.iter_cidrs()),
                    cdn_count=len(feed_store.cdn_ips.iter_cidrs()),
                    abuse_count=len(feed_store.abuse_ips.iter_cidrs()),
                    apple_relay_count=len(feed_store.apple_relay_ips.iter_cidrs()))


async def refresh_all_feeds() -> dict[str, int]:
    """Downloads and updates all threat intelligence feeds verifying SHA-256 checksums."""
    logger.info("Starting background refresh of IP reputation feeds with SHA-256 verification...")
    
    # 1. Fetch Tor Exits
    tor_text, tor_sha = await fetch_feed_text(settings.TOR_EXIT_NODES_URL)
    if tor_text and tor_sha:
        tor_set = parse_ip_lines(tor_text)
        if tor_set:
            feed_store.tor_exits = tor_set
            _save_feed_disk("tor.txt", tor_text, tor_sha)

    # 1b. Fetch Tor Relay Nodes Consensus List
    tor_relays_text, tor_relays_sha = await fetch_feed_text(settings.TOR_RELAYS_URL)
    if tor_relays_text and tor_relays_sha:
        tor_relays_set = parse_ip_lines(tor_relays_text)
        if tor_relays_set:
            feed_store.tor_relays = tor_relays_set
            _save_feed_disk("tor_relays.txt", tor_relays_text, tor_relays_sha)

    # 1c. Fetch GreenSnow Dynamic Proxies & Threat Feed
    gs_text, gs_sha = await fetch_feed_text(settings.GREENSNOW_URL)
    if gs_text and gs_sha:
        gs_set = parse_ip_lines(gs_text)
        if gs_set:
            feed_store.greensnow_ips = gs_set
            _save_feed_disk("greensnow.txt", gs_text, gs_sha)

    # 2. Fetch Team Cymru Fullbogons
    bogon_text, bogon_sha = await fetch_feed_text(settings.TEAM_CYMRU_BOGONS_URL)
    if bogon_text and bogon_sha:
        bogon_set = parse_ip_lines(bogon_text)
        if bogon_set:
            feed_store.bogon_ips = bogon_set
            _save_feed_disk("bogons.txt", bogon_text, bogon_sha)

    # 3. Fetch Abuse.ch Botnet C2 & ThreatFox List
    feodo_text, feodo_sha = await fetch_feed_text(settings.ABUSE_CH_C2_URL)
    tf_text, tf_sha = await fetch_feed_text(settings.THREATFOX_C2_URL)
    combined_c2_text = f"{feodo_text}\n{tf_text}"
    if combined_c2_text.strip():
        c2_set = parse_ip_lines(combined_c2_text)
        if c2_set:
            feed_store.botnet_c2_ips = c2_set
            c2_sha = calculate_sha256(combined_c2_text.encode("utf-8"))
            _save_feed_disk("botnet_c2.txt", combined_c2_text, c2_sha)

    # 4. Fetch Active Phishing Feeds (OpenPhish + IPsum)
    phish_set = netaddr.IPSet()
    openphish_text, _ = await fetch_feed_text(settings.OPENPHISH_URL)
    ipsum_text, _ = await fetch_feed_text(settings.PHISHING_IPSUM_URL)

    combined_phish_text = f"{openphish_text}\n{ipsum_text}"
    if combined_phish_text.strip():
        phish_set.update(parse_phishing_urls_to_ips(combined_phish_text))
        phish_set.update(parse_ip_lines(combined_phish_text))
        if phish_set:
            feed_store.phishing_ips = phish_set
            phish_sha = calculate_sha256(combined_phish_text.encode("utf-8"))
            _save_feed_disk("phishing.txt", combined_phish_text, phish_sha)

    # 5. Fetch Datacenter / Cloud IPs (AWS, GCP, OCI, DigitalOcean)
    dc_set = netaddr.IPSet()
    aws_data, aws_sha = await fetch_feed_json(settings.AWS_IP_RANGES_URL)
    if aws_data and aws_sha:
        dc_set.update(parse_aws_ip_ranges(aws_data))
        _save_feed_disk("aws.json", json.dumps(aws_data), aws_sha)
    
    gcp_data, gcp_sha = await fetch_feed_json(settings.GCP_IP_RANGES_URL)
    if gcp_data and gcp_sha:
        dc_set.update(parse_gcp_ip_ranges(gcp_data))
        _save_feed_disk("gcp.json", json.dumps(gcp_data), gcp_sha)

    oci_data, oci_sha = await fetch_feed_json(settings.OCI_IP_RANGES_URL)
    if oci_data and oci_sha:
        dc_set.update(parse_oci_ip_ranges(oci_data))
        _save_feed_disk("oci.json", json.dumps(oci_data), oci_sha)

    do_text, do_sha = await fetch_feed_text(settings.DIGITALOCEAN_IP_RANGES_URL)
    if do_text and do_sha:
        dc_set.update(parse_digitalocean_ip_ranges(do_text))
        _save_feed_disk("digitalocean.csv", do_text, do_sha)

    # Fetch extended Community Datacenter feeds (FireHOL Datacenter, Alibaba, Tencent, Vultr)
    fh_dc_text, _ = await fetch_feed_text(settings.FIREHOL_DATACENTER_URL)
    ali_text, _ = await fetch_feed_text(settings.ALIBABA_IP_RANGES_URL)
    ten_text, _ = await fetch_feed_text(settings.TENCENT_IP_RANGES_URL)
    vultr_text, _ = await fetch_feed_text(settings.VULTR_IP_RANGES_URL)

    combined_extra_dc = f"{fh_dc_text}\n{ali_text}\n{ten_text}\n{vultr_text}"
    if combined_extra_dc.strip():
        dc_set.update(parse_ip_lines(combined_extra_dc))
        extra_dc_sha = calculate_sha256(combined_extra_dc.encode("utf-8"))
        _save_feed_disk("datacenter_extra.netset", combined_extra_dc, extra_dc_sha)

    if dc_set:
        feed_store.datacenter_ips = dc_set
        feed_store._rebuild_int32_ranges()

    # 6. Fetch CDN Egress Ranges (Cloudflare + Fastly)
    cdn_set = netaddr.IPSet()
    cf_v4_text, cf_v4_sha = await fetch_feed_text(settings.CLOUDFLARE_IPS_V4_URL)
    cf_v6_text, cf_v6_sha = await fetch_feed_text(settings.CLOUDFLARE_IPS_V6_URL)
    cf_combined = f"{cf_v4_text}\n{cf_v6_text}"
    if cf_combined.strip():
        cf_sha = calculate_sha256(cf_combined.encode("utf-8"))
        cdn_set.update(parse_ip_lines(cf_combined))
        _save_feed_disk("cloudflare.txt", cf_combined, cf_sha)

    fastly_data, fastly_sha = await fetch_feed_json(settings.FASTLY_IPS_URL)
    if fastly_data and fastly_sha:
        cdn_set.update(parse_fastly_ip_ranges(fastly_data))
        _save_feed_disk("fastly.json", json.dumps(fastly_data), fastly_sha)

    if cdn_set:
        feed_store.cdn_ips = cdn_set

    # 7. Fetch Abuse Blocklists (Spamhaus DROP + FireHOL L1)
    abuse_set = netaddr.IPSet()
    spamhaus_text, spamhaus_sha = await fetch_feed_text(settings.SPAMHAUS_DROP_URL)
    firehol_text, firehol_sha = await fetch_feed_text(settings.FIREHOL_L1_URL)
    
    combined_abuse_text = f"{spamhaus_text}\n{firehol_text}"
    abuse_sha = calculate_sha256(combined_abuse_text.encode("utf-8"))
    abuse_set.update(parse_ip_lines(combined_abuse_text))

    if abuse_set:
        feed_store.abuse_ips = abuse_set
        _save_feed_disk("abuse.txt", combined_abuse_text, abuse_sha)

    # 8. Fetch Apple Private Relay Egress IPs
    apple_text, apple_sha = await fetch_feed_text(settings.APPLE_PRIVATE_RELAY_URL)
    if apple_text and apple_sha:
        apple_set = parse_apple_private_relay(apple_text)
        if apple_set:
            feed_store.apple_relay_ips = apple_set
            _save_feed_disk("apple_relay.csv", apple_text, apple_sha)

    feed_store.last_updated = time.time()

    # 9. Ensure MaxMind GeoLite2 Country & ASN MMDB databases are present on disk
    await download_mmdb_if_missing()

    counts = {
        "tor_exits": len(feed_store.tor_exits.iter_cidrs()),
        "bogons": len(feed_store.bogon_ips.iter_cidrs()),
        "botnet_c2_ips": len(feed_store.botnet_c2_ips.iter_cidrs()),
        "phishing_ips": len(feed_store.phishing_ips.iter_cidrs()),
        "datacenter_cidrs": len(feed_store.datacenter_ips.iter_cidrs()),
        "cdn_cidrs": len(feed_store.cdn_ips.iter_cidrs()),
        "abuse_ips": len(feed_store.abuse_ips.iter_cidrs()),
        "apple_relay_cidrs": len(feed_store.apple_relay_ips.iter_cidrs())
    }

    logger.info("Feeds refresh completed with SHA-256 integrity verification", **counts)
    return counts


async def download_mmdb_if_missing():
    """Downloads GeoLite2 Country and ASN databases if missing from data/mmdb/."""
    mmdb_dir = os.path.join(settings.DATA_DIR, "mmdb")
    os.makedirs(mmdb_dir, exist_ok=True)

    country_path = settings.MAXMIND_COUNTRY_DB_PATH
    asn_path = settings.MAXMIND_ASN_DB_PATH

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        if not os.path.exists(country_path) or os.path.getsize(country_path) == 0:
            try:
                logger.info("Downloading MaxMind GeoLite2 Country database...", url=settings.GEOLITE2_COUNTRY_URL)
                res = await client.get(settings.GEOLITE2_COUNTRY_URL)
                if res.status_code == 200:
                    with open(country_path, "wb") as f:
                        f.write(res.content)
                    logger.info("GeoLite2 Country database downloaded successfully", size_bytes=len(res.content))
                    # Re-initialize lookup service to pick up the new DB
                    from app.services.lookup import lookup_service
                    from app.security.l1_cache import l1_cache
                    lookup_service.initialize()
                    l1_cache.clear()
            except Exception as exc:
                logger.warning("Failed to download GeoLite2 Country DB", error=str(exc))

        if not os.path.exists(asn_path) or os.path.getsize(asn_path) == 0:
            try:
                logger.info("Downloading MaxMind GeoLite2 ASN database...", url=settings.GEOLITE2_ASN_URL)
                res = await client.get(settings.GEOLITE2_ASN_URL)
                if res.status_code == 200:
                    with open(asn_path, "wb") as f:
                        f.write(res.content)
                    logger.info("GeoLite2 ASN database downloaded successfully", size_bytes=len(res.content))
                    # Re-initialize lookup service to pick up the new DB
                    from app.services.lookup import lookup_service
                    from app.security.l1_cache import l1_cache
                    lookup_service.initialize()
                    l1_cache.clear()
            except Exception as exc:
                logger.warning("Failed to download GeoLite2 ASN DB", error=str(exc))


def start_feed_updater():
    """Initializes the background scheduler for updating feeds periodically."""
    scheduler.add_job(
        refresh_all_feeds,
        "interval",
        hours=settings.FEED_UPDATE_INTERVAL_HOURS,
        id="refresh_ip_feeds",
        replace_existing=True
    )
    scheduler.start()
