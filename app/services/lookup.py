import os
import maxminddb
from typing import Optional
from app.config import settings
from app.feeds.updater import feed_store
from app.security.logging import logger


class LookupResult:
    def __init__(self):
        self.asn: Optional[int] = None
        self.asn_org: str = "Unknown"
        self.country_code: Optional[str] = None
        self.country_name: str = "Unknown"
        self.network_type: str = "unknown"
        self.is_tor: bool = False
        self.is_tor_relay: bool = False
        self.is_greensnow: bool = False
        self.is_datacenter: bool = False
        self.is_abuse_listed: bool = False
        self.is_vpn: bool = False
        self.is_proxy: bool = False
        self.is_residential: bool = False
        self.is_mobile: bool = False
        self.is_icloud_relay: bool = False
        self.is_bogon: bool = False
        self.is_cdn_egress: bool = False
        self.is_botnet_c2: bool = False
        self.is_phishing: bool = False
        self.is_edu_gov: bool = False
        self.mmdb_matched: bool = False


class IPLookupService:
    def __init__(self):
        self._asn_reader: Optional[maxminddb.Reader] = None
        self._country_reader: Optional[maxminddb.Reader] = None

    def initialize(self):
        if os.path.exists(settings.MAXMIND_ASN_DB_PATH):
            try:
                self._asn_reader = maxminddb.open_database(settings.MAXMIND_ASN_DB_PATH)
                logger.info("Loaded MaxMind GeoLite2 ASN database", path=settings.MAXMIND_ASN_DB_PATH)
            except Exception as exc:
                logger.warning("Failed to open MaxMind ASN DB", error=str(exc))
                self._asn_reader = None
        else:
            logger.info("MaxMind ASN database file not found. Running in feed-only lookup mode.", path=settings.MAXMIND_ASN_DB_PATH)

        if os.path.exists(settings.MAXMIND_COUNTRY_DB_PATH):
            try:
                self._country_reader = maxminddb.open_database(settings.MAXMIND_COUNTRY_DB_PATH)
                logger.info("Loaded MaxMind GeoLite2 Country database", path=settings.MAXMIND_COUNTRY_DB_PATH)
            except Exception as exc:
                logger.warning("Failed to open MaxMind Country DB", error=str(exc))
                self._country_reader = None

    def close(self):
        if self._asn_reader:
            self._asn_reader.close()
        if self._country_reader:
            self._country_reader.close()

    def lookup(self, ip_str: str) -> LookupResult:
        res = LookupResult()

        # 1. Feed Store Checks (Tor Exits, Tor Relays, GreenSnow, Datacenter, Abuse, Apple Relay, Bogons, CDN, Botnet C2, Phishing)
        res.is_tor = feed_store.is_tor(ip_str)
        res.is_tor_relay = feed_store.is_tor_relay(ip_str)
        res.is_greensnow = feed_store.is_greensnow(ip_str)
        res.is_datacenter = feed_store.is_datacenter(ip_str)
        res.is_abuse_listed = feed_store.is_abuse_listed(ip_str) or res.is_greensnow
        res.is_icloud_relay = feed_store.is_icloud_relay(ip_str)
        res.is_bogon = feed_store.is_bogon(ip_str)
        res.is_cdn_egress = feed_store.is_cdn_egress(ip_str)
        res.is_botnet_c2 = feed_store.is_botnet_c2(ip_str)
        res.is_phishing = feed_store.is_phishing(ip_str)

        if res.is_icloud_relay:
            res.is_vpn = True

        # 2. MaxMind GeoLite2 ASN & Country Lookup
        if self._asn_reader:
            try:
                record = self._asn_reader.get(ip_str)
                if record and isinstance(record, dict):
                    res.mmdb_matched = True
                    res.asn = record.get("autonomous_system_number")
                    res.asn_org = record.get("autonomous_system_organization", "Unknown")
                    if not res.country_code:
                        country_dict = record.get("country", {}) or record.get("registered_country", {})
                        if isinstance(country_dict, dict):
                            res.country_code = country_dict.get("iso_code")
                            res.country_name = country_dict.get("names", {}).get("en", "Unknown") if isinstance(country_dict.get("names"), dict) else "Unknown"
            except Exception as exc:
                logger.debug("MMDB ASN lookup error", error=str(exc))

        if self._country_reader:
            try:
                record = self._country_reader.get(ip_str)
                if record and isinstance(record, dict):
                    res.mmdb_matched = True
                    country_dict = record.get("country", {}) or record.get("registered_country", {})
                    if isinstance(country_dict, dict):
                        res.country_code = country_dict.get("iso_code") or res.country_code
                        if isinstance(country_dict.get("names"), dict):
                            res.country_name = country_dict.get("names", {}).get("en", res.country_name)
            except Exception as exc:
                logger.debug("MMDB Country lookup error", error=str(exc))

        # 3. ASN Classification Heuristics
        if res.asn_org != "Unknown":
            org_lower = res.asn_org.lower()
            datacenter_keywords = ["hosting", "cloud", "datacenter", "server", "vps", "hetzner", "ovh", "digitalocean", "linode", "amazon", "google", "microsoft", "leaseweb"]
            residential_keywords = ["telecom", "broadband", "cable", "fiber", "comcast", "charter", "att", "verizon", "vodafone", "telefonica", "prodigy", "infinitum"]
            mobile_keywords = ["mobile", "cellular", "wireless", "lte", "gsm", "t-mobile", "orange", "claro"]
            edu_gov_keywords = ["university", "college", "edu", "ac.uk", "research", "government", "gobier", "gov", "state", "defense", "mil", "politécnico", "polytechnic"]

            if any(k in org_lower for k in edu_gov_keywords):
                res.is_edu_gov = True
                res.network_type = "education_government"
            elif any(k in org_lower for k in datacenter_keywords):
                res.is_datacenter = True
                res.network_type = "hosting"
            elif any(k in org_lower for k in mobile_keywords):
                res.is_mobile = True
                res.network_type = "mobile"
            elif any(k in org_lower for k in residential_keywords):
                res.is_residential = True
                res.network_type = "residential"
            else:
                res.network_type = "business"
        elif res.is_datacenter:
            res.network_type = "hosting"

        # 4. Proxy / VPN flags derived from indicators
        if res.is_tor or res.is_datacenter:
            res.is_proxy = res.is_tor

        return res


lookup_service = IPLookupService()
