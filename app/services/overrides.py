import os
import json
import netaddr
from app.config import settings
from app.security.logging import logger


class OverridesStore:
    def __init__(self):
        self.allowlist: netaddr.IPSet = netaddr.IPSet()
        self.denylist: netaddr.IPSet = netaddr.IPSet()
        self.allowlist_asns: set[int] = set()
        self.denylist_asns: set[int] = set()
        self.filepath = os.path.join(settings.DATA_DIR, "overrides.json")

    def load_overrides(self):
        """Loads custom allowlist/denylist CIDRs, IPs, and ASNs from data/overrides.json."""
        self.allowlist = netaddr.IPSet()
        self.denylist = netaddr.IPSet()
        self.allowlist_asns = set()
        self.denylist_asns = set()

        if not os.path.exists(self.filepath):
            # Create default empty template if file does not exist
            template = {
                "allowlist": ["192.168.99.100/32"],
                "denylist": ["198.51.100.42/32"],
                "allowlist_asns": [],
                "denylist_asns": []
            }
            try:
                os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
                with open(self.filepath, "w", encoding="utf-8") as f:
                    json.dump(template, f, indent=2)
            except Exception as exc:
                logger.warning("Could not write default overrides.json template", error=str(exc))

        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)

                allow_lines = data.get("allowlist", [])
                for line in allow_lines:
                    try:
                        self.allowlist.add(netaddr.IPNetwork(line.strip()))
                    except Exception:
                        pass

                deny_lines = data.get("denylist", [])
                for line in deny_lines:
                    try:
                        self.denylist.add(netaddr.IPNetwork(line.strip()))
                    except Exception:
                        pass

                allow_asns = data.get("allowlist_asns", [])
                for asn_val in allow_asns:
                    try:
                        self.allowlist_asns.add(int(asn_val))
                    except Exception:
                        pass

                deny_asns = data.get("denylist_asns", [])
                for asn_val in deny_asns:
                    try:
                        self.denylist_asns.add(int(asn_val))
                    except Exception:
                        pass

                logger.info("Custom IP/ASN Overrides loaded",
                            allowlist_count=len(self.allowlist.iter_cidrs()),
                            denylist_count=len(self.denylist.iter_cidrs()),
                            allowlist_asns=list(self.allowlist_asns),
                            denylist_asns=list(self.denylist_asns))
            except Exception as exc:
                logger.warning("Failed to load custom overrides.json", error=str(exc))

    def is_allowlisted(self, ip_str: str, asn: int = None) -> bool:
        try:
            if ip_str in self.allowlist:
                return True
            if asn and asn in self.allowlist_asns:
                return True
            return False
        except Exception:
            return False

    def is_denylisted(self, ip_str: str, asn: int = None) -> bool:
        try:
            if ip_str in self.denylist:
                return True
            if asn and asn in self.denylist_asns:
                return True
            return False
        except Exception:
            return False


overrides_store = OverridesStore()
