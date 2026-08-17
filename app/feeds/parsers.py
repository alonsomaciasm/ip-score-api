import re
import netaddr
import csv
import io

IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:3[0-2]|[12]?[0-9]))?\b')


def parse_ip_lines(text: str) -> netaddr.IPSet:
    """Parses text containing one IP or CIDR per line (e.g. Tor Exits, Spamhaus DROP, Bogons). Optimized with batch constructor."""
    if not text:
        return netaddr.IPSet()

    networks = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        
        token = line.split()[0].split(";")[0]
        try:
            networks.append(netaddr.IPNetwork(token))
        except (netaddr.AddrFormatError, ValueError):
            # Fallback: Regex search for embedded IPv4/CIDR
            matches = IP_REGEX.findall(line)
            for m in matches:
                try:
                    networks.append(netaddr.IPNetwork(m))
                except Exception:
                    pass

    return netaddr.IPSet(networks)


def parse_phishing_urls_to_ips(text: str) -> netaddr.IPSet:
    """Extracts IPv4 addresses and CIDRs directly from raw Phishing URLs or text lists."""
    if not text:
        return netaddr.IPSet()

    networks = []
    matches = IP_REGEX.findall(text)
    for m in matches:
        try:
            networks.append(netaddr.IPNetwork(m))
        except Exception:
            pass

    return netaddr.IPSet(networks)


def parse_aws_ip_ranges(data: dict) -> netaddr.IPSet:
    """Parses AWS official IP ranges JSON with batch constructor."""
    networks = []
    prefixes = data.get("prefixes", [])
    for p in prefixes:
        cidr = p.get("ip_prefix")
        if cidr:
            try:
                networks.append(netaddr.IPNetwork(cidr))
            except Exception:
                pass
    ipv6_prefixes = data.get("ipv6_prefixes", [])
    for p in ipv6_prefixes:
        cidr = p.get("ipv6_prefix")
        if cidr:
            try:
                networks.append(netaddr.IPNetwork(cidr))
            except Exception:
                pass
    return netaddr.IPSet(networks)


def parse_gcp_ip_ranges(data: dict) -> netaddr.IPSet:
    """Parses GCP official IP ranges JSON with batch constructor."""
    networks = []
    prefixes = data.get("prefixes", [])
    for p in prefixes:
        cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
        if cidr:
            try:
                networks.append(netaddr.IPNetwork(cidr))
            except Exception:
                pass
    return netaddr.IPSet(networks)


def parse_azure_ip_ranges(data: dict) -> netaddr.IPSet:
    """Parses Azure official ServiceTags IP ranges JSON with batch constructor."""
    networks = []
    values = data.get("values", [])
    for val in values:
        props = val.get("properties", {})
        prefixes = props.get("addressPrefixes", [])
        for cidr in prefixes:
            try:
                networks.append(netaddr.IPNetwork(cidr))
            except Exception:
                pass
    return netaddr.IPSet(networks)


def parse_oci_ip_ranges(data: dict) -> netaddr.IPSet:
    """Parses Oracle Cloud Infrastructure (OCI) official IP ranges JSON."""
    networks = []
    regions = data.get("regions", [])
    for reg in regions:
        cidrs = reg.get("cidrs", [])
        for item in cidrs:
            cidr = item.get("cidr")
            if cidr:
                try:
                    networks.append(netaddr.IPNetwork(cidr))
                except Exception:
                    pass
    return netaddr.IPSet(networks)


def parse_digitalocean_ip_ranges(csv_text: str) -> netaddr.IPSet:
    """Parses DigitalOcean official CSV IP ranges with batch constructor."""
    if not csv_text:
        return netaddr.IPSet()

    networks = []
    try:
        reader = csv.reader(io.StringIO(csv_text))
        for row in reader:
            if not row:
                continue
            cidr = row[0].strip()
            if cidr and not cidr.startswith("#"):
                try:
                    networks.append(netaddr.IPNetwork(cidr))
                except Exception:
                    pass
    except Exception:
        pass
    return netaddr.IPSet(networks)


def parse_fastly_ip_ranges(data: dict) -> netaddr.IPSet:
    """Parses Fastly official IP ranges JSON with batch constructor."""
    networks = []
    addresses = data.get("addresses", []) + data.get("ipv6_addresses", [])
    for cidr in addresses:
        try:
            networks.append(netaddr.IPNetwork(cidr))
        except Exception:
            pass
    return netaddr.IPSet(networks)


def parse_apple_private_relay(csv_text: str) -> netaddr.IPSet:
    """Parses official Apple Private Relay egress IP CSV with batch constructor."""
    if not csv_text:
        return netaddr.IPSet()

    networks = []
    try:
        reader = csv.reader(io.StringIO(csv_text))
        for row in reader:
            if not row:
                continue
            cidr = row[0].strip()
            if cidr and not cidr.startswith("#"):
                try:
                    networks.append(netaddr.IPNetwork(cidr))
                except Exception:
                    pass
    except Exception:
        pass
    return netaddr.IPSet(networks)
