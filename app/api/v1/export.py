from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import StreamingResponse
import time
from app.security.auth import verify_api_key
from app.feeds.updater import feed_store

router = APIRouter(prefix="/export", tags=["Intelligence Export"])


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="Export Threat Intelligence Feeds as Streaming CSV",
    description="Streams consolidated IP threat intelligence records (Tor, Botnet C2, Abuse lists, Cloud Datacenters, Apple Relay, Phishing) in CSV format with UTF-8 BOM for direct import into SIEM (Splunk/Elastic), Firewalls, or Excel."
)
async def export_threat_feeds_csv(
    feed_type: str = Query(
        default="all",
        description="Filter feed type to export: 'all', 'tor', 'c2', 'phishing', 'datacenter', 'abuse', 'apple_relay', 'cdn'"
    ),
    api_key: str = Depends(verify_api_key(required_scope="score:read"))
):
    def generate_csv_rows():
        # UTF-8 BOM header for Excel compatibility
        yield "\ufeff"
        yield "cidr_or_ip,category,description,checksum_sha256,exported_at\n"

        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        category_map = [
            ("tor", feed_store.tor_exits, "Tor Exit Node", "tor.txt"),
            ("tor_relay", feed_store.tor_relays, "Tor Relay Node", "tor_relays.txt"),
            ("c2", feed_store.botnet_c2_ips, "Botnet C2 Server", "botnet_c2.txt"),
            ("phishing", feed_store.phishing_ips, "Active Phishing Host", "phishing.txt"),
            ("abuse", feed_store.abuse_ips, "Spamhaus / FireHOL Abuse IP", "abuse.txt"),
            ("greensnow", feed_store.greensnow_ips, "GreenSnow Malicious IP", "greensnow.txt"),
            ("datacenter", feed_store.datacenter_ips, "Cloud / Datacenter Egress", "aws.json"),
            ("apple_relay", feed_store.apple_relay_ips, "Apple Private Relay Egress", "apple_relay.csv"),
            ("cdn", feed_store.cdn_ips, "CDN Edge Egress", "cloudflare.txt"),
        ]

        target_type = feed_type.lower().strip()

        for cat_key, ip_set, desc, file_ref in category_map:
            if target_type != "all" and target_type != cat_key:
                continue

            checksum = feed_store.checksums.get(file_ref, "N/A")[:12]
            if ip_set:
                for cidr in ip_set.iter_cidrs():
                    yield f"{str(cidr)},{cat_key},{desc},{checksum},{now_str}\n"

    filename = f"ip_reputation_feeds_{feed_type}_{time.strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        generate_csv_rows(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
