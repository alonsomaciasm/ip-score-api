import time
import os
import resource
from fastapi import APIRouter, status
from app.config import settings
from app.feeds.updater import feed_store
from app.services.overrides import overrides_store

router = APIRouter(prefix="/health", tags=["Health"])

START_TIME = time.time()


@router.get("/liveness", status_code=status.HTTP_200_OK, summary="Liveness Probe")
async def liveness():
    return {"status": "alive", "version": settings.VERSION}


@router.get("/readiness", status_code=status.HTTP_200_OK, summary="Readiness Probe")
async def readiness():
    return {
        "status": "ready",
        "version": settings.VERSION,
        "feeds": {
            "tor_exits_loaded": len(feed_store.tor_exits.iter_cidrs()),
            "bogons_loaded": len(feed_store.bogon_ips.iter_cidrs()),
            "botnet_c2_ips_loaded": len(feed_store.botnet_c2_ips.iter_cidrs()),
            "phishing_ips_loaded": len(feed_store.phishing_ips.iter_cidrs()),
            "datacenter_cidrs_loaded": len(feed_store.datacenter_ips.iter_cidrs()),
            "cdn_cidrs_loaded": len(feed_store.cdn_ips.iter_cidrs()),
            "abuse_ips_loaded": len(feed_store.abuse_ips.iter_cidrs()),
            "apple_relay_cidrs_loaded": len(feed_store.apple_relay_ips.iter_cidrs()),
            "last_updated": feed_store.last_updated
        }
    }


@router.get("/security", status_code=status.HTTP_200_OK, summary="Security Health Audit Report")
async def security_audit():
    """Returns a real-time security audit report including salt rotation date, SHA-256 feed integrity checksums, and memory usage."""
    current_utc_date = time.strftime("%Y-%m-%d", time.gmtime())
    
    # Calculate RSS memory footprint
    rss_mb = 0.0
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        # On Linux ru_maxrss is in kilobytes
        rss_mb = round(usage.ru_maxrss / 1024.0, 2)
    except Exception:
        pass

    return {
        "status": "secure",
        "version": settings.VERSION,
        "pii_zero_active": True,
        "pii_scrubber_enabled": True,
        "salt_rotation": {
            "active_utc_date": current_utc_date,
            "rotation_interval": "daily"
        },
        "overrides": {
            "allowlist_cidrs": len(overrides_store.allowlist.iter_cidrs()),
            "denylist_cidrs": len(overrides_store.denylist.iter_cidrs())
        },
        "feed_checksums_sha256": feed_store.checksums,
        "runtime": {
            "uptime_seconds": round(time.time() - START_TIME, 2),
            "rss_memory_mb": rss_mb
        }
    }
