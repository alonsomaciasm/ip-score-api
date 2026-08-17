from fastapi import APIRouter, Depends, Response, status
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from app.security.auth import verify_api_key
from app.feeds.updater import feed_store

router = APIRouter(prefix="/metrics", tags=["Observability"])

# Prometheus Metrics Definitions (PII Zero: metrics contain only aggregate metrics)
REQUEST_COUNT = Counter(
    "ip_score_requests_total",
    "Total count of IP reputation evaluation requests",
    ["risk_level", "recommendation"]
)

REQUEST_LATENCY = Histogram(
    "ip_score_request_duration_seconds",
    "Histogram of IP reputation calculation latency in seconds"
)

FEED_ITEMS_GAUGE = Gauge(
    "ip_score_feed_elements_total",
    "Total elements loaded per threat feed",
    ["feed_name"]
)


def update_feed_gauges():
    FEED_ITEMS_GAUGE.labels(feed_name="tor_exits").set(len(feed_store.tor_exits.iter_cidrs()))
    FEED_ITEMS_GAUGE.labels(feed_name="datacenter_cidrs").set(len(feed_store.datacenter_ips.iter_cidrs()))
    FEED_ITEMS_GAUGE.labels(feed_name="abuse_ips").set(len(feed_store.abuse_ips.iter_cidrs()))
    FEED_ITEMS_GAUGE.labels(feed_name="apple_private_relay").set(len(feed_store.apple_relay_ips.iter_cidrs()))


@router.get(
    "",
    summary="Get Prometheus Metrics",
    description="Returns aggregate system and business metrics in Prometheus format without PII.",
    response_class=Response
)
async def get_prometheus_metrics(
    api_key: str = Depends(verify_api_key(required_scope="metrics:read"))
):
    update_feed_gauges()
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
