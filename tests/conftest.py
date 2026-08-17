import pytest
import pytest_asyncio
import netaddr
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings
from app.feeds.updater import feed_store

# Enable private IPs for test environment
settings.ALLOW_PRIVATE_IPS_FOR_TESTING = True


@pytest.fixture(autouse=True)
def setup_test_feeds():
    """Populates feed_store with deterministic test CIDRs."""
    feed_store.tor_exits = netaddr.IPSet(["185.220.101.5/32"])
    feed_store.datacenter_ips = netaddr.IPSet(["1.1.1.0/24", "8.8.8.0/24"])
    feed_store.abuse_ips = netaddr.IPSet(["198.51.100.10/32"])
    yield


@pytest_asyncio.fixture
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
