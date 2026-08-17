import pytest


@pytest.mark.asyncio
async def test_score_endpoint_unauthorized(async_client):
    response = await async_client.post("/api/v1/score", json={"ip": "185.220.101.5"})
    assert response.status_code == 401
    json_data = response.json()
    assert "detail" in json_data


@pytest.mark.asyncio
async def test_score_endpoint_success(async_client):
    headers = {"X-API-Key": "sk_test_1234567890abcdef"}
    response = await async_client.post(
        "/api/v1/score",
        json={"ip": "185.220.101.5"},
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()

    assert data["ip_version"] == 4
    assert "risk_score" in data
    assert "risk_level" in data
    assert "recommendation" in data
    assert "flags" in data
    assert "network" in data
    assert "confidence" in data
    assert "signals_used" in data
    assert "X-Request-ID" in response.headers


@pytest.mark.asyncio
async def test_batch_score_endpoint_success(async_client):
    headers = {"X-API-Key": "sk_test_1234567890abcdef"}
    batch_payload = {"ips": ["185.220.101.5", "8.8.8.8", "203.0.113.10"]}
    response = await async_client.post(
        "/api/v1/score/batch",
        json=batch_payload,
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()

    assert data["total_evaluated"] == 3
    assert len(data["results"]) == 3
    assert data["results"][0]["ip"] == "185.220.101.5"
    assert data["results"][0]["result"]["risk_score"] >= 90


@pytest.mark.asyncio
async def test_metrics_endpoint_success(async_client):
    headers = {"X-API-Key": "sk_test_1234567890abcdef"}
    response = await async_client.get("/api/v1/metrics", headers=headers)
    assert response.status_code == 200
    assert "ip_score_requests_total" in response.text or "ip_score_feed_elements_total" in response.text


@pytest.mark.asyncio
async def test_invalid_ip_format(async_client):
    headers = {"X-API-Key": "sk_test_1234567890abcdef"}
    response = await async_client.post(
        "/api/v1/score",
        json={"ip": "999.888.777.666"},
        headers=headers
    )
    assert response.status_code == 400
    data = response.json()
    assert data["status"] == 400
    assert "request_id" in data
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_invalid_ipv6_format(async_client):
    headers = {"X-API-Key": "sk_test_1234567890abcdef"}
    response = await async_client.post(
        "/api/v1/score",
        json={"ip": "2001:::db8:::1"},
        headers=headers
    )
    assert response.status_code == 400
    data = response.json()
    assert data["status"] == 400


@pytest.mark.asyncio
async def test_private_ip_rejection(async_client, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_IPS_FOR_TESTING", False)
    headers = {"X-API-Key": "sk_test_1234567890abcdef"}
    response = await async_client.post(
        "/api/v1/score",
        json={"ip": "10.0.0.1"},
        headers=headers
    )
    assert response.status_code == 400
    data = response.json()
    assert "Private or reserved" in data["detail"] or "invalid" in data["detail"].lower()


@pytest.mark.asyncio
async def test_insufficient_scope_forbidden(async_client):
    # sk_test_1234567890abcdef has score:read, metrics:read but NOT admin:feeds
    headers = {"X-API-Key": "sk_test_1234567890abcdef"}
    response = await async_client.post("/api/v1/admin/feeds/refresh", headers=headers)
    assert response.status_code == 403
    data = response.json()
    assert "Insufficient scope" in data["detail"]["detail"]


@pytest.mark.asyncio
async def test_empty_json_body(async_client):
    headers = {"X-API-Key": "sk_test_1234567890abcdef"}
    response = await async_client.post(
        "/api/v1/score",
        json={},
        headers=headers
    )
    assert response.status_code == 400
    data = response.json()
    assert data["status"] == 400


@pytest.mark.asyncio
async def test_empty_batch_array(async_client):
    headers = {"X-API-Key": "sk_test_1234567890abcdef"}
    response = await async_client.post(
        "/api/v1/score/batch",
        json={"ips": []},
        headers=headers
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_batch_exceed_max_limit_rejection(async_client):
    headers = {"X-API-Key": "sk_test_1234567890abcdef"}
    # Send 51 IPs (limit is BATCH_MAX_SIZE = 50)
    over_limit_ips = [f"1.1.1.{i}" for i in range(1, 52)]
    response = await async_client.post(
        "/api/v1/score/batch",
        json={"ips": over_limit_ips},
        headers=headers
    )
    assert response.status_code in [400, 422]
    data = response.json()
    assert data["status"] in [400, 422]


@pytest.mark.asyncio
async def test_security_audit_endpoint(async_client):
    response = await async_client.get("/api/v1/health/security")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "secure"
    assert "pii_zero_active" in data
    assert "feed_checksums_sha256" in data


@pytest.mark.asyncio
async def test_health_liveness(async_client):
    response = await async_client.get("/api/v1/health/liveness")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"


@pytest.mark.asyncio
async def test_health_readiness(async_client):
    response = await async_client.get("/api/v1/health/readiness")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"


@pytest.mark.asyncio
async def test_dashboard_endpoint_success(async_client):
    response = await async_client.get("/dashboard")
    assert response.status_code == 200
    assert "IP Reputation Score API" in response.text
    assert "PII Zero Active" in response.text


@pytest.mark.asyncio
async def test_jwt_bearer_authentication_success(async_client):
    from app.security.auth import create_jwt_token
    token = create_jwt_token(scopes=["score:read", "metrics:read"], subject="zero_trust_service")
    headers = {"Authorization": f"Bearer {token}"}
    
    response = await async_client.post(
        "/api/v1/score",
        json={"ip": "185.220.101.5"},
        headers=headers
    )
    assert response.status_code == 200
    assert response.json()["risk_score"] >= 90


@pytest.mark.asyncio
async def test_jwt_bearer_insufficient_scope(async_client):
    from app.security.auth import create_jwt_token
    token = create_jwt_token(scopes=["score:read"], subject="unprivileged_client")
    headers = {"Authorization": f"Bearer {token}"}
    
    response = await async_client.post(
        "/api/v1/admin/feeds/refresh",
        headers=headers
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_payload_too_large_rejection(async_client):
    headers = {
        "X-API-Key": "sk_test_1234567890abcdef",
        "Content-Length": "2048576"  # 2 MB > limit 1 MB
    }
    response = await async_client.post(
        "/api/v1/score",
        json={"ip": "185.220.101.5"},
        headers=headers
    )
    assert response.status_code == 413
    data = response.json()
    assert data["status"] == 413
    assert "exceeds maximum limit" in data["detail"]


@pytest.mark.asyncio
async def test_export_threat_feeds_csv(async_client):
    headers = {"X-API-Key": "sk_test_1234567890abcdef"}
    response = await async_client.get("/api/v1/export?feed_type=tor", headers=headers)
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "cidr_or_ip,category,description" in response.text


@pytest.mark.asyncio
async def test_static_widget_js_served(async_client):
    response = await async_client.get("/static/ip-score-widget.js")
    assert response.status_code == 200
    assert "IPScoreWidget" in response.text


