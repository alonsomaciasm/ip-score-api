from fastapi import APIRouter, Depends, Request, status
from app.models.request import ScoreRequest, BatchScoreRequest
from app.models.response import ScoreResponse, BatchScoreResponse, BatchItemResponse, ErrorResponse
from app.services.scoring import ScoringEngine
from app.services.cache import cache_service
from app.security.auth import verify_api_key
from app.security.rate_limiter import limiter
from app.security.logging import logger

router = APIRouter(prefix="/score", tags=["Scoring"])


@router.post(
    "",
    response_model=ScoreResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid IP format or private IP address"},
        401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"}
    },
    summary="Evaluate IP Risk Score",
    description="Returns risk score (0-100), risk level, recommendation, network flags and confidence for a given IPv4 or IPv6 address without persisting PII."
)
@limiter.limit("100/minute")
async def evaluate_ip_score(
    request: Request,
    body: ScoreRequest,
    api_key: str = Depends(verify_api_key(required_scope="score:read"))
) -> ScoreResponse:
    ip_str = body.ip

    # 1. Check L1 RAM Cache fast-path raw bytes
    from app.security.l1_cache import l1_cache
    cached_bytes = l1_cache.get_bytes(ip_str)
    if cached_bytes:
        return Response(content=cached_bytes, media_type="application/json")

    cached_response = await cache_service.get_score(ip_str)
    if cached_response:
        logger.debug("Score returned from cache")
        return cached_response

    # 2. Calculate score using scoring engine
    score_response = await ScoringEngine.calculate_score(body)

    # 3. Store result in cache asynchronously under hashed key
    l1_cache.set(ip_str, score_response)
    await cache_service.set_score(ip_str, score_response)

    # Log aggregated metrics (PII Zero: no IP logged)
    logger.info(
        "Evaluated IP score",
        risk_level=score_response.risk_level,
        recommendation=score_response.recommendation,
        risk_score=score_response.risk_score
    )

    return score_response


from fastapi.responses import Response
import orjson

@router.post(
    "/batch",
    response_model=BatchScoreResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid batch request format"},
        401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"}
    },
    summary="Evaluate Batch of IP Risk Scores",
    description="Evaluates up to 50 IPv4 or IPv6 addresses in a single high-throughput batch request without persisting PII."
)
@limiter.limit("30/minute")
async def evaluate_batch_scores(
    request: Request,
    body: BatchScoreRequest,
    api_key: str = Depends(verify_api_key(required_scope="score:read"))
):
    results_list = []
    ips_to_calculate = []
    
    # 1. Batch fetch from Redis in 1 single TCP RTT via Pipelining
    cached_map = await cache_service.get_scores_batch(body.ips)

    for ip_str in body.ips:
        cached = cached_map.get(ip_str)
        if cached:
            results_list.append({"ip": ip_str, "result": cached.model_dump()})
        else:
            ips_to_calculate.append(ip_str)

    # 2. Evaluate remaining non-cached IPs
    if ips_to_calculate:
        to_cache = []
        for ip_str in ips_to_calculate:
            req = ScoreRequest(ip=ip_str)
            evaluated = await ScoringEngine.calculate_score(req)
            to_cache.append((ip_str, evaluated))
            results_list.append({"ip": ip_str, "result": evaluated.model_dump()})

        # Batch write to Redis in 1 single TCP RTT via Pipelining
        await cache_service.set_scores_batch(to_cache)

    logger.info("Evaluated batch IP scores", batch_size=len(results_list))
    payload = {"total_evaluated": len(results_list), "results": results_list}
    return Response(content=orjson.dumps(payload), media_type="application/json")
