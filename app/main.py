import asyncio
import uuid
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.security.logging import setup_logging, logger
from app.security.rate_limiter import limiter
from app.services.overrides import overrides_store
from app.services.cache import cache_service
from app.services.lookup import lookup_service
from app.feeds.updater import start_feed_updater, refresh_all_feeds, load_feeds_from_disk_fallback
from app.api.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup initialization
    setup_logging(debug=settings.DEBUG)
    logger.info("Initializing IP Reputation Score API...", version=settings.VERSION)

    # 1. Load feeds and custom overrides from disk
    load_feeds_from_disk_fallback()
    overrides_store.load_overrides()

    # 2. Initialize MMDB lookup service
    lookup_service.initialize()

    # 3. Connect Redis Cache & Subnet Velocity Tracker
    await cache_service.connect()
    from app.security.subnet_velocity import subnet_velocity_tracker
    await subnet_velocity_tracker.initialize()

    # 4. Refresh remote feeds asynchronously in background & start scheduler
    asyncio.create_task(refresh_all_feeds())
    start_feed_updater()

    yield

    # Shutdown cleanup
    logger.info("Shutting down IP Reputation Score API...")
    await cache_service.close()
    await subnet_velocity_tracker.close()
    lookup_service.close()


from fastapi.staticfiles import StaticFiles

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Production-grade IP Reputation Score API built with Security by Design, Privacy by Design, and PII Zero principles.",
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    docs_url=f"{settings.API_PREFIX}/docs",
    redoc_url=f"{settings.API_PREFIX}/redoc",
    lifespan=lifespan
)

# Mount Static Files directory for client widget JS
import os
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Rate Limiter setup
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

from fastapi.middleware.gzip import GZipMiddleware

# GZip Compression Middleware (High-Throughput Payload Compression)
app.add_middleware(GZipMiddleware, minimum_size=500)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type", "X-API-Key", "X-Request-ID"],
)


# Request Body Limit Middleware (Security Hardening against DoS/RAM Exhaustion)
@app.middleware("http")
async def limit_request_body_size(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        content_length = request.headers.get("Content-Length")
        if content_length:
            try:
                length = int(content_length)
                if length > settings.MAX_REQUEST_BODY_SIZE:
                    return JSONResponse(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        content={
                            "type": "https://errors.ipscore.api/payload-too-large",
                            "title": "Payload Too Large",
                            "status": 413,
                            "detail": f"Request body size ({length} bytes) exceeds maximum limit of {settings.MAX_REQUEST_BODY_SIZE} bytes.",
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        }
                    )
            except ValueError:
                pass
    return await call_next(request)


# Correlation ID and Security Headers Middleware
@app.middleware("http")
async def add_security_and_correlation_headers(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com;"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    return response


# Validation Error Handler (Returns clean RFC 7807 JSON without leaking internal details)
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    first_msg = errors[0].get("msg") if errors else "Invalid request input"
    req_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "type": "https://errors.ipscore.api/invalid-input",
            "title": "Bad Request",
            "status": 400,
            "detail": first_msg,
            "request_id": req_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    )


# General Exception Handler (Enterprise Grade: Hides internal stack traces from clients, logs trace internally)
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", None)
    logger.error("Unhandled server exception", error=str(exc), request_id=req_id)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "type": "https://errors.ipscore.api/internal-error",
            "title": "Internal Server Error",
            "status": 500,
            "detail": "An unexpected server error occurred.",
            "request_id": req_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    )


# Include API Router
app.include_router(api_router, prefix=settings.API_PREFIX)


# Root Dashboard access shortcut
@app.get("/dashboard", include_in_schema=False)
async def root_dashboard():
    from app.api.v1.dashboard import get_dashboard
    return await get_dashboard()

