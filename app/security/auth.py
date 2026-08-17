import hashlib
import hmac
import time
from typing import Optional, List
import jwt
from fastapi import Security, HTTPException, status, Request
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings
from app.security.logging import logger

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
http_bearer = HTTPBearer(auto_error=False)


def hash_key(key: str) -> str:
    """Computes SHA-256 hex digest of an API key."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def safe_compare(val1: str, val2: str) -> bool:
    """Constant-time string comparison to eliminate side-channel timing attacks."""
    return hmac.compare_digest(val1.encode("utf-8"), val2.encode("utf-8"))


def create_jwt_token(scopes: List[str], exp_minutes: int = 60, subject: str = "client") -> str:
    """Generates a signed JWT token containing subject and scopes claims."""
    now = int(time.time())
    payload = {
        "sub": subject,
        "iat": now,
        "nbf": now,
        "exp": now + (exp_minutes * 60),
        "iss": "ipscore.api",
        "scopes": scopes
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_api_key(required_scope: str = "score:read"):
    """
    Dual-mode Authentication dependency:
    Supports both X-API-Key header AND Bearer JWT Tokens with scope enforcement.
    """
    async def dependency(
        request: Request,
        api_key: Optional[str] = Security(api_key_header),
        bearer_auth: Optional[HTTPAuthorizationCredentials] = Security(http_bearer)
    ) -> str:
        matched_scopes: Optional[List[str]] = None
        authenticated_identity = None

        # Mode 1: Check Bearer JWT Token
        if bearer_auth and bearer_auth.credentials:
            token = bearer_auth.credentials
            try:
                payload = jwt.decode(
                    token,
                    settings.JWT_SECRET,
                    algorithms=[settings.JWT_ALGORITHM],
                    issuer="ipscore.api"
                )
                matched_scopes = payload.get("scopes", [])
                authenticated_identity = f"jwt:{payload.get('sub', 'unknown')}"
            except jwt.ExpiredSignatureError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={
                        "type": "https://errors.ipscore.api/expired-token",
                        "title": "Unauthorized",
                        "status": 401,
                        "detail": "Bearer JWT token has expired"
                    }
                )
            except jwt.PyJWTError as exc:
                logger.debug("Invalid JWT token", error=str(exc))
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={
                        "type": "https://errors.ipscore.api/invalid-token",
                        "title": "Unauthorized",
                        "status": 401,
                        "detail": "Invalid Bearer JWT token signature or payload"
                    }
                )

        # Mode 2: Check X-API-Key header
        elif api_key:
            incoming_hash = hash_key(api_key)
            for stored_key_or_hash, scopes in settings.API_KEYS.items():
                if safe_compare(api_key, stored_key_or_hash) or safe_compare(incoming_hash, stored_key_or_hash):
                    matched_scopes = scopes
                    authenticated_identity = f"key:{api_key[:8]}..."
                    break

        # If neither credential was provided
        if matched_scopes is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "type": "https://errors.ipscore.api/unauthorized",
                    "title": "Unauthorized",
                    "status": 401,
                    "detail": "Missing authentication credentials (Provide X-API-Key header or Authorization: Bearer <JWT>)"
                }
            )

        # Enforce Scopes
        if required_scope not in matched_scopes and "*" not in matched_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "type": "https://errors.ipscore.api/forbidden",
                    "title": "Forbidden",
                    "status": 403,
                    "detail": f"Insufficient scope. Required: '{required_scope}'"
                }
            )

        return authenticated_identity or "authenticated"

    return dependency
