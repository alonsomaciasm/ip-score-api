from fastapi import APIRouter, Depends, status
from app.security.auth import verify_api_key
from app.feeds.updater import refresh_all_feeds

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.post(
    "/feeds/refresh",
    status_code=status.HTTP_200_OK,
    summary="Trigger Manual Feeds Refresh",
    description="Manually triggers immediate download and reload of all threat intelligence IP feeds."
)
async def trigger_feeds_refresh(
    api_key: str = Depends(verify_api_key(required_scope="admin:feeds"))
):
    counts = await refresh_all_feeds()
    return {
        "status": "success",
        "message": "Feeds reloaded successfully",
        "counts": counts
    }
