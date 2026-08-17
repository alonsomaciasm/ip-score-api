from fastapi import APIRouter
from app.api.v1.score import router as score_router
from app.api.v1.health import router as health_router
from app.api.v1.admin import router as admin_router
from app.api.v1.metrics import router as metrics_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.export import router as export_router

api_router = APIRouter()
api_router.include_router(score_router)
api_router.include_router(health_router)
api_router.include_router(admin_router)
api_router.include_router(metrics_router)
api_router.include_router(dashboard_router)
api_router.include_router(export_router)
