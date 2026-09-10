from fastapi import APIRouter
from backend.app.api.v1.auth import router as auth_router
from backend.app.api.v1.upload import router as upload_router
from backend.app.api.v1.analyses import router as analyses_router
from backend.app.api.v1.reports import router as reports_router
from backend.app.api.v1.demo import router as demo_router
from backend.app.api.v1.policies import router as policies_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(upload_router)
api_router.include_router(analyses_router)
api_router.include_router(reports_router)
api_router.include_router(demo_router)
api_router.include_router(policies_router)
