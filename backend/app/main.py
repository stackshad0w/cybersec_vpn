import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.app.core.config import settings, BASE_DIR
from backend.app.core.database import init_db, SessionLocal
from backend.app.core.security import get_password_hash
from backend.app.models.user import User, UserRole
from backend.app.services.demo_service import DemoService
from backend.app.api.v1.router import api_router

FRONTEND_DIR = BASE_DIR / "frontend"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize DB tables
    init_db()
    
    # 2. Seed default users if empty
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == "admin").first():
            admin_user = User(
                username="admin",
                email="admin@cybersec-vpn.internal",
                hashed_password=get_password_hash("Admin@123!Secure"),
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(admin_user)
            
        if not db.query(User).filter(User.username == "analyst").first():
            analyst_user = User(
                username="analyst",
                email="analyst@cybersec-vpn.internal",
                hashed_password=get_password_hash("Analyst@123!"),
                role=UserRole.ANALYST,
                is_active=True
            )
            db.add(analyst_user)
        db.commit()

        # 3. Pre-seed Demo Analysis for instant judge demonstration
        DemoService.load_demo_analysis(db)
    except Exception as e:
        print(f"Startup initialization notice: {e}")
        db.rollback()
    finally:
        db.close()

    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Privacy-Preserving AI-Assisted IPsec VPN Security Assessment Platform.",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API V1 routes
app.include_router(api_router, prefix=settings.API_V1_STR)

# Mount static frontend assets
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/", tags=["Frontend Dashboard"])
def index():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "documentation": "/docs",
        "api_v1": settings.API_V1_STR
    }

@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT
    }
