from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.schemas.analysis import AnalysisDetailResponse
from backend.app.services.demo_service import DemoService
from backend.app.models.user import User
from backend.app.api.v1.deps import get_current_user

router = APIRouter(prefix="/demo", tags=["Demo Mode"])

@router.post("/load", response_model=AnalysisDetailResponse)
def load_demo(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Loads PRD-compliant Demo Analysis for immediate live presentation.
    Score: 82, IPsec detected, IKEv2, Tunnel mode, AES-256-GCM, PFS enabled, Replay enabled, Video-like 91%.
    """
    user_id = current_user.id if current_user else None
    demo_analysis = DemoService.load_demo_analysis(db, user_id=user_id)
    return demo_analysis
