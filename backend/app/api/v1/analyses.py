import os
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.analysis import Analysis, AnalysisStatus
from backend.app.models.user import User, UserRole
from backend.app.schemas.analysis import AnalysisSummaryResponse, AnalysisDetailResponse
from backend.app.services.analysis_service import AnalysisService
from backend.app.api.v1.deps import get_current_user

router = APIRouter(prefix="/analyses", tags=["Analyses"])

@router.get("", response_model=List[AnalysisSummaryResponse])
def list_analyses(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[AnalysisStatus] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Analysis).order_by(Analysis.id.desc())
    if status:
        query = query.filter(Analysis.status == status)
    return query.offset(skip).limit(limit).all()

@router.get("/{analysis_id}", response_model=AnalysisDetailResponse)
def get_analysis_detail(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis

@router.post("/{analysis_id}/run", response_model=AnalysisDetailResponse)
def trigger_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return AnalysisService.run_analysis(db, analysis_id)

@router.delete("/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Clean up capture file from disk
    if analysis.capture and analysis.capture.file_path and os.path.exists(analysis.capture.file_path):
        try:
            os.remove(analysis.capture.file_path)
        except OSError:
            pass

    db.delete(analysis)
    db.commit()
    return None
