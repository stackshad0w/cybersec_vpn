import os
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.analysis import Analysis
from backend.app.models.report import Report, ReportType
from backend.app.models.user import User
from backend.app.services.analysis_service import AnalysisService
from backend.app.api.v1.deps import get_current_user

router = APIRouter(prefix="/analyses", tags=["Reports & Exports"])

@router.get("/{analysis_id}/reports/executive.pdf")
def download_executive_report(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    report = db.query(Report).filter(
        Report.analysis_id == analysis_id,
        Report.report_type == ReportType.EXECUTIVE_PDF
    ).first()

    if not report or not os.path.exists(report.file_path):
        # Regenerate report on the fly
        AnalysisService.generate_reports_for_analysis(db, analysis)
        report = db.query(Report).filter(
            Report.analysis_id == analysis_id,
            Report.report_type == ReportType.EXECUTIVE_PDF
        ).first()

    if not report or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Executive report could not be generated.")

    return FileResponse(
        report.file_path,
        media_type="application/pdf",
        filename=f"Executive_Report_Analysis_{analysis_id}.pdf"
    )

@router.get("/{analysis_id}/reports/technical.pdf")
def download_technical_report(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    report = db.query(Report).filter(
        Report.analysis_id == analysis_id,
        Report.report_type == ReportType.TECHNICAL_PDF
    ).first()

    if not report or not os.path.exists(report.file_path):
        AnalysisService.generate_reports_for_analysis(db, analysis)
        report = db.query(Report).filter(
            Report.analysis_id == analysis_id,
            Report.report_type == ReportType.TECHNICAL_PDF
        ).first()

    if not report or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Technical report could not be generated.")

    return FileResponse(
        report.file_path,
        media_type="application/pdf",
        filename=f"Technical_Audit_Report_Analysis_{analysis_id}.pdf"
    )

@router.get("/{analysis_id}/reports/export.json")
def download_json_export(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    report = db.query(Report).filter(
        Report.analysis_id == analysis_id,
        Report.report_type == ReportType.JSON
    ).first()

    if not report or not os.path.exists(report.file_path):
        AnalysisService.generate_reports_for_analysis(db, analysis)
        report = db.query(Report).filter(
            Report.analysis_id == analysis_id,
            Report.report_type == ReportType.JSON
        ).first()

    if not report or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="JSON export could not be generated.")

    return FileResponse(
        report.file_path,
        media_type="application/json",
        filename=f"IPsec_Analysis_Export_{analysis_id}.json"
    )
