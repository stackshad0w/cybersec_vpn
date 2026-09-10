import os
import uuid
import shutil
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.config import settings
from backend.app.models.user import User, UserRole
from backend.app.models.capture import CaptureFile
from backend.app.models.analysis import Analysis, AnalysisStatus
from backend.app.schemas.analysis import AnalysisSummaryResponse
from backend.app.analyzers.pcap_parser import PCAPParser
from backend.app.services.analysis_service import AnalysisService
from backend.app.api.v1.deps import get_current_user

router = APIRouter(prefix="/upload", tags=["PCAP Upload & Ingestion"])

@router.post("", response_model=AnalysisSummaryResponse)
async def upload_pcap(
    file: UploadFile = File(...),
    title: str = Form(None),
    auto_run: bool = Form(True),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # 1. Extension validation
    filename = file.filename or "capture.pcap"
    ext = filename.lower().split(".")[-1]
    if ext not in ("pcap", "pcapng", "cap"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file extension. Only .pcap, .pcapng, and .cap formats are accepted."
        )

    # 2. Save file temporarily with randomized UUID filename
    file_uuid = uuid.uuid4().hex
    saved_filename = f"{file_uuid}_{filename}"
    file_path = settings.UPLOAD_DIR / saved_filename

    total_bytes = 0
    with open(file_path, "wb") as buffer:
        while chunk := await file.read(65536):
            total_bytes += len(chunk)
            if total_bytes > settings.MAX_PCAP_SIZE_BYTES:
                buffer.close()
                if file_path.exists():
                    os.remove(file_path)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File exceeds maximum allowed size of {settings.MAX_PCAP_SIZE_MB} MB."
                )
            buffer.write(chunk)

    # 3. Structural Magic Bytes & Format Validation
    val_res = PCAPParser.validate_file(str(file_path), settings.MAX_PCAP_SIZE_BYTES)
    if not val_res["valid"]:
        if file_path.exists():
            os.remove(file_path)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Structural PCAP validation failed: {val_res.get('error')}"
        )

    # 4. Create Capture and Analysis DB Records
    capture = CaptureFile(
        original_filename=filename,
        stored_filename=saved_filename,
        file_path=str(file_path),
        file_size=val_res["size_bytes"],
        sha256_hash=val_res["sha256"],
        file_format=val_res["format"]
    )
    db.add(capture)
    db.flush()

    analysis_title = title or f"Analysis - {filename}"
    analysis = Analysis(
        title=analysis_title,
        status=AnalysisStatus.PENDING,
        capture_id=capture.id,
        user_id=current_user.id if current_user else None
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    # 5. Automatically execute analysis pipeline
    if auto_run:
        analysis = AnalysisService.run_analysis(db, analysis.id)

    return analysis
