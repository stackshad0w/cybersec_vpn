import os
import shutil
import uuid
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.config import settings, BASE_DIR
from backend.app.models.capture import CaptureFile
from backend.app.models.analysis import Analysis, AnalysisStatus
from backend.app.models.user import User
from backend.app.schemas.analysis import AnalysisDetailResponse
from backend.app.services.demo_service import DemoService
from backend.app.services.analysis_service import AnalysisService
from backend.app.analyzers.pcap_parser import PCAPParser
from backend.app.api.v1.deps import get_current_user

router = APIRouter(prefix="/demo", tags=["Demo Mode"])

TESTBED_DIR = BASE_DIR / "testbed" / "pcaps"

SCENARIOS = {
    "secure_ikev2": ("secure_ikev2_tunnel.pcap", "Secure IKEv2 Tunnel (AES-256-GCM, DH-19, PFS ON, Replay ON)"),
    "weak_ikev1": ("weak_ikev1_tunnel.pcap", "Legacy Weak IKEv1 Tunnel (3DES-CBC, MD5, DH-2, Replay Violations)"),
    "transport_gcm": ("transport_gcm.pcap", "Host-to-Host Transport Mode (AES-256-GCM, PFS ON)"),
    "demo_video": ("demo_target_video.pcap", "Enterprise Video VPN (PRD Target - Score 82, Video-like 91%)")
}

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

@router.post("/scenario/{scenario_name}", response_model=AnalysisDetailResponse)
def load_scenario(
    scenario_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes real-time forensic analysis on a selected testbed PCAP scenario:
    - secure_ikev2
    - weak_ikev1
    - transport_gcm
    - demo_video
    """
    if scenario_name not in SCENARIOS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{scenario_name}' not found. Available scenarios: {list(SCENARIOS.keys())}"
        )

    pcap_filename, title = SCENARIOS[scenario_name]
    src_file = TESTBED_DIR / pcap_filename
    if not src_file.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Testbed capture file '{pcap_filename}' not found on server."
        )

    dest_filename = f"{uuid.uuid4().hex}_{pcap_filename}"
    dest_path = settings.UPLOAD_DIR / dest_filename
    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src_file, dest_path)

    val_res = PCAPParser.validate_file(str(dest_path), settings.MAX_PCAP_SIZE_BYTES)
    capture = CaptureFile(
        original_filename=pcap_filename,
        stored_filename=dest_filename,
        file_path=str(dest_path),
        file_size=val_res["size_bytes"],
        sha256_hash=val_res["sha256"],
        file_format=val_res["format"]
    )
    db.add(capture)
    db.flush()

    user_id = current_user.id if current_user else None
    analysis = Analysis(
        title=f"Testbed: {title}",
        status=AnalysisStatus.PENDING,
        capture_id=capture.id,
        user_id=user_id,
        is_demo=0
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    analysis = AnalysisService.run_analysis(db, analysis.id)
    return analysis
