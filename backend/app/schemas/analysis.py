from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from backend.app.models.analysis import AnalysisStatus, RiskLevel
from backend.app.schemas.finding import SecurityFindingResponse
from backend.app.schemas.ipsec import IKESessionResponse, IPsecSessionResponse
from backend.app.schemas.ml import TrafficPredictionResponse
from backend.app.schemas.metadata import MetadataExposureResponse

class CaptureFileResponse(BaseModel):
    id: int
    original_filename: str
    file_size: int
    sha256_hash: str
    file_format: str
    packet_count: int
    duration_seconds: float
    uploaded_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AnalysisSummaryResponse(BaseModel):
    id: int
    title: str
    status: AnalysisStatus
    security_score: float
    risk_level: RiskLevel
    processing_time_seconds: float
    is_demo: int
    created_at: datetime
    completed_at: Optional[datetime] = None
    capture: Optional[CaptureFileResponse] = None

    model_config = ConfigDict(from_attributes=True)

class AnalysisDetailResponse(AnalysisSummaryResponse):
    error_message: Optional[str] = None
    ike_sessions: List[IKESessionResponse] = []
    ipsec_sessions: List[IPsecSessionResponse] = []
    findings: List[SecurityFindingResponse] = []
    traffic_prediction: Optional[TrafficPredictionResponse] = None
    metadata_exposure: Optional[MetadataExposureResponse] = None

    model_config = ConfigDict(from_attributes=True)
