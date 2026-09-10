from typing import Optional
from pydantic import BaseModel, ConfigDict

class MetadataExposureResponse(BaseModel):
    id: int
    endpoint_exposure_score: float
    timing_exposure_score: float
    packet_size_exposure_score: float
    volume_exposure_score: float
    ike_exposure_score: float
    overall_exposure_score: float
    endpoint_evidence: Optional[str] = None
    timing_evidence: Optional[str] = None
    packet_size_evidence: Optional[str] = None
    volume_evidence: Optional[str] = None
    ike_evidence: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
