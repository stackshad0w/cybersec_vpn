from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict

class TrafficPredictionResponse(BaseModel):
    id: int
    predicted_class: str
    confidence_score: float
    secondary_class: Optional[str] = None
    secondary_confidence: Optional[float] = None
    explanation: Optional[str] = None
    packet_count: int
    byte_count: int
    flow_duration: float
    packets_per_sec: float
    bytes_per_sec: float
    mean_packet_size: float
    upload_download_ratio: float
    burst_rate: float
    is_anomaly: bool
    anomaly_score: float
    anomaly_evidence: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class FeatureMetricsResponse(BaseModel):
    features: Dict[str, Any]
    feature_importance: Dict[str, float]
