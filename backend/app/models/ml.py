from sqlalchemy import Column, Integer, String, Float, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

class TrafficPrediction(Base):
    __tablename__ = "traffic_predictions"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)

    predicted_class = Column(String(50), nullable=False)  # ICMP-like, Web-like, VoIP-like, Video-like, Email-like, Other
    confidence_score = Column(Float, nullable=False)  # 0.0 - 1.0 (e.g. 0.91 for 91%)
    secondary_class = Column(String(50), nullable=True)
    secondary_confidence = Column(Float, nullable=True)
    
    # Explainability & Feature importance summary
    explanation = Column(Text, nullable=True)
    
    # Statistical Feature Vector (stored as JSON string for forensic audit)
    features_json = Column(Text, nullable=False)
    
    # Aggregate metrics
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    flow_duration = Column(Float, default=0.0)
    packets_per_sec = Column(Float, default=0.0)
    bytes_per_sec = Column(Float, default=0.0)
    mean_packet_size = Column(Float, default=0.0)
    upload_download_ratio = Column(Float, default=0.0)
    burst_rate = Column(Float, default=0.0)
    
    # Anomaly Detection Output
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float, default=0.0)
    anomaly_evidence = Column(Text, nullable=True)

    analysis = relationship("Analysis", back_populates="traffic_prediction")
