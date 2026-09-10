import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Enum, ForeignKey, Text
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

class AnalysisStatus(str, enum.Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class RiskLevel(str, enum.Enum):
    EXCELLENT = "Excellent"
    GOOD = "Good"
    MODERATE = "Moderate"
    HIGH_RISK = "High Risk"
    CRITICAL = "Critical"

class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    status = Column(Enum(AnalysisStatus), default=AnalysisStatus.PENDING, index=True)
    security_score = Column(Float, default=0.0)  # 0 - 100
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.MODERATE)
    
    # Execution metrics
    processing_time_seconds = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)
    is_demo = Column(Integer, default=0) # 1 if generated from demo mode
    
    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    capture_id = Column(Integer, ForeignKey("captures.id"), nullable=True)

    owner = relationship("User", back_populates="analyses")
    capture = relationship("CaptureFile", back_populates="analysis")
    
    ipsec_sessions = relationship("IPsecSession", back_populates="analysis", cascade="all, delete-orphan")
    ike_sessions = relationship("IKESession", back_populates="analysis", cascade="all, delete-orphan")
    findings = relationship("SecurityFinding", back_populates="analysis", cascade="all, delete-orphan")
    traffic_prediction = relationship("TrafficPrediction", back_populates="analysis", uselist=False, cascade="all, delete-orphan")
    metadata_exposure = relationship("MetadataExposure", back_populates="analysis", uselist=False, cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="analysis", cascade="all, delete-orphan")
