from sqlalchemy import Column, Integer, Float, ForeignKey, Text
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

class MetadataExposure(Base):
    __tablename__ = "metadata_exposure"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)

    # Individual dimension exposure scores: 0 (No Exposure) to 100 (Full Exposure)
    endpoint_exposure_score = Column(Float, default=0.0)
    timing_exposure_score = Column(Float, default=0.0)
    packet_size_exposure_score = Column(Float, default=0.0)
    volume_exposure_score = Column(Float, default=0.0)
    ike_exposure_score = Column(Float, default=0.0)
    
    # Aggregate Exposure Index: 0 to 100
    overall_exposure_score = Column(Float, default=0.0)

    # Detailed forensic evidence
    endpoint_evidence = Column(Text, nullable=True)
    timing_evidence = Column(Text, nullable=True)
    packet_size_evidence = Column(Text, nullable=True)
    volume_evidence = Column(Text, nullable=True)
    ike_evidence = Column(Text, nullable=True)

    analysis = relationship("Analysis", back_populates="metadata_exposure")
