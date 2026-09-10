import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

class ReportType(str, enum.Enum):
    EXECUTIVE_PDF = "EXECUTIVE_PDF"
    TECHNICAL_PDF = "TECHNICAL_PDF"
    JSON = "JSON"

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)

    report_type = Column(Enum(ReportType), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, default=0)
    generated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    analysis = relationship("Analysis", back_populates="reports")
