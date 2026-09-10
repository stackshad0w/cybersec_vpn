from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    action = Column(String(100), nullable=False)  # e.g., USER_LOGIN, PCAP_UPLOAD, RUN_ANALYSIS, EXPORT_REPORT
    target_type = Column(String(50), nullable=True)
    target_id = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    details = Column(Text, nullable=True)  # Strictly redacted per Privacy-First design
    
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="audit_logs")
