from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, BigInteger, DateTime, Float
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

class CaptureFile(Base):
    __tablename__ = "captures"

    id = Column(Integer, primary_key=True, index=True)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False, unique=True)
    file_path = Column(String(512), nullable=False)
    file_size = Column(BigInteger, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    file_format = Column(String(20), nullable=False)  # pcap, pcapng
    packet_count = Column(Integer, default=0)
    duration_seconds = Column(Float, default=0.0)
    uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    analysis = relationship("Analysis", back_populates="capture", uselist=False)
