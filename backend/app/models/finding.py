import enum
from sqlalchemy import Column, Integer, String, ForeignKey, Text, Enum
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

class FindingSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingCategory(str, enum.Enum):
    CRYPTOGRAPHY = "CRYPTOGRAPHY"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    AUTHENTICATION = "AUTHENTICATION"
    PFS = "PFS"
    REPLAY_PROTECTION = "REPLAY_PROTECTION"
    SA_LIFETIME = "SA_LIFETIME"
    PROTOCOL = "PROTOCOL"
    METADATA_LEAK = "METADATA_LEAK"

class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)

    title = Column(String(255), nullable=False)
    category = Column(Enum(FindingCategory), nullable=False)
    severity = Column(Enum(FindingSeverity), nullable=False)
    
    evidence_status = Column(String(30), default="VERIFIED")  # VERIFIED, POTENTIAL_INFERRED, NOT_OBSERVABLE
    evidence = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    remediation_command = Column(Text, nullable=True)

    analysis = relationship("Analysis", back_populates="findings")
