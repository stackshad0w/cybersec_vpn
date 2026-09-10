import enum
from sqlalchemy import Column, Integer, String, Float, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

class EvidenceStatus(str, enum.Enum):
    VERIFIED = "VERIFIED"
    POTENTIAL_INFERRED = "POTENTIAL_INFERRED"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"

class IPsecMode(str, enum.Enum):
    TUNNEL = "Tunnel"
    TRANSPORT = "Transport"
    UNKNOWN = "Unknown"

class IKESession(Base):
    __tablename__ = "ike_sessions"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)

    version = Column(String(20), default="IKEv2")  # IKEv1, IKEv2
    initiator_spi = Column(String(32), nullable=True)
    responder_spi = Column(String(32), nullable=True)
    
    # Cryptographic Suite
    encryption_algorithm = Column(String(64), nullable=True)
    integrity_algorithm = Column(String(64), nullable=True)
    prf_algorithm = Column(String(64), nullable=True)
    dh_group = Column(String(64), nullable=True)
    dh_group_number = Column(Integer, nullable=True)
    
    # Features & Properties
    pfs_enabled = Column(Boolean, default=False)
    pfs_status = Column(String(30), default=EvidenceStatus.NOT_OBSERVABLE)
    
    auth_method = Column(String(64), nullable=True)
    auth_status = Column(String(30), default=EvidenceStatus.POTENTIAL_INFERRED)
    
    nat_traversal_detected = Column(Boolean, default=False)
    nat_t_status = Column(String(30), default=EvidenceStatus.VERIFIED)
    
    sa_lifetime_seconds = Column(Integer, nullable=True)
    traffic_selectors = Column(Text, nullable=True)
    
    evidence = Column(Text, nullable=True)
    
    analysis = relationship("Analysis", back_populates="ike_sessions")

class IPsecSession(Base):
    __tablename__ = "ipsec_sessions"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)

    protocol = Column(String(10), default="ESP")  # ESP (50), AH (51)
    mode = Column(String(20), default=IPsecMode.UNKNOWN)
    mode_confidence = Column(Float, default=0.0)
    mode_evidence = Column(Text, nullable=True)
    
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)
    spi_inbound = Column(String(32), nullable=True)
    spi_outbound = Column(String(32), nullable=True)
    
    packet_count = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    
    # Replay Protection & Sequence Analysis
    replay_protection_enabled = Column(Boolean, default=True)
    replay_protection_status = Column(String(30), default=EvidenceStatus.VERIFIED)
    min_sequence_number = Column(Integer, default=1)
    max_sequence_number = Column(Integer, default=1)
    duplicate_sequences_count = Column(Integer, default=0)
    out_of_order_count = Column(Integer, default=0)
    
    analysis = relationship("Analysis", back_populates="ipsec_sessions")
