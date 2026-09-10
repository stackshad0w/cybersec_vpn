from typing import Optional
from pydantic import BaseModel

class IKESessionResponse(BaseModel):
    id: int
    version: str
    initiator_spi: Optional[str] = None
    responder_spi: Optional[str] = None
    encryption_algorithm: Optional[str] = None
    integrity_algorithm: Optional[str] = None
    prf_algorithm: Optional[str] = None
    dh_group: Optional[str] = None
    dh_group_number: Optional[int] = None
    pfs_enabled: bool
    pfs_status: str
    auth_method: Optional[str] = None
    auth_status: str
    nat_traversal_detected: bool
    nat_t_status: str
    sa_lifetime_seconds: Optional[int] = None
    evidence: Optional[str] = None

    class Config:
        from_attributes = True

class IPsecSessionResponse(BaseModel):
    id: int
    protocol: str
    mode: str
    mode_confidence: float
    mode_evidence: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    spi_inbound: Optional[str] = None
    spi_outbound: Optional[str] = None
    packet_count: int
    total_bytes: int
    replay_protection_enabled: bool
    replay_protection_status: str
    duplicate_sequences_count: int
    out_of_order_count: int

    class Config:
        from_attributes = True
