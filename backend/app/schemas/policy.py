from typing import List, Dict
from pydantic import BaseModel, Field

class RiskWeightsConfig(BaseModel):
    cryptography: float = Field(0.25, ge=0.0, le=1.0)
    key_exchange: float = Field(0.15, ge=0.0, le=1.0)
    authentication: float = Field(0.15, ge=0.0, le=1.0)
    pfs: float = Field(0.15, ge=0.0, le=1.0)
    replay_protection: float = Field(0.10, ge=0.0, le=1.0)
    sa_configuration: float = Field(0.10, ge=0.0, le=1.0)
    protocol: float = Field(0.05, ge=0.0, le=1.0)
    metadata_exposure: float = Field(0.05, ge=0.0, le=1.0)

class SecurityPolicyConfig(BaseModel):
    policy_name: str = "Standard Enterprise Baseline"
    allowed_ciphers: List[str] = ["AES-256-GCM", "AES-128-GCM", "AES-256-CBC", "CHACHA20-POLY1305"]
    allowed_integrity: List[str] = ["HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512", "AEAD"]
    min_dh_group: int = 14  # Min 2048-bit MODP or ECP
    require_pfs: bool = True
    require_ikev2: bool = True
    max_sa_lifetime_seconds: int = 28800  # 8 hours
    weights: RiskWeightsConfig = RiskWeightsConfig()
