import os
from pathlib import Path
from typing import List

# Base workspace directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent

class Settings:
    PROJECT_NAME: str = "AI-Powered IPsec VPN Analyzer"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1")
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'cybsec_vpn.db'}")
    
    # Security & JWT
    JWT_SECRET: str = os.getenv("JWT_SECRET", "super-secret-default-key-change-in-production-min-32-chars")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
    
    # Storage & Upload Limits
    MAX_PCAP_SIZE_MB: int = int(os.getenv("MAX_PCAP_SIZE_MB", "100"))
    MAX_PCAP_SIZE_BYTES: int = MAX_PCAP_SIZE_MB * 1024 * 1024
    PCAP_RETENTION_MINUTES: int = int(os.getenv("PCAP_RETENTION_MINUTES", "1440"))
    UPLOAD_DIR: Path = BASE_DIR / os.getenv("UPLOAD_DIR", "uploads")
    
    # AI/ML Model Path
    MODEL_PATH: Path = BASE_DIR / os.getenv("MODEL_PATH", "ml/models/random_forest_vpn_traffic.joblib")
    
    # Privacy & Auditing
    REDACT_SENSITIVE_LOGS: bool = os.getenv("REDACT_SENSITIVE_LOGS", "True").lower() in ("true", "1")
    ALLOW_EXTERNAL_AI_PAYLOADS: bool = False  # Strict PRD Privacy requirement
    
    # CORS
    CORS_ORIGINS: List[str] = ["*"]

settings = Settings()

# Ensure uploads directory exists
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
