import re
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from passlib.context import CryptContext
from backend.app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the hashed representation."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # Fallback to PBKDF2/SHA256 if bcrypt fails
        salt, h = hashed_password.split("$")[-2:]
        test_h = hashlib.pbkdf2_hmac("sha256", plain_password.encode(), salt.encode(), 100000).hex()
        return hmac.compare_digest(h, test_h)

def get_password_hash(password: str) -> str:
    """Generates a secure password hash."""
    try:
        return pwd_context.hash(password)
    except Exception:
        import os
        salt = os.urandom(16).hex()
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()
        return f"pbkdf2$100000${salt}${h}"

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except Exception:
        return None

# Privacy & Secret Redaction
SENSITIVE_PATTERNS = [
    re.compile(r'(?i)(password|passwd|pwd|psk|secret|key|private_key|authorization)\s*[:=]\s*["\']?([^"\'\s,]+)', re.IGNORECASE),
    re.compile(r'(?i)(bearer\s+)([A-Za-z0-9\-\._~\+\/]+=*)', re.IGNORECASE),
    re.compile(r'(?i)(-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----)', re.DOTALL),
]

def redact_sensitive_data(text: str) -> str:
    """Sanitizes sensitive information from logs and outputs per PRD Privacy-First requirement."""
    if not settings.REDACT_SENSITIVE_LOGS or not text:
        return text
    sanitized = text
    for pattern in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(r'\1: [REDACTED]', sanitized)
    return sanitized
