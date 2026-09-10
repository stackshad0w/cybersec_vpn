import os
import time
from pathlib import Path
from backend.app.core.config import settings

class PrivacyGuard:
    """
    Enforces privacy compliance, payload protection, and file retention policies.
    """

    @classmethod
    def sanitize_log(cls, message: str) -> str:
        """Sanitizes text by redacting sensitive tokens."""
        from backend.app.core.security import redact_sensitive_data
        return redact_sensitive_data(message)

    @classmethod
    def cleanup_expired_captures(cls):
        """
        Removes uploaded capture files that exceed PCAP_RETENTION_MINUTES.
        """
        upload_dir = settings.UPLOAD_DIR
        if not upload_dir.exists():
            return

        now = time.time()
        retention_seconds = settings.PCAP_RETENTION_MINUTES * 60

        for item in upload_dir.glob("*"):
            if item.is_file():
                file_age = now - item.stat().st_mtime
                if file_age > retention_seconds:
                    try:
                        item.unlink()
                    except OSError:
                        pass
