import time
import os
import sys
from pathlib import Path

# Ensure root in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from backend.app.core.database import SessionLocal
from backend.app.models.analysis import Analysis, AnalysisStatus
from backend.app.services.analysis_service import AnalysisService

def poll_and_process():
    """
    Background worker loop that processes queued analyses.
    Can be used standalone or scaled alongside Redis.
    """
    print("[Worker] CyberSec VPN Analyzer background task worker started.")
    while True:
        db = SessionLocal()
        try:
            pending_job = db.query(Analysis).filter(Analysis.status == AnalysisStatus.PENDING).first()
            if pending_job:
                print(f"[Worker] Picked up Analysis #{pending_job.id}: {pending_job.title}")
                try:
                    AnalysisService.run_analysis(db, pending_job.id)
                    print(f"[Worker] Analysis #{pending_job.id} completed successfully.")
                except Exception as e:
                    print(f"[Worker] Analysis #{pending_job.id} failed with error: {e}")
            else:
                time.sleep(2)
        except Exception as err:
            print(f"[Worker] Unexpected error in polling loop: {err}")
            time.sleep(5)
        finally:
            db.close()

if __name__ == "__main__":
    poll_and_process()
