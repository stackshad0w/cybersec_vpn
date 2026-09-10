from datetime import datetime
from pydantic import BaseModel
from backend.app.models.report import ReportType

class ReportResponse(BaseModel):
    id: int
    report_type: ReportType
    file_path: str
    file_size: int
    generated_at: datetime

    class Config:
        from_attributes = True
