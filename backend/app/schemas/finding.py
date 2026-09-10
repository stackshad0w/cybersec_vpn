from typing import Optional
from pydantic import BaseModel
from backend.app.models.finding import FindingSeverity, FindingCategory

class SecurityFindingResponse(BaseModel):
    id: int
    title: str
    category: FindingCategory
    severity: FindingSeverity
    evidence_status: str
    evidence: Optional[str] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    remediation_command: Optional[str] = None

    class Config:
        from_attributes = True
