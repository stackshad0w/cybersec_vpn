from fastapi import APIRouter, Depends
from backend.app.schemas.policy import SecurityPolicyConfig, RiskWeightsConfig
from backend.app.models.user import User, UserRole
from backend.app.api.v1.deps import get_current_user, require_roles

router = APIRouter(prefix="/policies", tags=["Security Policies & Risk Weights"])

# In-memory policy state (or persisted to config/DB)
CURRENT_POLICY = SecurityPolicyConfig()

@router.get("", response_model=SecurityPolicyConfig)
def get_security_policy(current_user: User = Depends(get_current_user)):
    """Returns current active security policy and risk weight configurations."""
    return CURRENT_POLICY

@router.put("", response_model=SecurityPolicyConfig)
def update_security_policy(
    policy_update: SecurityPolicyConfig,
    current_user: User = Depends(require_roles([UserRole.ADMIN]))
):
    """Updates security policy thresholds and category weights (Admin only)."""
    global CURRENT_POLICY
    CURRENT_POLICY = policy_update
    return CURRENT_POLICY
