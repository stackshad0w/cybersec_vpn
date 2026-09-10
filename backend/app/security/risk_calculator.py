from typing import Dict, Any, List, Tuple
from backend.app.models.analysis import RiskLevel
from backend.app.security.rules_engine import RuleResult
from backend.app.schemas.policy import RiskWeightsConfig

class RiskCalculator:
    """
    Computes overall normalized security score (0 - 100) and assigns risk levels.
    Supports organization-configurable weights across 8 core dimensions.
    """

    @classmethod
    def calculate_score(
        cls,
        eval_results: Dict[str, RuleResult],
        weights: RiskWeightsConfig = RiskWeightsConfig()
    ) -> Tuple[float, RiskLevel, Dict[str, float]]:
        weights_dict = {
            "cryptography": weights.cryptography,
            "key_exchange": weights.key_exchange,
            "authentication": weights.authentication,
            "pfs": weights.pfs,
            "replay_protection": weights.replay_protection,
            "sa_configuration": weights.sa_configuration,
            "protocol": weights.protocol,
            "metadata_exposure": weights.metadata_exposure,
        }

        total_weight = sum(weights_dict.values())
        if total_weight <= 0:
            total_weight = 1.0

        dimension_scores = {}
        weighted_sum = 0.0

        for dim, weight in weights_dict.items():
            res = eval_results.get(dim)
            dim_score = res.score if res else 70.0
            dimension_scores[dim] = round(dim_score, 1)
            weighted_sum += (dim_score * (weight / total_weight))

        final_score = round(weighted_sum, 1)

        # Classify Risk Level
        if final_score >= 85.0:
            risk_level = RiskLevel.EXCELLENT
        elif final_score >= 70.0:
            risk_level = RiskLevel.GOOD
        elif final_score >= 50.0:
            risk_level = RiskLevel.MODERATE
        elif final_score >= 30.0:
            risk_level = RiskLevel.HIGH_RISK
        else:
            risk_level = RiskLevel.CRITICAL

        return final_score, risk_level, dimension_scores
