from app.config.settings import settings

RISK_LEVEL_RANKS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

class AlertPolicyService:
    """
    Evaluates whether a Phase 5 UnifiedThreatAssessment matches configured alert policies.
    """
    @staticmethod
    def should_generate_alert(
        threat_score: float,
        risk_level: str,
        signal_status: str
    ) -> bool:
        """
        Evaluate logic:
        1. Validate against signal_status specific policy flags.
        2. Validate score AND risk level rank thresholds.
        """
        sig_lower = signal_status.lower()
        
        # 1. Check signal status specific exclusions
        if sig_lower == "normal":
            return False
        elif sig_lower == "anomaly_only" and not settings.ALERT_ON_ANOMALY_ONLY:
            return False
        elif sig_lower == "intrusion_only" and not settings.ALERT_ON_INTRUSION_ONLY:
            return False
        elif sig_lower == "confirmed_attack" and not settings.ALERT_ON_CONFIRMED_ATTACK:
            return False

        # 2. Check AND condition for score and risk level
        # Risk level threshold
        req_risk_rank = RISK_LEVEL_RANKS.get(settings.ALERT_MIN_RISK_LEVEL.lower(), 1)
        actual_risk_rank = RISK_LEVEL_RANKS.get(risk_level.lower(), 1)
        
        score_passes = (threat_score >= settings.ALERT_MIN_THREAT_SCORE)
        risk_passes = (actual_risk_rank >= req_risk_rank)
        
        return score_passes and risk_passes
