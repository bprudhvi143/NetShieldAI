from sqlalchemy import select, and_, or_
from sqlalchemy.orm import Session
from app.models.incident import Incident
from app.models.alert import Alert

class AlertCorrelationService:
    """
    Service responsible for correlating alerts to active incidents.
    """
    @staticmethod
    def correlate_alert_to_incident(
        db: Session,
        dataset: str,
        source_ip: str | None,
        attack_type: str | None
    ) -> tuple[str, str | None, int | None]:
        """
        Runs hierarchical correlation logic:
        1. Strong: Same dataset + same source_ip + same attack_type
        2. Fallback: Same dataset + same source_ip (if attack_type is null or missing)
        Only correlates against active incidents (OPEN, INVESTIGATING, CONTAINED).
        Returns: (correlation_type, correlation_reason, incident_id)
        """
        if not source_ip:
            return "NONE", "No source IP available for correlation", None

        active_incident_statuses = ["OPEN", "INVESTIGATING", "CONTAINED"]

        # Step 1: Strong correlation (Dataset + Source IP + Attack Type)
        if attack_type:
            strong_stmt = (
                select(Incident)
                .join(Alert, Alert.incident_id == Incident.id)
                .where(
                    and_(
                        Incident.status.in_(active_incident_statuses),
                        Alert.dataset == dataset,
                        Alert.source_ip == source_ip,
                        Alert.attack_type == attack_type
                    )
                )
            )
            strong_res = db.execute(strong_stmt).scalars().first()
            if strong_res:
                reason = f"Correlated with active incident #{strong_res.id} matching dataset={dataset}, source_ip={source_ip}, and attack_type={attack_type}."
                return "SAME_SOURCE_ATTACK", reason, strong_res.id

        # Step 2: Fallback correlation (Dataset + Source IP)
        fallback_stmt = (
            select(Incident)
            .join(Alert, Alert.incident_id == Incident.id)
            .where(
                and_(
                    Incident.status.in_(active_incident_statuses),
                    Alert.dataset == dataset,
                    Alert.source_ip == source_ip
                )
            )
        )
        fallback_res = db.execute(fallback_stmt).scalars().first()
        if fallback_res:
            reason = f"Correlated with active incident #{fallback_res.id} matching dataset={dataset} and source_ip={source_ip} (fallback)."
            return "SAME_SOURCE", reason, fallback_res.id

        return "NONE", "No active incident matched correlation criteria", None
