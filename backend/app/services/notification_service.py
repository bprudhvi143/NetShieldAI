import logging
from app.schemas.notification import NotificationPayload

logger = logging.getLogger("app.services.notification")

class NotificationService:
    """
    Service responsible for formatting and routing security events to channels.
    In Phase 6, events are routed to application logs.
    """
    @staticmethod
    def dispatch_notification(payload: NotificationPayload) -> None:
        """
        Log the structured notification event payload.
        """
        # Log structured JSON-like text
        logger.info(
            f"[Notification System] Type: {payload.event_type} | Title: {payload.title} | "
            f"Severity: {payload.severity} | Priority: {payload.priority} | "
            f"Risk Level: {payload.risk_level} | Threat Score: {payload.threat_score} | "
            f"Signal Status: {payload.signal_status} | Attack Type: {payload.attack_type} | "
            f"Source IP: {payload.source_ip} | Destination IP: {payload.destination_ip} | "
            f"Summary: {payload.summary} | Reasons: {payload.reasons}"
        )
