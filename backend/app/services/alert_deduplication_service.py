import hashlib
from datetime import datetime, timedelta
from sqlalchemy import select, and_
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.config.settings import settings

class AlertDeduplicationService:
    """
    Handles alert deduplication fingerprinting and queries.
    """
    @staticmethod
    def calculate_deduplication_key(
        dataset: str,
        signal_status: str,
        attack_type: str | None,
        source_ip: str | None,
        destination_ip: str | None,
        protocol: str | None,
        priority: str
    ) -> str:
        """
        Generate a deterministic SHA256 fingerprint for deduplication.
        Handles null fields via canonical strings.
        """
        c_dataset = str(dataset).strip()
        c_signal = str(signal_status).strip()
        c_attack = str(attack_type).strip() if attack_type else "<none>"
        c_src = str(source_ip).strip() if source_ip else "<unknown>"
        c_dst = str(destination_ip).strip() if destination_ip else "<unknown>"
        c_proto = str(protocol).strip() if protocol else "<unknown>"
        c_priority = str(priority).strip()

        raw_str = f"{c_dataset}|{c_signal}|{c_attack}|{c_src}|{c_dst}|{c_proto}|{c_priority}"
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    @staticmethod
    def find_matching_active_alert(
        db: Session,
        deduplication_key: str
    ) -> Alert | None:
        """
        Search for an active alert (status in NEW, ACKNOWLEDGED, INVESTIGATING)
        sharing the same deduplication key within the configured time window.
        """
        window_seconds = settings.ALERT_DEDUPLICATION_WINDOW_SECONDS
        cutoff_time = datetime.now() - timedelta(seconds=window_seconds)

        active_statuses = ["NEW", "ACKNOWLEDGED", "INVESTIGATING"]

        # Run query
        stmt = select(Alert).where(
            and_(
                Alert.deduplication_key == deduplication_key,
                Alert.status.in_(active_statuses),
                Alert.updated_at >= cutoff_time
            )
        )
        result = db.execute(stmt)
        return result.scalars().first()
