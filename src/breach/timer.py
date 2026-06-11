"""72-hour GDPR Article 33 breach notification countdown timer."""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum


class AlertLevel(str, Enum):
    """Timer alert bands aligned to the 72-hour notification window."""

    OK = "OK"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    EXPIRED = "EXPIRED"


@dataclass
class TimerStatus:
    """Fully computed timer state at the moment of evaluation."""

    breach_id: str
    detection_datetime: datetime
    current_datetime: datetime
    elapsed_hours: float
    remaining_hours: float
    elapsed_percentage: float
    alert_level: AlertLevel
    notification_deadline: datetime
    is_expired: bool
    requires_ico_notification: bool


class BreachTimer:
    """Manages the Article 33 72-hour notification countdown from breach detection."""

    NOTIFICATION_WINDOW_HOURS: int = 72
    WARNING_THRESHOLD_HOURS: int = 48
    CRITICAL_THRESHOLD_HOURS: int = 68
    LATE_DETECTION_WARNING_DAYS: int = 30

    def __init__(self, detection_datetime: datetime, breach_id: str) -> None:
        self.detection_datetime = self._validate_detection_datetime(detection_datetime)
        self.breach_id = self._validate_breach_id(breach_id)

    def get_status(self) -> TimerStatus:
        """Calculate current timer state from UTC now(). Pure — no side effects."""
        raise NotImplementedError("Timer status calculation not yet implemented.")

    def display(self) -> None:
        """Render a Rich terminal panel showing timer state."""
        raise NotImplementedError("Timer display not yet implemented.")

    def to_dict(self) -> dict:
        """Return a JSON-serialisable timer snapshot for the evidence log."""
        raise NotImplementedError("Timer serialisation not yet implemented.")

    @classmethod
    def _validate_detection_datetime(cls, detection_datetime: datetime) -> datetime:
        if detection_datetime.tzinfo is None:
            warnings.warn(
                "No timezone specified — assuming UTC. Verify this is correct.",
                UserWarning,
                stacklevel=2,
            )
            detection_datetime = detection_datetime.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        if detection_datetime > now:
            raise ValueError("Detection datetime cannot be in the future")

        if detection_datetime < now - timedelta(days=cls.LATE_DETECTION_WARNING_DAYS):
            warnings.warn(
                "Detection datetime is more than 30 days ago — verify this is correct.",
                UserWarning,
                stacklevel=2,
            )

        return detection_datetime

    @staticmethod
    def _validate_breach_id(breach_id: str) -> str:
        forbidden = ("/", "\\", "..", "\0")
        if any(char in breach_id for char in forbidden):
            raise ValueError(f"Invalid breach_id: {breach_id}")
        return breach_id
