"""72-hour GDPR Article 33 breach notification countdown timer."""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
        now = datetime.now(UTC)
        elapsed_hours = (now - self.detection_datetime).total_seconds() / 3600
        remaining_hours = max(0.0, self.NOTIFICATION_WINDOW_HOURS - elapsed_hours)
        elapsed_pct = min(100.0, (elapsed_hours / self.NOTIFICATION_WINDOW_HOURS) * 100)

        if elapsed_hours >= self.NOTIFICATION_WINDOW_HOURS:
            alert_level = AlertLevel.EXPIRED
        elif elapsed_hours >= self.CRITICAL_THRESHOLD_HOURS:
            alert_level = AlertLevel.CRITICAL
        elif elapsed_hours >= self.WARNING_THRESHOLD_HOURS:
            alert_level = AlertLevel.WARNING
        else:
            alert_level = AlertLevel.OK

        return TimerStatus(
            breach_id=self.breach_id,
            detection_datetime=self.detection_datetime,
            current_datetime=now,
            elapsed_hours=round(elapsed_hours, 2),
            remaining_hours=round(remaining_hours, 2),
            elapsed_percentage=round(elapsed_pct, 1),
            alert_level=alert_level,
            notification_deadline=self.detection_datetime
            + timedelta(hours=self.NOTIFICATION_WINDOW_HOURS),
            is_expired=elapsed_hours >= self.NOTIFICATION_WINDOW_HOURS,
            requires_ico_notification=True,
        )

    def display(self) -> None:
        """Render a Rich terminal panel showing timer state."""
        from rich.panel import Panel
        from rich.progress import BarColumn, Progress, TextColumn
        from rich.table import Table

        status = self.get_status()
        colour_map = {
            AlertLevel.OK: "green",
            AlertLevel.WARNING: "yellow",
            AlertLevel.CRITICAL: "red",
            AlertLevel.EXPIRED: "bright_red",
        }
        alert_messages = {
            AlertLevel.OK: "Within notification window — continue evidence gathering.",
            AlertLevel.WARNING: "48 hours elapsed — escalate to DPO and prepare ICO notification.",
            AlertLevel.CRITICAL: "68 hours elapsed — submit ICO notification immediately.",
            AlertLevel.EXPIRED: "72-hour window exceeded — notify ICO without delay and document late submission.",
        }
        colour = colour_map[status.alert_level]

        table = Table.grid(padding=(0, 1))
        table.add_row("Breach ID:", status.breach_id)
        table.add_row("Detected (UTC):", status.detection_datetime.isoformat())
        table.add_row("Elapsed:", f"{status.elapsed_hours:.2f} hours")
        table.add_row("Remaining:", f"{status.remaining_hours:.2f} hours")
        table.add_row("Deadline (UTC):", status.notification_deadline.isoformat())
        table.add_row("Status:", f"[{colour}]{status.alert_level.value}[/{colour}]")
        table.add_row("", alert_messages[status.alert_level])

        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, complete_style=colour, finished_style=colour),
            TextColumn("{task.percentage:>3.0f}%"),
        )
        progress.add_task("Window elapsed", total=100, completed=status.elapsed_percentage)

        from rich.console import Console

        console = Console()
        console.print(
            Panel(
                table,
                title="GDPR ARTICLE 33 — BREACH TIMER",
                border_style=colour,
            )
        )
        console.print(progress)

    def to_dict(self) -> dict:
        """Return a JSON-serialisable timer snapshot for the evidence log."""
        status = self.get_status()
        return {
            "elapsed_hours": status.elapsed_hours,
            "remaining_hours": status.remaining_hours,
            "elapsed_percentage": status.elapsed_percentage,
            "alert_level": status.alert_level.value,
            "notification_deadline": status.notification_deadline.isoformat(),
            "is_expired": status.is_expired,
            "snapshot_utc": status.current_datetime.isoformat(),
        }

    @classmethod
    def _validate_detection_datetime(cls, detection_datetime: datetime) -> datetime:
        if detection_datetime.tzinfo is None:
            warnings.warn(
                "No timezone specified — assuming UTC. Verify this is correct.",
                UserWarning,
                stacklevel=2,
            )
            detection_datetime = detection_datetime.replace(tzinfo=UTC)

        now = datetime.now(UTC)
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
