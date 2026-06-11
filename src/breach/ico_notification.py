"""ICO Article 33 notification draft generator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.breach.timer import TimerStatus
from src.models.breach_model import BreachInput, ClassificationResult

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"


@dataclass
class DraftResult:
    """Generated ICO notification draft with validation warnings."""

    text: str
    warnings: list[str]
    completeness_percent: float


class ICONotificationGenerator:
    """Generates pre-filled ICO notification drafts from breach data."""

    def __init__(self, templates_dir: Path = TEMPLATES_DIR) -> None:
        self._env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(enabled_extensions=()),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(
        self,
        breach: BreachInput,
        classification: ClassificationResult,
        timer: TimerStatus,
        notification_datetime: datetime | None = None,
    ) -> DraftResult:
        """Render the ICO notification draft from validated breach data."""
        raise NotImplementedError("ICO notification generation not yet implemented.")

    def to_file(self, draft: DraftResult, output_path: Path) -> Path:
        """Write the notification draft to a .txt file."""
        raise NotImplementedError("ICO notification file write not yet implemented.")

    def _build_template_context(
        self,
        breach: BreachInput,
        classification: ClassificationResult,
        timer: TimerStatus,
        notification_datetime: datetime,
    ) -> dict:
        raise NotImplementedError

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(UTC)
