"""ICO Article 33 notification draft generator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.breach.timer import TimerStatus
from src.models.breach_model import BreachInput, ClassificationResult

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"

REQUIRED_FIELD_REFERENCES: dict[str, str] = {
    "description": "Article 33(3)(a) — nature of the breach",
    "data_categories": "Article 33(3)(a) — categories of personal data",
    "estimated_data_subjects": "Article 33(3)(a) — approximate number of data subjects",
    "dpo_contact": "Article 33(3)(b) — contact point",
    "likely_consequences": "Article 33(3)(c) — likely consequences",
    "measures_taken": "Article 33(3)(d) — measures taken or proposed",
    "controller_name": "Controller identification",
    "controller_address": "Controller identification",
}


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
        notify_at = notification_datetime or self._utcnow()
        if notify_at.tzinfo is None:
            notify_at = notify_at.replace(tzinfo=UTC)

        completeness, warnings = self._validate_completeness(breach)
        context = self._build_template_context(breach, classification, timer, notify_at)
        template = self._env.get_template("ico_notification.j2")
        text = template.render(**context)

        return DraftResult(
            text=text,
            warnings=warnings,
            completeness_percent=completeness,
        )

    def to_file(self, draft: DraftResult, output_path: Path) -> Path:
        """Write the notification draft to a .txt file."""
        target = output_path.resolve()
        base = output_path.parent.resolve()
        if not str(target).startswith(str(base)):
            raise ValueError(f"Output path escapes output directory: {target}")

        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(draft.text, encoding="utf-8")
        return target

    def _build_template_context(
        self,
        breach: BreachInput,
        classification: ClassificationResult,
        timer: TimerStatus,
        notification_datetime: datetime,
    ) -> dict:
        return {
            "generation_datetime": self._utcnow().isoformat(),
            "breach_id": breach.breach_id,
            "controller_name": breach.controller_name,
            "ico_reg_number": breach.ico_registration_number or "Not provided",
            "controller_address": breach.controller_address,
            "dpo_name": breach.dpo_contact.name,
            "dpo_role": breach.dpo_contact.role,
            "dpo_email": str(breach.dpo_contact.email),
            "dpo_telephone": breach.dpo_contact.telephone,
            "breach_type": breach.breach_type.value.upper(),
            "description": breach.description,
            "root_cause": breach.root_cause.strip() or None,
            "detection_datetime": breach.detection_datetime.isoformat(),
            "notification_datetime": notification_datetime.isoformat(),
            "elapsed_hours": f"{timer.elapsed_hours:.2f}",
            "data_categories": breach.affected_data_categories,
            "estimated_data_subjects": breach.estimated_data_subjects,
            "estimated_records": breach.estimated_records,
            "encrypted": breach.data_encrypted,
            "special_category": breach.special_category_involved,
            "likely_consequences": breach.likely_consequences,
            "measures_taken": breach.measures_taken,
            "severity": classification.severity.value,
            "ico_required": classification.ico_notification_required,
            "subject_required": classification.subject_notification_required,
        }

    def _validate_completeness(self, breach: BreachInput) -> tuple[float, list[str]]:
        checks = {
            "description": bool(breach.description and breach.description.strip()),
            "data_categories": bool(breach.affected_data_categories),
            "estimated_data_subjects": breach.estimated_data_subjects > 0,
            "dpo_contact": bool(
                breach.dpo_contact.name.strip()
                and str(breach.dpo_contact.email).strip()
                and breach.dpo_contact.telephone.strip()
            ),
            "likely_consequences": bool(breach.likely_consequences),
            "measures_taken": bool(breach.measures_taken),
            "controller_name": bool(breach.controller_name.strip()),
            "controller_address": bool(breach.controller_address.strip()),
        }

        present = sum(1 for value in checks.values() if value)
        completeness = round((present / len(checks)) * 100.0, 1)
        warnings = [
            f"{REQUIRED_FIELD_REFERENCES[field]} is missing or incomplete"
            for field, ok in checks.items()
            if not ok
        ]
        return completeness, warnings

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(UTC)
