"""Article 33(3) evidence log — JSON + Markdown with completeness scoring."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.breach.nist_mapper import NISTMappingResult
from src.breach.timer import BreachTimer
from src.models.breach_model import BreachInput, ClassificationResult

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"


@dataclass
class EvidenceLogEntry:
    """All fields required to create an Article 33(3) evidence log."""

    breach: BreachInput
    timer: BreachTimer
    classification: ClassificationResult
    nist: NISTMappingResult


@dataclass
class ValidationResult:
    """Result of Article 33(3) field validation."""

    is_complete: bool
    completeness_percent: float
    missing_fields: list[str]


class EvidenceLog:
    """Creates and maintains append-only breach evidence logs."""

    ARTICLE_33_3_REQUIRED_FIELDS: list[str] = [
        "description",
        "data_categories",
        "estimated_data_subjects",
        "dpo_contact",
        "likely_consequences",
        "measures_taken",
    ]
    COMPLETENESS_WEIGHT_PER_FIELD: float = 100.0 / len(ARTICLE_33_3_REQUIRED_FIELDS)
    SCHEMA_VERSION: str = "1.0"

    def __init__(self, breach_id: str, output_dir: Path) -> None:
        self.breach_id = breach_id
        self.output_dir = output_dir

    def create(self, entry: EvidenceLogEntry) -> Path:
        """Write evidence_log.json and evidence_log.md for a new breach."""
        raise NotImplementedError("Evidence log creation not yet implemented.")

    def update(self, field: str, value: Any) -> None:
        """Append a field update to the audit trail without overwriting history."""
        raise NotImplementedError("Evidence log update not yet implemented.")

    def render_markdown(self, log_data: dict) -> str:
        """Render the evidence log as Markdown via Jinja2 template."""
        raise NotImplementedError("Markdown rendering not yet implemented.")

    def completeness_score(self, entry: EvidenceLogEntry) -> float:
        """Return 0–100 completeness based on Article 33(3) required fields."""
        raise NotImplementedError("Completeness scoring not yet implemented.")

    def validate_article_33_3(self, entry: EvidenceLogEntry) -> ValidationResult:
        """Validate all four Article 33(3) mandatory content fields."""
        raise NotImplementedError("Article 33(3) validation not yet implemented.")

    def _write_json(self, log_data: dict) -> Path:
        raise NotImplementedError

    def _write_markdown(self, log_data: dict) -> Path:
        raise NotImplementedError

    def _build_log_dict(self, entry: EvidenceLogEntry, score: float) -> dict:
        raise NotImplementedError

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(UTC)

    @staticmethod
    def _resolve_safe_path(output_dir: Path, breach_id: str, filename: str) -> Path:
        """Resolve output path and verify it stays within output_dir."""
        target = (output_dir / breach_id / filename).resolve()
        base = output_dir.resolve()
        if not str(target).startswith(str(base)):
            raise ValueError(f"Output path escapes output directory: {target}")
        return target
