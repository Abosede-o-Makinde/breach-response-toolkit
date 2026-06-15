"""Article 33(3) evidence log — JSON + Markdown with completeness scoring."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src import __version__
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
        if entry.breach.breach_id != self.breach_id:
            raise ValueError(
                f"breach_id mismatch: expected {self.breach_id}, got {entry.breach.breach_id}"
            )

        score = self.completeness_score(entry)
        log_data = self._build_log_dict(entry, score)
        json_path = self._write_json(log_data)
        self._write_markdown(log_data)
        return json_path

    def update(self, field: str, value: Any) -> None:
        """Append a field update to the audit trail without overwriting history."""
        json_path = self._resolve_safe_path(self.output_dir, self.breach_id, "evidence_log.json")
        if not json_path.is_file():
            raise FileNotFoundError(f"Evidence log not found: {json_path}")

        with json_path.open(encoding="utf-8") as handle:
            log_data = json.load(handle)

        if field not in log_data.get("article_33_3_fields", {}):
            raise ValueError(f"Unknown Article 33(3) field: {field}")

        log_data["article_33_3_fields"][field] = value
        log_data["last_updated_utc"] = self._utcnow().isoformat()
        log_data.setdefault("audit_trail", []).append(
            {
                "timestamp_utc": self._utcnow().isoformat(),
                "action": f"FIELD_UPDATED: {field}",
                "actor": f"breach-response-toolkit v{__version__}",
            }
        )

        self._write_json(log_data)
        self._write_markdown(log_data)

    def render_markdown(self, log_data: dict) -> str:
        """Render the evidence log as Markdown via Jinja2 template."""
        env = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(default=False),
        )
        template = env.get_template("breach_log.md.j2")
        internal = log_data.get("internal_tracking", {})
        return template.render(
            breach_id=log_data["breach_id"],
            schema_version=log_data["schema_version"],
            created_utc=log_data["created_utc"],
            last_updated_utc=log_data["last_updated_utc"],
            completeness_percent=log_data["article_33_3_completeness_percent"],
            fields=log_data["article_33_3_fields"],
            internal={
                "detection_datetime_utc": internal.get("detection_datetime_utc", ""),
                "notification_deadline_utc": internal.get("notification_deadline_utc", ""),
                "severity_classification": internal.get("severity_classification", {}),
                "timer_snapshot": internal.get("timer_snapshot", {}),
                "nist_mapping": internal.get("nist_mapping", {}),
            },
            audit_trail=log_data.get("audit_trail", []),
        )

    def completeness_score(self, entry: EvidenceLogEntry) -> float:
        """Return 0–100 completeness based on Article 33(3) required fields."""
        present = sum(
            1 for field in self.ARTICLE_33_3_REQUIRED_FIELDS if self._is_field_present(entry, field)
        )
        return round((present / len(self.ARTICLE_33_3_REQUIRED_FIELDS)) * 100.0, 1)

    def validate_article_33_3(self, entry: EvidenceLogEntry) -> ValidationResult:
        """Validate all four Article 33(3) mandatory content fields."""
        missing = [
            field
            for field in self.ARTICLE_33_3_REQUIRED_FIELDS
            if not self._is_field_present(entry, field)
        ]
        score = self.completeness_score(entry)
        return ValidationResult(
            is_complete=not missing,
            completeness_percent=score,
            missing_fields=missing,
        )

    def _is_field_present(self, entry: EvidenceLogEntry, field: str) -> bool:
        breach = entry.breach
        if field == "description":
            return bool(breach.description and breach.description.strip())
        if field == "data_categories":
            return bool(breach.affected_data_categories)
        if field == "estimated_data_subjects":
            return breach.estimated_data_subjects > 0
        if field == "dpo_contact":
            dpo = breach.dpo_contact
            return bool(dpo.name.strip() and str(dpo.email).strip() and dpo.telephone.strip())
        if field == "likely_consequences":
            return bool(breach.likely_consequences)
        if field == "measures_taken":
            return bool(breach.measures_taken)
        return False

    def _write_json(self, log_data: dict) -> Path:
        target = self._resolve_safe_path(self.output_dir, self.breach_id, "evidence_log.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            json.dump(log_data, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        return target

    def _write_markdown(self, log_data: dict) -> Path:
        target = self._resolve_safe_path(self.output_dir, self.breach_id, "evidence_log.md")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.render_markdown(log_data), encoding="utf-8")
        return target

    def _build_log_dict(self, entry: EvidenceLogEntry, score: float) -> dict:
        breach = entry.breach
        now = self._utcnow().isoformat()
        deadline = (breach.detection_datetime + timedelta(hours=72)).isoformat()

        return {
            "breach_id": breach.breach_id,
            "schema_version": self.SCHEMA_VERSION,
            "created_utc": now,
            "last_updated_utc": now,
            "article_33_3_completeness_percent": score,
            "article_33_3_fields": {
                "a_nature_of_breach": {
                    "description": breach.description,
                    "root_cause": breach.root_cause,
                    "breach_type": breach.breach_type.value.upper(),
                    "categories_of_personal_data": breach.affected_data_categories,
                    "approximate_data_subjects": breach.estimated_data_subjects,
                    "approximate_records": breach.estimated_records,
                },
                "b_dpo_contact": breach.dpo_contact.model_dump(mode="json"),
                "c_likely_consequences": breach.likely_consequences,
                "d_measures_taken": breach.measures_taken,
            },
            "internal_tracking": {
                "detection_datetime_utc": breach.detection_datetime.isoformat(),
                "notification_deadline_utc": deadline,
                "controller_name": breach.controller_name,
                "ico_registration_number": breach.ico_registration_number,
                "timer_snapshot": entry.timer.to_dict(),
                "severity_classification": entry.classification.model_dump(mode="json"),
                "nist_mapping": self._nist_to_dict(entry.nist),
            },
            "audit_trail": [
                {
                    "timestamp_utc": now,
                    "action": "LOG_CREATED",
                    "actor": f"breach-response-toolkit v{__version__}",
                }
            ],
        }

    @staticmethod
    def _nist_to_dict(nist: NISTMappingResult) -> dict:
        return {
            "framework_reference": nist.framework_reference,
            "functions_impacted": [item.value for item in nist.functions_impacted],
            "failed_controls_count": len(nist.failed_controls),
            "top_failed_control": (
                f"{nist.failed_controls[0].subcategory} — {nist.failed_controls[0].description}"
                if nist.failed_controls
                else None
            ),
            "failed_controls": [
                {
                    "function": control.function.value,
                    "category": control.category,
                    "subcategory": control.subcategory,
                    "description": control.description,
                    "gdpr_article": control.gdpr_article,
                }
                for control in nist.failed_controls
            ],
            "recommended_controls": [
                {
                    "function": rec.function.value,
                    "category": rec.category,
                    "subcategory": rec.subcategory,
                    "recommendation": rec.recommendation,
                    "priority": rec.priority,
                    "gdpr_article": rec.gdpr_article,
                }
                for rec in nist.recommended_controls
            ],
        }

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(UTC)

    @staticmethod
    def _resolve_safe_path(output_dir: Path, breach_id: str, filename: str) -> Path:
        """Resolve output path and verify it stays within output_dir."""
        forbidden = ("/", "\\", "..", "\0")
        if any(char in breach_id for char in forbidden):
            raise ValueError(f"Invalid breach_id: {breach_id}")

        base = output_dir.resolve()
        target = (output_dir / breach_id / filename).resolve()
        if not str(target).startswith(str(base)):
            raise ValueError(f"Output path escapes output directory: {target}")
        return target
