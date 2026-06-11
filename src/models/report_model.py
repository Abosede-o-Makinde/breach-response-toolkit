"""Aggregated report payload for PDF generation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from src.models.breach_model import BreachInput, ClassificationResult


class TimerSnapshot(BaseModel):
    """Serialised timer state for reports and evidence logs."""

    elapsed_hours: float
    remaining_hours: float
    elapsed_percentage: float
    alert_level: str
    notification_deadline: datetime
    is_expired: bool
    snapshot_utc: datetime


class NISTMappingSummary(BaseModel):
    """Summary of NIST CSF mapping for report output."""

    framework_reference: str
    functions_impacted: list[str]
    failed_controls_count: int
    top_failed_control: str
    failed_controls: list[dict[str, Any]] = Field(default_factory=list)
    recommended_controls: list[dict[str, Any]] = Field(default_factory=list)


class EvidenceLogSummary(BaseModel):
    """Evidence log completeness summary for reports."""

    article_33_3_completeness_percent: float
    missing_fields: list[str] = Field(default_factory=list)


class OutputPaths(BaseModel):
    """Paths to generated artefact files."""

    evidence_log_json: str
    evidence_log_md: str
    ico_notification: str
    pdf_report: str


class BreachReportData(BaseModel):
    """Full aggregated payload passed to the PDF report generator."""

    breach: BreachInput
    generated_at_utc: datetime
    schema_version: str = "1.0"
    timer: TimerSnapshot
    classification: ClassificationResult
    nist_mapping: NISTMappingSummary
    evidence_log: EvidenceLogSummary
    ico_notification_text: str
    outputs: OutputPaths
