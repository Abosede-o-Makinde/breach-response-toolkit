"""Tests for src/reporter/pdf_report.py — target: >=75% coverage."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from freezegun import freeze_time

from src.breach.classifier import BreachClassifier
from src.breach.evidence_log import EvidenceLog, EvidenceLogEntry
from src.breach.ico_notification import ICONotificationGenerator
from src.breach.nist_mapper import NISTMapper
from src.breach.timer import BreachTimer
from src.models.breach_model import BreachInput, SeverityLevel
from src.models.report_model import (
    BreachReportData,
    EvidenceLogSummary,
    NISTMappingSummary,
    OutputPaths,
    TimerSnapshot,
)
from src.reporter.pdf_report import BreachReportGenerator

DETECTION = datetime(2024, 6, 9, 14, 30, 0, tzinfo=UTC)
FROZEN_NOW = datetime(2024, 6, 9, 18, 30, 0, tzinfo=UTC)


def _build_report_data(breach: BreachInput) -> BreachReportData:
    breach = breach.model_copy(update={"detection_datetime": DETECTION})
    with freeze_time(FROZEN_NOW):
        timer = BreachTimer(breach.detection_datetime, breach.breach_id)
        timer_status = timer.get_status()
        classification = BreachClassifier().classify(breach)
        nist = NISTMapper().map_breach(
            breach.breach_type,
            breach.data_type,
            classification.severity,
        )
        entry = EvidenceLogEntry(
            breach=breach,
            timer=timer,
            classification=classification,
            nist=nist,
        )
        evidence_log = EvidenceLog(breach.breach_id, Path("outputs"))
        validation = evidence_log.validate_article_33_3(entry)
        ico_draft = ICONotificationGenerator().generate(breach, classification, timer_status)

    nist_dict = evidence_log._nist_to_dict(nist)
    base = Path("outputs") / breach.breach_id
    return BreachReportData(
        breach=breach,
        generated_at_utc=FROZEN_NOW,
        timer=TimerSnapshot(
            elapsed_hours=timer_status.elapsed_hours,
            remaining_hours=timer_status.remaining_hours,
            elapsed_percentage=timer_status.elapsed_percentage,
            alert_level=timer_status.alert_level.value,
            notification_deadline=timer_status.notification_deadline,
            is_expired=timer_status.is_expired,
            snapshot_utc=timer_status.current_datetime,
        ),
        classification=classification,
        nist_mapping=NISTMappingSummary(
            framework_reference=nist.framework_reference,
            functions_impacted=[item.value for item in nist.functions_impacted],
            failed_controls_count=len(nist.failed_controls),
            top_failed_control=nist_dict["top_failed_control"] or "None",
            failed_controls=nist_dict["failed_controls"],
            recommended_controls=nist_dict["recommended_controls"],
        ),
        evidence_log=EvidenceLogSummary(
            article_33_3_completeness_percent=validation.completeness_percent,
            missing_fields=validation.missing_fields,
        ),
        ico_notification_text=ico_draft.text,
        outputs=OutputPaths(
            evidence_log_json=str(base / "evidence_log.json"),
            evidence_log_md=str(base / "evidence_log.md"),
            ico_notification=str(base / "ico_notification.txt"),
            pdf_report=str(base / "breach_report.pdf"),
        ),
    )


class TestBreachReportGenerator:
    def test_generate_creates_pdf_file(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        report_data = _build_report_data(sample_breach_input)
        output_path = tmp_output_dir / sample_breach_input.breach_id / "breach_report.pdf"
        written = BreachReportGenerator().generate(report_data, output_path)
        assert written.is_file()
        assert written.stat().st_size > 1000

    def test_pdf_starts_with_pdf_header(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        report_data = _build_report_data(sample_breach_input)
        output_path = tmp_output_dir / "breach_report.pdf"
        BreachReportGenerator().generate(report_data, output_path)
        assert output_path.read_bytes()[:4] == b"%PDF"

    def test_pdf_is_multi_page_document(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        report_data = _build_report_data(sample_breach_input)
        output_path = tmp_output_dir / "breach_report.pdf"
        BreachReportGenerator().generate(report_data, output_path)
        raw = output_path.read_bytes()
        assert b"/Type /Pages" in raw
        assert b"/Count 7" in raw

    def test_generate_creates_parent_directories(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        report_data = _build_report_data(sample_breach_input)
        output_path = tmp_output_dir / "nested" / "reports" / "breach_report.pdf"
        BreachReportGenerator().generate(report_data, output_path)
        assert output_path.is_file()

    @pytest.mark.parametrize("severity", list(SeverityLevel))
    def test_all_severity_levels_generate_without_error(
        self,
        sample_breach_input: BreachInput,
        tmp_output_dir: Path,
        severity: SeverityLevel,
    ) -> None:
        from src.models.breach_model import ClassificationResult, ScoreBreakdown

        report_data = _build_report_data(sample_breach_input)
        patched = report_data.model_copy(
            update={
                "classification": ClassificationResult(
                    severity=severity,
                    score=80.0,
                    breakdown=ScoreBreakdown(
                        data_type_score=30,
                        scale_score=20,
                        special_category_bonus=0,
                        encryption_reduction=0,
                        total=50,
                    ),
                    ico_notification_required=True,
                    subject_notification_required=severity == SeverityLevel.CRITICAL,
                    reasoning="Test reasoning for PDF severity badge rendering across all bands.",
                    recommended_actions=["Action one", "Action two"],
                )
            }
        )
        output_path = tmp_output_dir / f"report_{severity.value}.pdf"
        BreachReportGenerator().generate(patched, output_path)
        assert output_path.is_file()
