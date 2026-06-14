"""Full breach report pipeline orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from src.breach.classifier import BreachClassifier
from src.breach.evidence_log import EvidenceLog, EvidenceLogEntry, ValidationResult
from src.breach.ico_notification import ICONotificationGenerator
from src.breach.nist_mapper import NISTMapper, NISTMappingResult
from src.breach.timer import BreachTimer, TimerStatus
from src.models.breach_model import BreachInput, ClassificationResult
from src.models.report_model import (
    BreachReportData,
    EvidenceLogSummary,
    NISTMappingSummary,
    OutputPaths,
    TimerSnapshot,
)
from src.reporter.pdf_report import BreachReportGenerator


@dataclass
class PipelineResult:
    """Result of a full --mode report pipeline run."""

    breach_id: str
    report_data: BreachReportData
    output_paths: OutputPaths
    ico_warnings: list[str] = field(default_factory=list)


class BreachReportPipeline:
    """
    Orchestrates the five-module breach response pipeline:

    timer → classifier → NIST mapper → evidence log → ICO draft → PDF report
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.timer_module = BreachTimer
        self.classifier = BreachClassifier()
        self.nist_mapper = NISTMapper()
        self.evidence_log = EvidenceLog
        self.ico_generator = ICONotificationGenerator()
        self.pdf_generator = BreachReportGenerator()

    def run(self, breach: BreachInput) -> PipelineResult:
        """Execute the full pipeline for a validated breach input."""
        breach_dir = self.output_dir / breach.breach_id

        timer = self.timer_module(breach.detection_datetime, breach.breach_id)
        timer_status = timer.get_status()
        classification = self.classifier.classify(breach)
        nist = self.nist_mapper.map_breach(
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
        log_writer = self.evidence_log(breach.breach_id, self.output_dir)
        validation = log_writer.validate_article_33_3(entry)
        json_path = log_writer.create(entry)
        md_path = json_path.parent / "evidence_log.md"

        ico_draft = self.ico_generator.generate(breach, classification, timer_status)
        ico_path = breach_dir / "ico_notification.txt"
        self.ico_generator.to_file(ico_draft, ico_path)

        generated_at = datetime.now(UTC)
        pdf_path = breach_dir / "breach_report.pdf"
        output_paths = OutputPaths(
            evidence_log_json=str(json_path),
            evidence_log_md=str(md_path),
            ico_notification=str(ico_path),
            pdf_report=str(pdf_path),
        )

        report_data = self._build_report_data(
            breach=breach,
            generated_at=generated_at,
            timer_status=timer_status,
            classification=classification,
            nist=nist,
            validation=validation,
            ico_text=ico_draft.text,
            output_paths=output_paths,
        )
        self.pdf_generator.generate(report_data, pdf_path)

        return PipelineResult(
            breach_id=breach.breach_id,
            report_data=report_data,
            output_paths=output_paths,
            ico_warnings=ico_draft.warnings,
        )

    @staticmethod
    def _build_report_data(
        *,
        breach: BreachInput,
        generated_at: datetime,
        timer_status: TimerStatus,
        classification: ClassificationResult,
        nist: NISTMappingResult,
        validation: ValidationResult,
        ico_text: str,
        output_paths: OutputPaths,
    ) -> BreachReportData:
        nist_dict = EvidenceLog._nist_to_dict(nist)
        return BreachReportData(
            breach=breach,
            generated_at_utc=generated_at,
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
            ico_notification_text=ico_text,
            outputs=output_paths,
        )
