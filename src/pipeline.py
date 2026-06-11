"""Full breach report pipeline orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.breach.classifier import BreachClassifier
from src.breach.evidence_log import EvidenceLog
from src.breach.ico_notification import ICONotificationGenerator
from src.breach.nist_mapper import NISTMapper
from src.breach.timer import BreachTimer
from src.models.breach_model import BreachInput
from src.models.report_model import BreachReportData, OutputPaths
from src.reporter.pdf_report import BreachReportGenerator


@dataclass
class PipelineResult:
    """Result of a full --mode report pipeline run."""

    breach_id: str
    report_data: BreachReportData
    output_paths: OutputPaths


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
        raise NotImplementedError("Full report pipeline not yet implemented.")
