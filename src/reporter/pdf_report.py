"""PDF breach incident report generator via fpdf2."""

from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

from src.models.breach_model import SeverityLevel
from src.models.report_model import BreachReportData


class Colour:
    """RGB colour constants for PDF styling."""

    DARK_BLUE = (31, 56, 100)
    WHITE = (255, 255, 255)
    LIGHT_GREY = (245, 245, 245)
    LOW = (0, 153, 0)
    MEDIUM = (255, 165, 0)
    HIGH = (220, 80, 0)
    CRITICAL = (139, 0, 0)
    TEXT_DARK = (30, 30, 30)


class BreachReportGenerator:
    """Generates a multi-page A4 PDF breach incident report."""

    PAGE_SIZE = (210, 297)
    MARGIN = 20

    def generate(self, report_data: BreachReportData, output_path: Path) -> Path:
        """Compile all module outputs into breach_report.pdf."""
        raise NotImplementedError("PDF report generation not yet implemented.")

    def _create_pdf(self) -> FPDF:
        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=self.MARGIN)
        return pdf

    def _add_cover_page(self, pdf: FPDF, report_data: BreachReportData) -> None:
        raise NotImplementedError

    def _add_executive_summary(self, pdf: FPDF, report_data: BreachReportData) -> None:
        raise NotImplementedError

    def _add_timer_section(self, pdf: FPDF, report_data: BreachReportData) -> None:
        raise NotImplementedError

    def _add_classification_section(self, pdf: FPDF, report_data: BreachReportData) -> None:
        raise NotImplementedError

    def _add_nist_section(self, pdf: FPDF, report_data: BreachReportData) -> None:
        raise NotImplementedError

    def _add_evidence_log_section(self, pdf: FPDF, report_data: BreachReportData) -> None:
        raise NotImplementedError

    def _add_ico_draft_section(self, pdf: FPDF, report_data: BreachReportData) -> None:
        raise NotImplementedError

    def _severity_colour(self, severity: SeverityLevel) -> tuple[int, int, int]:
        mapping = {
            SeverityLevel.LOW: Colour.LOW,
            SeverityLevel.MEDIUM: Colour.MEDIUM,
            SeverityLevel.HIGH: Colour.HIGH,
            SeverityLevel.CRITICAL: Colour.CRITICAL,
        }
        return mapping[severity]

    def _add_section_header(self, pdf: FPDF, title: str) -> None:
        raise NotImplementedError

    def _add_key_value_row(self, pdf: FPDF, key: str, value: str) -> None:
        raise NotImplementedError
