"""PDF breach incident report generator via fpdf2."""

from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

from src import __version__
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
        pdf = self._create_pdf()
        self._add_cover_page(pdf, report_data)
        self._add_executive_summary(pdf, report_data)
        self._add_timer_section(pdf, report_data)
        self._add_classification_section(pdf, report_data)
        self._add_nist_section(pdf, report_data)
        self._add_evidence_log_section(pdf, report_data)
        self._add_ico_draft_section(pdf, report_data)

        target = output_path.resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        pdf.output(str(target))
        return target

    def _create_pdf(self) -> FPDF:
        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=self.MARGIN)
        pdf.set_margins(self.MARGIN, self.MARGIN, self.MARGIN)
        return pdf

    def _add_cover_page(self, pdf: FPDF, report_data: BreachReportData) -> None:
        pdf.add_page()
        pdf.set_fill_color(*Colour.DARK_BLUE)
        pdf.rect(0, 0, 210, 45, style="F")
        pdf.set_text_color(*Colour.WHITE)
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_y(12)
        pdf.cell(0, 10, "breach-response-toolkit", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=11)
        pdf.cell(0, 8, f"Incident Report v{__version__}", align="C", new_x="LMARGIN", new_y="NEXT")

        pdf.set_text_color(*Colour.TEXT_DARK)
        pdf.ln(20)
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(
            0,
            10,
            self._safe_text("Personal Data Breach Incident Report"),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.ln(4)
        self._add_key_value_row(pdf, "Breach reference", report_data.breach.breach_id)
        self._add_key_value_row(
            pdf,
            "Generated (UTC)",
            report_data.generated_at_utc.isoformat(),
        )
        self._add_key_value_row(pdf, "Controller", report_data.breach.controller_name)

        severity = report_data.classification.severity
        colour = self._severity_colour(severity)
        pdf.ln(6)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(self.MARGIN)
        pdf.cell(40, 8, "Assessed severity:")
        pdf.set_fill_color(*colour)
        pdf.set_text_color(*Colour.WHITE)
        pdf.cell(40, 8, severity.value, align="C", fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(8)

        pdf.set_text_color(120, 120, 120)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "DRAFT - CONFIDENTIAL", align="C", new_x="LMARGIN", new_y="NEXT")

    def _add_executive_summary(self, pdf: FPDF, report_data: BreachReportData) -> None:
        pdf.add_page()
        self._add_section_header(pdf, "Executive Summary")

        timer = report_data.timer
        classification = report_data.classification
        self._add_key_value_row(pdf, "Timer status", timer.alert_level)
        self._add_key_value_row(pdf, "Elapsed", f"{timer.elapsed_hours:.1f} hours")
        self._add_key_value_row(pdf, "Remaining", f"{timer.remaining_hours:.1f} hours")
        self._add_key_value_row(
            pdf,
            "Notification deadline (UTC)",
            timer.notification_deadline.isoformat(),
        )
        self._add_key_value_row(
            pdf,
            "Severity score",
            f"{classification.score:.1f} / 100 ({classification.severity.value})",
        )
        ico_flag = "REQUIRED" if classification.ico_notification_required else "NOT REQUIRED"
        subject_flag = (
            "REQUIRED (Art. 34)" if classification.subject_notification_required else "NOT REQUIRED"
        )
        self._add_key_value_row(pdf, "ICO notification", ico_flag)
        self._add_key_value_row(pdf, "Subject notification", subject_flag)

        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Breach description", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        self._write_paragraph(pdf, report_data.breach.description)
        if report_data.breach.root_cause.strip():
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, "Root cause", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=10)
            self._write_paragraph(pdf, report_data.breach.root_cause)

    def _add_timer_section(self, pdf: FPDF, report_data: BreachReportData) -> None:
        pdf.add_page()
        self._add_section_header(pdf, "Article 33 Timer Detail")
        timer = report_data.timer
        rows = [
            ("Detection (UTC)", report_data.breach.detection_datetime.isoformat()),
            ("Elapsed hours", f"{timer.elapsed_hours:.2f}"),
            ("Remaining hours", f"{timer.remaining_hours:.2f}"),
            ("Window used", f"{timer.elapsed_percentage:.1f}%"),
            ("Alert level", timer.alert_level),
            ("Expired", "Yes" if timer.is_expired else "No"),
            ("Deadline (UTC)", timer.notification_deadline.isoformat()),
        ]
        for key, value in rows:
            self._add_key_value_row(pdf, key, value)

    def _add_classification_section(self, pdf: FPDF, report_data: BreachReportData) -> None:
        pdf.add_page()
        self._add_section_header(pdf, "Severity Classification")
        breakdown = report_data.classification.breakdown
        table_rows = [
            ("Data type", f"{breakdown.data_type_score:.1f}"),
            ("Scale", f"{breakdown.scale_score:.1f}"),
            ("Special category bonus", f"{breakdown.special_category_bonus:.1f}"),
            ("Encryption reduction", f"{breakdown.encryption_reduction:.1f}"),
            ("Total score", f"{breakdown.total:.1f}"),
        ]
        for key, value in table_rows:
            self._add_key_value_row(pdf, key, value)

        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Reasoning", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        self._write_paragraph(pdf, report_data.classification.reasoning)

        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Recommended actions", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        for index, action in enumerate(report_data.classification.recommended_actions, start=1):
            self._write_paragraph(pdf, f"{index}. {action}")

    def _add_nist_section(self, pdf: FPDF, report_data: BreachReportData) -> None:
        pdf.add_page()
        self._add_section_header(pdf, "NIST CSF Mapping")
        nist = report_data.nist_mapping
        self._add_key_value_row(pdf, "Framework", nist.framework_reference)
        self._add_key_value_row(
            pdf,
            "Functions impacted",
            ", ".join(nist.functions_impacted),
        )
        self._add_key_value_row(pdf, "Failed controls", str(nist.failed_controls_count))
        self._add_key_value_row(pdf, "Top failed control", self._safe_text(nist.top_failed_control))

        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Failed controls", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=9)
        for control in nist.failed_controls[:8]:
            line = (
                f"{control.get('subcategory', '')}: "
                f"{control.get('description', '')} "
                f"({control.get('gdpr_article', '')})"
            )
            self._write_paragraph(pdf, line, height=4)

        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Recommended remediations", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=9)
        for rec in nist.recommended_controls[:6]:
            line = (
                f"[{rec.get('priority', '')}] {rec.get('subcategory', '')}: "
                f"{rec.get('recommendation', '')}"
            )
            self._write_paragraph(pdf, line, height=4)

    def _add_evidence_log_section(self, pdf: FPDF, report_data: BreachReportData) -> None:
        pdf.add_page()
        self._add_section_header(pdf, "Evidence Log Summary (Article 33(3))")
        evidence = report_data.evidence_log
        breach = report_data.breach
        self._add_key_value_row(
            pdf,
            "Completeness",
            f"{evidence.article_33_3_completeness_percent:.1f}%",
        )
        if evidence.missing_fields:
            self._add_key_value_row(
                pdf,
                "Missing fields",
                ", ".join(evidence.missing_fields),
            )

        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "(a) Nature of breach", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        self._write_paragraph(pdf, breach.description)
        self._write_paragraph(
            pdf,
            "Categories: " + ", ".join(breach.affected_data_categories),
        )

        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "(b) DPO contact", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        dpo = breach.dpo_contact
        self._write_paragraph(
            pdf,
            f"{dpo.name} | {dpo.role} | {dpo.email} | {dpo.telephone}",
        )

        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "(c) Likely consequences", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        for item in breach.likely_consequences:
            self._write_paragraph(pdf, f"- {item}")

        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "(d) Measures taken", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        for item in breach.measures_taken:
            self._write_paragraph(pdf, f"- {item}")

    def _add_ico_draft_section(self, pdf: FPDF, report_data: BreachReportData) -> None:
        pdf.add_page()
        self._add_section_header(pdf, "ICO Notification Draft")
        pdf.set_font("Helvetica", "I", 10)
        self._write_paragraph(
            pdf,
            "DRAFT FOR REVIEW - must be reviewed by a qualified DPO or legal "
            "representative before submission to the ICO.",
        )
        pdf.ln(3)
        pdf.set_font("Courier", size=8)
        for line in report_data.ico_notification_text.splitlines():
            self._write_paragraph(pdf, line, height=3.5)

    def _severity_colour(self, severity: SeverityLevel) -> tuple[int, int, int]:
        mapping = {
            SeverityLevel.LOW: Colour.LOW,
            SeverityLevel.MEDIUM: Colour.MEDIUM,
            SeverityLevel.HIGH: Colour.HIGH,
            SeverityLevel.CRITICAL: Colour.CRITICAL,
        }
        return mapping[severity]

    def _add_section_header(self, pdf: FPDF, title: str) -> None:
        pdf.set_fill_color(*Colour.LIGHT_GREY)
        pdf.set_text_color(*Colour.DARK_BLUE)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 10, self._safe_text(title), fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)
        pdf.set_text_color(*Colour.TEXT_DARK)

    def _add_key_value_row(self, pdf: FPDF, key: str, value: str) -> None:
        pdf.set_x(self.MARGIN)
        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(
            0,
            6,
            self._safe_text(f"{key}: {value}"),
            new_x="LMARGIN",
            new_y="NEXT",
        )

    def _write_paragraph(self, pdf: FPDF, text: str, height: float = 5) -> None:
        pdf.set_x(self.MARGIN)
        pdf.multi_cell(0, height, self._safe_text(text), new_x="LMARGIN", new_y="NEXT")

    @staticmethod
    def _safe_text(text: str) -> str:
        """Normalise text for core PDF fonts (Latin-1)."""
        replacements = {
            "\u2014": "-",
            "\u2013": "-",
            "\u2022": "-",
            "\u26a0": "WARNING:",
            "\u2705": "OK",
            "\u274c": "X",
        }
        cleaned = text
        for source, target in replacements.items():
            cleaned = cleaned.replace(source, target)
        return cleaned.encode("latin-1", errors="replace").decode("latin-1")
