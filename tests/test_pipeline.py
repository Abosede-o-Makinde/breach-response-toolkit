"""Tests for src/pipeline.py — full report orchestration."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from freezegun import freeze_time

from src.models.breach_model import BreachInput
from src.pipeline import BreachReportPipeline, PipelineResult

DETECTION = datetime(2024, 6, 9, 14, 30, 0, tzinfo=UTC)
FROZEN_NOW = datetime(2024, 6, 9, 18, 30, 0, tzinfo=UTC)


def _breach_with_fixed_detection(breach: BreachInput) -> BreachInput:
    return breach.model_copy(update={"detection_datetime": DETECTION})


class TestBreachReportPipeline:
    def test_run_creates_all_output_files(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        breach = _breach_with_fixed_detection(sample_breach_input)
        with freeze_time(FROZEN_NOW):
            result = BreachReportPipeline(tmp_output_dir).run(breach)

        breach_dir = tmp_output_dir / breach.breach_id
        assert (breach_dir / "evidence_log.json").is_file()
        assert (breach_dir / "evidence_log.md").is_file()
        assert (breach_dir / "ico_notification.txt").is_file()
        assert (breach_dir / "breach_report.pdf").is_file()
        assert result.output_paths.pdf_report.endswith("breach_report.pdf")

    def test_run_returns_pipeline_result(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        breach = _breach_with_fixed_detection(sample_breach_input)
        with freeze_time(FROZEN_NOW):
            result = BreachReportPipeline(tmp_output_dir).run(breach)

        assert isinstance(result, PipelineResult)
        assert result.breach_id == breach.breach_id
        assert result.report_data.breach.breach_id == breach.breach_id
        assert result.report_data.classification.severity is not None
        assert result.report_data.timer.alert_level == "OK"

    def test_report_data_links_all_module_outputs(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        breach = _breach_with_fixed_detection(sample_breach_input)
        with freeze_time(FROZEN_NOW):
            result = BreachReportPipeline(tmp_output_dir).run(breach)

        data = result.report_data
        assert data.classification.ico_notification_required is True
        assert data.nist_mapping.failed_controls_count > 0
        assert data.evidence_log.article_33_3_completeness_percent == 100.0
        assert "Article 33" in data.ico_notification_text or "ICO" in data.ico_notification_text

    def test_evidence_log_json_contains_internal_tracking(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        breach = _breach_with_fixed_detection(sample_breach_input)
        with freeze_time(FROZEN_NOW):
            BreachReportPipeline(tmp_output_dir).run(breach)

        log_path = tmp_output_dir / breach.breach_id / "evidence_log.json"
        payload = json.loads(log_path.read_text(encoding="utf-8"))
        assert payload["breach_id"] == breach.breach_id
        assert "internal_tracking" in payload
        assert "severity_classification" in payload["internal_tracking"]
        assert "nist_mapping" in payload["internal_tracking"]

    def test_output_paths_stay_within_output_directory(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        breach = _breach_with_fixed_detection(sample_breach_input)
        base = tmp_output_dir.resolve()
        with freeze_time(FROZEN_NOW):
            result = BreachReportPipeline(tmp_output_dir).run(breach)

        for path_str in result.output_paths.model_dump().values():
            resolved = Path(path_str).resolve()
            assert str(resolved).startswith(str(base))

    def test_pdf_is_non_empty(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        breach = _breach_with_fixed_detection(sample_breach_input)
        with freeze_time(FROZEN_NOW):
            result = BreachReportPipeline(tmp_output_dir).run(breach)

        pdf_path = Path(result.output_paths.pdf_report)
        assert pdf_path.stat().st_size > 1000
        assert pdf_path.read_bytes()[:4] == b"%PDF"

    def test_ico_draft_has_no_warnings_for_complete_input(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        breach = _breach_with_fixed_detection(sample_breach_input)
        with freeze_time(FROZEN_NOW):
            result = BreachReportPipeline(tmp_output_dir).run(breach)

        assert result.ico_warnings == []

    def test_incomplete_breach_surfaces_ico_warnings(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        breach = _breach_with_fixed_detection(sample_breach_input).model_copy(
            update={"controller_address": ""}
        )
        with freeze_time(FROZEN_NOW):
            result = BreachReportPipeline(tmp_output_dir).run(breach)

        assert any("Controller identification" in warning for warning in result.ico_warnings)
