"""Smoke tests verifying repository structure and architecture scaffold."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


class TestRepositoryStructure:
    def test_required_directories_exist(self) -> None:
        required_dirs = [
            "src/breach",
            "src/models",
            "src/reporter",
            "config",
            "templates",
            "docs",
            "sample_data",
            "sample_outputs",
            "tests",
            ".github/workflows",
        ]
        for relative in required_dirs:
            assert (ROOT / relative).is_dir(), f"Missing directory: {relative}"

    def test_required_config_files_exist(self) -> None:
        assert (ROOT / "config/breach_types.json").is_file()
        assert (ROOT / "config/nist_mappings.json").is_file()

    def test_required_templates_exist(self) -> None:
        assert (ROOT / "templates/ico_notification.j2").is_file()
        assert (ROOT / "templates/breach_log.md.j2").is_file()

    def test_sample_data_exists(self) -> None:
        assert (ROOT / "sample_data/example_breach.json").is_file()


class TestPackageImports:
    def test_import_core_modules(self) -> None:
        from src.breach.classifier import BreachClassifier
        from src.breach.evidence_log import EvidenceLog
        from src.breach.ico_notification import ICONotificationGenerator
        from src.breach.nist_mapper import NISTMapper
        from src.breach.timer import AlertLevel, BreachTimer
        from src.models.breach_model import BreachInput, SeverityLevel
        from src.pipeline import BreachReportPipeline
        from src.reporter.pdf_report import BreachReportGenerator

        assert BreachTimer is not None
        assert BreachClassifier is not None
        assert NISTMapper is not None
        assert EvidenceLog is not None
        assert ICONotificationGenerator is not None
        assert BreachReportGenerator is not None
        assert BreachReportPipeline is not None
        assert AlertLevel.OK.value == "OK"
        assert SeverityLevel.CRITICAL.value == "CRITICAL"
        assert BreachInput is not None


class TestBreachInputValidation:
    def test_sample_breach_input_validates(self, sample_breach_input) -> None:
        from src.models.breach_model import DataType

        assert sample_breach_input.breach_id == "B-TEST-001"
        assert sample_breach_input.data_type == DataType.FINANCIAL

    def test_invalid_breach_id_rejected(self) -> None:
        from datetime import datetime, timezone

        from pydantic import ValidationError

        from src.models.breach_model import BreachInput, BreachType, DataType, DPOContact

        with pytest.raises(ValidationError):
            BreachInput(
                breach_id="../bad",
                detection_datetime=datetime.now(timezone.utc),
                data_type=DataType.BASIC_CONTACT,
                records_affected=1,
                breach_type=BreachType.CONFIDENTIALITY,
                description="A" * 25,
                affected_data_categories=["names"],
                estimated_data_subjects=1,
                estimated_records=1,
                dpo_contact=DPOContact(name="X", email="x@test.com", telephone="1"),
                likely_consequences=["risk"],
                measures_taken=["action"],
                controller_name="Org",
                controller_address="Addr",
            )


class TestTimerValidation:
    def test_future_detection_datetime_rejected(self) -> None:
        from datetime import datetime, timedelta, timezone

        from src.breach.timer import BreachTimer

        future = datetime.now(timezone.utc) + timedelta(hours=1)
        with pytest.raises(ValueError, match="cannot be in the future"):
            BreachTimer(future, "B-001")

    def test_path_traversal_in_breach_id_rejected(self) -> None:
        from datetime import datetime, timedelta, timezone

        from src.breach.timer import BreachTimer

        past = datetime.now(timezone.utc) - timedelta(hours=5)
        with pytest.raises(ValueError, match="Invalid breach_id"):
            BreachTimer(past, "../../etc/passwd")
