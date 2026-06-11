"""Shared pytest fixtures for breach-response-toolkit."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.models.breach_model import BreachInput, BreachType, DataType, DPOContact


@pytest.fixture
def sample_breach_input() -> BreachInput:
    return BreachInput(
        breach_id="B-TEST-001",
        detection_datetime=datetime.now(timezone.utc) - timedelta(hours=10),
        data_type=DataType.FINANCIAL,
        records_affected=1500,
        special_category_involved=False,
        data_encrypted=False,
        breach_type=BreachType.CONFIDENTIALITY,
        description="Test breach: SQL injection exposed customer financial records",
        affected_data_categories=["bank account numbers", "sort codes"],
        estimated_data_subjects=1500,
        estimated_records=1500,
        dpo_contact=DPOContact(
            name="Test DPO",
            email="dpo@test.com",
            telephone="01234 567890",
        ),
        likely_consequences=["Financial fraud risk for affected customers"],
        measures_taken=["System isolated", "Forensics team engaged"],
        controller_name="Test Organisation",
        ico_registration_number="ZA123456",
        controller_address="1 Test Street, London, EC1A 1BB",
    )


@pytest.fixture
def tmp_output_dir(tmp_path: Path) -> Path:
    return tmp_path / "outputs"
