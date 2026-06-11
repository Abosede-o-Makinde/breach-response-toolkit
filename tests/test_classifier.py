"""Tests for src/breach/classifier.py — target: 15 tests, ≥95% coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src.breach.classifier import BreachClassifier
from src.models.breach_model import BreachInput, BreachType, DataType, DPOContact, SeverityLevel

_BASE = {
    "breach_id": "B-TEST-CLS",
    "detection_datetime": datetime.now(UTC) - timedelta(hours=10),
    "breach_type": BreachType.CONFIDENTIALITY,
    "description": "Test breach for classifier unit tests across severity bands",
    "affected_data_categories": ["test data"],
    "estimated_data_subjects": 100,
    "estimated_records": 100,
    "dpo_contact": DPOContact(name="Test DPO", email="dpo@test.com", telephone="01234 567890"),
    "likely_consequences": ["Identity theft or fraud risk for affected individuals"],
    "measures_taken": ["System isolated and forensic investigation commenced"],
    "controller_name": "Test Organisation",
    "ico_registration_number": "ZA123456",
    "controller_address": "1 Test Street, London, EC1A 1BB",
}


def _breach(**overrides) -> BreachInput:
    return BreachInput(**{**_BASE, **overrides})


class TestBreachClassifier:
    def setup_method(self) -> None:
        self.classifier = BreachClassifier()

    def test_basic_contact_low_records_encrypted_returns_low(self) -> None:
        breach = _breach(
            data_type=DataType.BASIC_CONTACT,
            records_affected=5,
            special_category_involved=False,
            data_encrypted=True,
        )
        assert self.classifier.classify(breach).severity == SeverityLevel.LOW

    def test_financial_1000_records_unencrypted_returns_high(self) -> None:
        breach = _breach(
            data_type=DataType.FINANCIAL,
            records_affected=1000,
            special_category_involved=False,
            data_encrypted=False,
        )
        result = self.classifier.classify(breach)
        assert result.severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}

    def test_biometric_5000_special_unencrypted_returns_critical(self) -> None:
        breach = _breach(
            data_type=DataType.BIOMETRIC,
            records_affected=5000,
            special_category_involved=True,
            data_encrypted=False,
        )
        assert self.classifier.classify(breach).severity == SeverityLevel.CRITICAL

    def test_criminal_data_returns_high_or_critical(self) -> None:
        breach = _breach(
            data_type=DataType.CRIMINAL,
            records_affected=50,
            special_category_involved=True,
            data_encrypted=False,
        )
        result = self.classifier.classify(breach)
        assert result.severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}

    def test_encryption_reduces_total_score(self) -> None:
        base = _breach(
            data_type=DataType.FINANCIAL,
            records_affected=500,
            special_category_involved=False,
            data_encrypted=False,
        )
        encrypted = _breach(
            data_type=DataType.FINANCIAL,
            records_affected=500,
            special_category_involved=False,
            data_encrypted=True,
        )
        assert self.classifier.classify(encrypted).score < self.classifier.classify(base).score

    def test_special_category_increases_score_by_20(self) -> None:
        without = _breach(
            data_type=DataType.HEALTH,
            records_affected=100,
            special_category_involved=False,
            data_encrypted=False,
        )
        with_special = _breach(
            data_type=DataType.HEALTH,
            records_affected=100,
            special_category_involved=True,
            data_encrypted=False,
        )
        diff = self.classifier.classify(with_special).score - self.classifier.classify(without).score
        assert diff == pytest.approx(20.0)

    def test_scale_score_increases_with_record_count(self) -> None:
        low_count = _breach(data_type=DataType.BASIC_CONTACT, records_affected=5)
        high_count = _breach(data_type=DataType.BASIC_CONTACT, records_affected=5000)
        assert self.classifier.classify(high_count).score > self.classifier.classify(low_count).score

    def test_score_clamped_between_0_and_100(self) -> None:
        extreme = _breach(
            data_type=DataType.BIOMETRIC,
            records_affected=1_000_000,
            special_category_involved=True,
            data_encrypted=False,
        )
        result = self.classifier.classify(extreme)
        assert 0.0 <= result.score <= 100.0

    def test_critical_requires_both_ico_and_subject_notification(self) -> None:
        breach = _breach(
            data_type=DataType.BIOMETRIC,
            records_affected=10000,
            special_category_involved=True,
            data_encrypted=False,
        )
        result = self.classifier.classify(breach)
        assert result.ico_notification_required is True
        assert result.subject_notification_required is True

    def test_high_severity_requires_ico_notification_only(self) -> None:
        breach = _breach(
            data_type=DataType.FINANCIAL,
            records_affected=1000,
            special_category_involved=False,
            data_encrypted=False,
        )
        result = self.classifier.classify(breach)
        assert result.ico_notification_required is True
        assert result.subject_notification_required is False

    def test_special_category_always_triggers_ico_notification(self) -> None:
        breach = _breach(
            data_type=DataType.BASIC_CONTACT,
            records_affected=5,
            special_category_involved=True,
            data_encrypted=True,
        )
        result = self.classifier.classify(breach)
        assert result.ico_notification_required is True

    def test_zero_records_handled_without_exception(self) -> None:
        breach = _breach(
            data_type=DataType.FINANCIAL,
            records_affected=0,
            special_category_involved=False,
            data_encrypted=False,
        )
        result = self.classifier.classify(breach)
        assert result is not None
        assert result.severity is not None

    def test_result_reasoning_is_non_empty_string(self) -> None:
        breach = _breach(
            data_type=DataType.HEALTH,
            records_affected=200,
            special_category_involved=True,
            data_encrypted=False,
        )
        result = self.classifier.classify(breach)
        assert isinstance(result.reasoning, str)
        assert len(result.reasoning) >= 50

    def test_result_includes_at_least_one_recommended_action(self) -> None:
        breach = _breach(
            data_type=DataType.FINANCIAL,
            records_affected=500,
            special_category_involved=False,
            data_encrypted=False,
        )
        result = self.classifier.classify(breach)
        assert len(result.recommended_actions) >= 1

    def test_breakdown_fields_sum_to_total_score(self) -> None:
        breach = _breach(
            data_type=DataType.CREDENTIALS,
            records_affected=200,
            special_category_involved=False,
            data_encrypted=False,
        )
        result = self.classifier.classify(breach)
        bd = result.breakdown
        expected = max(
            0,
            min(
                100,
                bd.data_type_score
                + bd.scale_score
                + bd.special_category_bonus
                + bd.encryption_reduction,
            ),
        )
        assert result.score == pytest.approx(expected)
