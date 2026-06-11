"""Tests for src/breach/nist_mapper.py — target: 10 tests, ≥85% coverage."""

from __future__ import annotations

import json

import pytest

from src.breach.nist_mapper import NISTFunction, NISTMapper
from src.models.breach_model import BreachType, DataType, SeverityLevel


class TestNISTMapper:
    def setup_method(self) -> None:
        self.mapper = NISTMapper()

    def test_confidentiality_breach_includes_protect_function(self) -> None:
        result = self.mapper.map_breach(
            BreachType.CONFIDENTIALITY, DataType.FINANCIAL, SeverityLevel.HIGH
        )
        assert NISTFunction.PROTECT in result.functions_impacted

    def test_availability_breach_includes_recover_function(self) -> None:
        result = self.mapper.map_breach(
            BreachType.AVAILABILITY, DataType.BASIC_CONTACT, SeverityLevel.MEDIUM
        )
        assert NISTFunction.RECOVER in result.functions_impacted

    def test_integrity_breach_includes_detect_function(self) -> None:
        result = self.mapper.map_breach(
            BreachType.INTEGRITY, DataType.CREDENTIALS, SeverityLevel.HIGH
        )
        assert NISTFunction.DETECT in result.functions_impacted

    def test_combined_breach_includes_all_five_functions(self) -> None:
        result = self.mapper.map_breach(
            BreachType.COMBINED, DataType.HEALTH, SeverityLevel.CRITICAL
        )
        assert set(result.functions_impacted) == set(NISTFunction)

    def test_failed_controls_have_gdpr_article_references(self) -> None:
        result = self.mapper.map_breach(
            BreachType.CONFIDENTIALITY, DataType.FINANCIAL, SeverityLevel.HIGH
        )
        assert result.failed_controls
        assert all(control.gdpr_article.startswith("Art.") for control in result.failed_controls)

    def test_recommendations_have_priority_field(self) -> None:
        result = self.mapper.map_breach(
            BreachType.CONFIDENTIALITY, DataType.FINANCIAL, SeverityLevel.HIGH
        )
        assert result.recommended_controls
        assert all(rec.priority for rec in result.recommended_controls)

    def test_critical_breach_has_at_least_one_immediate_priority_rec(self) -> None:
        result = self.mapper.map_breach(
            BreachType.COMBINED, DataType.BIOMETRIC, SeverityLevel.CRITICAL
        )
        priorities = {rec.priority for rec in result.recommended_controls}
        assert "IMMEDIATE" in priorities

    def test_framework_reference_is_nist_csf_v1_1(self) -> None:
        result = self.mapper.map_breach(
            BreachType.CONFIDENTIALITY, DataType.FINANCIAL, SeverityLevel.LOW
        )
        assert result.framework_reference == "NIST CSF v1.1"

    def test_config_file_loads_without_error(self) -> None:
        config = self.mapper._load_mappings()
        assert "breach_type_mappings" in config
        assert "CONFIDENTIALITY" in config["breach_type_mappings"]

    def test_invalid_breach_type_raises_value_error(self, tmp_path) -> None:
        config_path = tmp_path / "empty_nist.json"
        config_path.write_text(
            json.dumps({"version": "NIST CSF v1.1", "breach_type_mappings": {}}),
            encoding="utf-8",
        )
        mapper = NISTMapper(config_path=config_path)
        with pytest.raises(ValueError, match="Unknown breach type"):
            mapper.map_breach(BreachType.CONFIDENTIALITY, DataType.FINANCIAL, SeverityLevel.HIGH)
