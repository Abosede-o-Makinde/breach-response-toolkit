"""Tests for src/breach/evidence_log.py — target: 8 tests, ≥85% coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.breach.classifier import BreachClassifier
from src.breach.evidence_log import EvidenceLog, EvidenceLogEntry
from src.breach.nist_mapper import NISTMapper
from src.breach.timer import BreachTimer
from src.models.breach_model import BreachInput, DPOContact


def _build_entry(breach: BreachInput) -> EvidenceLogEntry:
    timer = BreachTimer(breach.detection_datetime, breach.breach_id)
    classification = BreachClassifier().classify(breach)
    nist = NISTMapper().map_breach(
        breach.breach_type,
        breach.data_type,
        classification.severity,
    )
    return EvidenceLogEntry(
        breach=breach,
        timer=timer,
        classification=classification,
        nist=nist,
    )


class TestEvidenceLog:
    def test_create_writes_json_file(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        entry = _build_entry(sample_breach_input)
        log = EvidenceLog(sample_breach_input.breach_id, tmp_output_dir)
        json_path = log.create(entry)
        assert json_path.is_file()
        assert json_path.name == "evidence_log.json"

    def test_create_writes_markdown_file(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        entry = _build_entry(sample_breach_input)
        log = EvidenceLog(sample_breach_input.breach_id, tmp_output_dir)
        log.create(entry)
        md_path = tmp_output_dir / sample_breach_input.breach_id / "evidence_log.md"
        assert md_path.is_file()
        assert "Article 33(3)(a)" in md_path.read_text(encoding="utf-8")

    def test_full_input_scores_100_percent_completeness(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        entry = _build_entry(sample_breach_input)
        log = EvidenceLog(sample_breach_input.breach_id, tmp_output_dir)
        assert log.completeness_score(entry) == 100.0

    def test_missing_dpo_contact_reduces_completeness_score(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        incomplete = sample_breach_input.model_copy(
            update={
                "dpo_contact": DPOContact(name="", email="dpo@test.com", telephone="01234 567890")
            }
        )
        entry = _build_entry(incomplete)
        log = EvidenceLog(incomplete.breach_id, tmp_output_dir)
        score = log.completeness_score(entry)
        assert score < 100.0
        assert score == pytest.approx(83.3, abs=0.1)

    def test_article_33_3_all_four_fields_present_in_json(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        entry = _build_entry(sample_breach_input)
        log = EvidenceLog(sample_breach_input.breach_id, tmp_output_dir)
        json_path = log.create(entry)
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        fields = payload["article_33_3_fields"]
        assert "a_nature_of_breach" in fields
        assert "b_dpo_contact" in fields
        assert "c_likely_consequences" in fields
        assert "d_measures_taken" in fields

    def test_update_appends_to_audit_trail(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        entry = _build_entry(sample_breach_input)
        log = EvidenceLog(sample_breach_input.breach_id, tmp_output_dir)
        json_path = log.create(entry)
        log.update("d_measures_taken", ["Patched vulnerability", "Notified DPO"])
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        assert len(payload["audit_trail"]) == 2
        assert "FIELD_UPDATED" in payload["audit_trail"][-1]["action"]

    def test_update_does_not_overwrite_existing_fields(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        entry = _build_entry(sample_breach_input)
        log = EvidenceLog(sample_breach_input.breach_id, tmp_output_dir)
        json_path = log.create(entry)
        original_description = json.loads(json_path.read_text(encoding="utf-8"))[
            "article_33_3_fields"
        ]["a_nature_of_breach"]["description"]
        log.update("d_measures_taken", ["Additional containment step"])
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        assert payload["article_33_3_fields"]["a_nature_of_breach"]["description"] == (
            original_description
        )

    def test_json_output_is_valid_json(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        entry = _build_entry(sample_breach_input)
        log = EvidenceLog(sample_breach_input.breach_id, tmp_output_dir)
        json_path = log.create(entry)
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        assert payload["breach_id"] == sample_breach_input.breach_id
        assert payload["schema_version"] == "1.0"
