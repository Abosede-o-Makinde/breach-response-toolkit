"""Tests for src/breach/ico_notification.py — target: 8 tests, ≥85% coverage."""

from __future__ import annotations

from pathlib import Path

from src.breach.classifier import BreachClassifier
from src.breach.ico_notification import ICONotificationGenerator
from src.breach.timer import BreachTimer
from src.models.breach_model import BreachInput


def _draft_for(breach: BreachInput):
    timer = BreachTimer(breach.detection_datetime, breach.breach_id)
    classification = BreachClassifier().classify(breach)
    generator = ICONotificationGenerator()
    return generator.generate(breach, classification, timer.get_status())


class TestICONotification:
    def test_generated_draft_contains_all_article_33_3_section_headers(
        self, sample_breach_input: BreachInput
    ) -> None:
        draft = _draft_for(sample_breach_input)
        assert "SECTION 1 — CONTROLLER DETAILS" in draft.text
        assert "SECTION 2 — CONTACT POINT [Article 33(3)(b)]" in draft.text
        assert "SECTION 3 — NATURE OF BREACH [Article 33(3)(a)]" in draft.text
        assert "SECTION 4 — LIKELY CONSEQUENCES [Article 33(3)(c)]" in draft.text
        assert "SECTION 5 — MEASURES TAKEN [Article 33(3)(d)]" in draft.text
        assert "SECTION 6 — SEVERITY ASSESSMENT (INTERNAL)" in draft.text

    def test_breach_id_present_in_notification_draft(
        self, sample_breach_input: BreachInput
    ) -> None:
        draft = _draft_for(sample_breach_input)
        assert sample_breach_input.breach_id in draft.text

    def test_dpo_contact_details_in_notification_draft(
        self, sample_breach_input: BreachInput
    ) -> None:
        draft = _draft_for(sample_breach_input)
        assert sample_breach_input.dpo_contact.name in draft.text
        assert sample_breach_input.dpo_contact.email in draft.text
        assert sample_breach_input.dpo_contact.telephone in draft.text

    def test_description_in_notification_draft(self, sample_breach_input: BreachInput) -> None:
        draft = _draft_for(sample_breach_input)
        assert sample_breach_input.description in draft.text

    def test_missing_measures_taken_produces_validation_warning(
        self, sample_breach_input: BreachInput
    ) -> None:
        payload = sample_breach_input.model_dump()
        payload["measures_taken"] = []
        payload["dpo_contact"] = sample_breach_input.dpo_contact
        incomplete = BreachInput.model_construct(**payload)
        draft = _draft_for(incomplete)
        assert any("Article 33(3)(d)" in warning for warning in draft.warnings)
        assert draft.completeness_percent < 100.0

    def test_special_category_flag_reflected_in_draft(
        self, sample_breach_input: BreachInput
    ) -> None:
        special = sample_breach_input.model_copy(update={"special_category_involved": True})
        draft = _draft_for(special)
        assert "special" in draft.text.lower()
        assert "Yes" in draft.text

    def test_draft_includes_review_disclaimer(self, sample_breach_input: BreachInput) -> None:
        draft = _draft_for(sample_breach_input)
        assert "DRAFT FOR REVIEW" in draft.text
        assert "reviewed by a qualified DPO" in draft.text

    def test_to_file_writes_txt_output(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        draft = _draft_for(sample_breach_input)
        generator = ICONotificationGenerator()
        output_path = tmp_output_dir / sample_breach_input.breach_id / "ico_notification.txt"
        written = generator.to_file(draft, output_path)
        assert written.is_file()
        assert written.read_text(encoding="utf-8") == draft.text

    def test_notification_completeness_100_for_full_input(
        self, sample_breach_input: BreachInput
    ) -> None:
        draft = _draft_for(sample_breach_input)
        assert draft.completeness_percent == 100.0
        assert draft.warnings == []
