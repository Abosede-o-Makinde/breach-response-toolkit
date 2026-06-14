"""Security tests — target: 6 tests."""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from freezegun import freeze_time
from pydantic import ValidationError

from src.breach.classifier import BreachClassifier
from src.breach.timer import BreachTimer
from src.models.breach_model import BreachInput
from src.pipeline import BreachReportPipeline

FROZEN_NOW = datetime(2024, 6, 9, 18, 30, 0, tzinfo=UTC)


def _malicious_breach(sample_breach_input: BreachInput, **updates) -> BreachInput:
    detection = datetime(2024, 6, 9, 14, 30, 0, tzinfo=UTC)
    return sample_breach_input.model_copy(
        update={
            "detection_datetime": detection,
            **updates,
        }
    )


class TestInputSecurity:
    def test_sql_injection_string_in_description_does_not_raise(
        self, sample_breach_input: BreachInput
    ) -> None:
        breach = _malicious_breach(
            sample_breach_input,
            description="'; DROP TABLE breaches; -- unauthorised access to records",
        )
        with freeze_time(FROZEN_NOW):
            result = BreachClassifier().classify(breach)
        assert result.severity is not None
        assert "DROP TABLE" in breach.description

    def test_path_traversal_in_breach_id_rejected(self) -> None:
        past = datetime.now(UTC) - timedelta(hours=5)
        with pytest.raises(ValueError, match="Invalid breach_id"):
            BreachTimer(past, "../../etc/passwd")

        with pytest.raises(ValidationError):
            BreachInput.model_validate(
                {
                    "breach_id": "../escape",
                    "detection_datetime": past.isoformat(),
                    "data_type": "financial",
                    "records_affected": 1,
                    "breach_type": "confidentiality",
                    "description": "Path traversal probe in breach identifier field",
                    "affected_data_categories": ["names"],
                    "estimated_data_subjects": 1,
                    "estimated_records": 1,
                    "dpo_contact": {
                        "name": "DPO",
                        "email": "dpo@test.com",
                        "telephone": "01234 567890",
                    },
                    "likely_consequences": ["Identity theft"],
                    "measures_taken": ["Investigation started"],
                    "controller_name": "Test Org",
                    "controller_address": "1 Test Street",
                }
            )

    def test_script_tag_in_description_stored_as_plain_text(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        payload = "<script>alert('xss')</script> injected via portal form"
        breach = _malicious_breach(sample_breach_input, description=payload)
        with freeze_time(FROZEN_NOW):
            result = BreachReportPipeline(tmp_output_dir).run(breach)

        log_path = tmp_output_dir / breach.breach_id / "evidence_log.json"
        md_path = tmp_output_dir / breach.breach_id / "evidence_log.md"
        log_text = log_path.read_text(encoding="utf-8")
        md_text = md_path.read_text(encoding="utf-8")

        assert payload in log_text
        assert payload in md_text
        assert payload in result.report_data.breach.description
        assert "<script>" in log_text

    def test_output_files_stay_within_output_directory(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        breach = _malicious_breach(sample_breach_input)
        base = tmp_output_dir.resolve()
        with freeze_time(FROZEN_NOW):
            result = BreachReportPipeline(tmp_output_dir).run(breach)

        for path_str in result.output_paths.model_dump().values():
            resolved = Path(path_str).resolve()
            assert str(resolved).startswith(str(base))

    def test_very_long_string_input_accepted_gracefully(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        long_tail = "A" * 5000
        breach = _malicious_breach(
            sample_breach_input,
            description=f"Long-form breach narrative for stress testing: {long_tail}",
        )
        with freeze_time(FROZEN_NOW):
            result = BreachReportPipeline(tmp_output_dir).run(breach)

        log_data = json.loads(
            (tmp_output_dir / breach.breach_id / "evidence_log.json").read_text(encoding="utf-8")
        )
        assert long_tail in log_data["article_33_3_fields"]["a_nature_of_breach"]["description"]
        assert result.report_data.breach.description.endswith(long_tail)

    def test_no_outbound_network_calls_during_report_generation(
        self, sample_breach_input: BreachInput, tmp_output_dir: Path
    ) -> None:
        breach = _malicious_breach(sample_breach_input)

        def block_connect(*args, **kwargs):
            raise AssertionError(f"Unexpected network connection: {args}")

        with (
            freeze_time(FROZEN_NOW),
            patch.object(socket.socket, "connect", block_connect),
        ):
            BreachReportPipeline(tmp_output_dir).run(breach)
