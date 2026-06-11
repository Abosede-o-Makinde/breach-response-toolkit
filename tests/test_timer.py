"""Tests for src/breach/timer.py — target: 12 tests, ≥95% coverage."""

from __future__ import annotations

import json
import warnings
from datetime import UTC, datetime, timedelta

import pytest
from freezegun import freeze_time

from src.breach.timer import AlertLevel, BreachTimer

DETECTION = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)


def _status_at(hours_after_detection: float):
    frozen = DETECTION + timedelta(hours=hours_after_detection)
    with freeze_time(frozen):
        timer = BreachTimer(DETECTION, "B-TEST-001")
        return timer.get_status()


class TestBreachTimer:
    def test_alert_level_ok_at_10_hours(self) -> None:
        status = _status_at(10)
        assert status.alert_level == AlertLevel.OK

    def test_alert_level_ok_at_47_hours(self) -> None:
        status = _status_at(47)
        assert status.alert_level == AlertLevel.OK

    def test_alert_level_warning_at_50_hours(self) -> None:
        status = _status_at(50)
        assert status.alert_level == AlertLevel.WARNING

    def test_alert_level_critical_at_69_hours(self) -> None:
        status = _status_at(69)
        assert status.alert_level == AlertLevel.CRITICAL

    def test_alert_level_expired_at_73_hours(self) -> None:
        status = _status_at(73)
        assert status.alert_level == AlertLevel.EXPIRED
        assert status.is_expired is True

    def test_remaining_hours_is_zero_when_expired(self) -> None:
        status = _status_at(73)
        assert status.remaining_hours == 0.0

    def test_deadline_is_exactly_72_hours_from_detection(self) -> None:
        status = _status_at(10)
        expected = DETECTION + timedelta(hours=72)
        assert status.notification_deadline == expected

    def test_future_datetime_raises_value_error(self) -> None:
        future = datetime.now(UTC) + timedelta(hours=1)
        with pytest.raises(ValueError, match="cannot be in the future"):
            BreachTimer(future, "B-001")

    def test_naive_datetime_triggers_warning(self) -> None:
        naive = datetime(2024, 6, 1, 12, 0, 0)
        with freeze_time("2024-06-01T22:00:00Z"):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                timer = BreachTimer(naive, "B-001")
                assert timer.detection_datetime.tzinfo == UTC
                assert any("assuming UTC" in str(w.message) for w in caught)

    def test_to_dict_is_json_serialisable(self) -> None:
        frozen = DETECTION + timedelta(hours=10)
        with freeze_time(frozen):
            timer = BreachTimer(DETECTION, "B-TEST-001")
            payload = timer.to_dict()
            json.dumps(payload)
            assert payload["alert_level"] == "OK"
            assert payload["elapsed_hours"] == 10.0
            assert "notification_deadline" in payload
            assert "snapshot_utc" in payload

    def test_elapsed_percentage_near_50_at_36_hours(self) -> None:
        status = _status_at(36)
        assert status.elapsed_percentage == 50.0

    def test_path_traversal_in_breach_id_raises_value_error(self) -> None:
        past = datetime.now(UTC) - timedelta(hours=5)
        with pytest.raises(ValueError, match="Invalid breach_id"):
            BreachTimer(past, "../../etc/passwd")
