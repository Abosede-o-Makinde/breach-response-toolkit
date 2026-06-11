"""4-dimension GDPR breach severity classifier."""

from __future__ import annotations

import warnings
from pathlib import Path

from src.models.breach_model import (
    BreachInput,
    ClassificationResult,
    DataType,
    SeverityLevel,
)

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


class BreachClassifier:
    """Scores breach severity across data type, scale, special category, and encryption."""

    DATA_TYPE_WEIGHTS: dict[DataType, float] = {
        DataType.BASIC_CONTACT: 15,
        DataType.CREDENTIALS: 30,
        DataType.FINANCIAL: 35,
        DataType.HEALTH: 40,
        DataType.BIOMETRIC: 45,
        DataType.CRIMINAL: 45,
    }

    SCALE_THRESHOLDS: list[tuple[int, float]] = [
        (10, 5),
        (100, 10),
        (1000, 15),
        (10000, 20),
        (float("inf"), 25),
    ]

    SPECIAL_CATEGORY_BONUS: float = 20.0
    ENCRYPTION_REDUCTION: float = -15.0

    SEVERITY_BANDS: list[tuple[float, SeverityLevel]] = [
        (25, SeverityLevel.LOW),
        (50, SeverityLevel.MEDIUM),
        (75, SeverityLevel.HIGH),
        (100, SeverityLevel.CRITICAL),
    ]

    def __init__(self, config_path: Path = CONFIG_DIR / "breach_types.json") -> None:
        self.config_path = config_path

    def classify(self, breach: BreachInput) -> ClassificationResult:
        """Score a breach and return severity level with notification flags."""
        raise NotImplementedError("Breach classification not yet implemented.")

    def _score_data_type(self, data_type: DataType) -> float:
        raise NotImplementedError

    def _score_scale(self, records_affected: int) -> float:
        if records_affected < 0:
            raise ValueError("records_affected must be non-negative")
        if records_affected == 0:
            warnings.warn("Using 1 as conservative minimum for scale scoring.", UserWarning)
            records_affected = 1
        raise NotImplementedError

    def _score_special_category(self, involved: bool) -> float:
        raise NotImplementedError

    def _score_encryption(self, encrypted: bool) -> float:
        raise NotImplementedError

    def _determine_severity(self, score: float) -> SeverityLevel:
        raise NotImplementedError

    def _determine_notification_flags(
        self, breach: BreachInput, severity: SeverityLevel, score: float
    ) -> tuple[bool, bool]:
        raise NotImplementedError

    def _generate_reasoning(self, breach: BreachInput, result: ClassificationResult) -> str:
        raise NotImplementedError

    def _generate_recommended_actions(
        self, breach: BreachInput, severity: SeverityLevel
    ) -> list[str]:
        raise NotImplementedError
