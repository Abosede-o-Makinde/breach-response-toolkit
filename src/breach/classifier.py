"""4-dimension GDPR breach severity classifier."""

from __future__ import annotations

import json
import warnings
from pathlib import Path

from src.models.breach_model import (
    BreachInput,
    ClassificationResult,
    DataType,
    ScoreBreakdown,
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
        self._notification_rules = self._load_notification_rules()

    def classify(self, breach: BreachInput) -> ClassificationResult:
        """Score a breach and return severity level with notification flags."""
        data_type_score = self._score_data_type(breach.data_type)
        scale_score = self._score_scale(breach.records_affected)
        special_category_bonus = self._score_special_category(breach.special_category_involved)
        encryption_reduction = self._score_encryption(breach.data_encrypted)

        raw_total = (
            data_type_score + scale_score + special_category_bonus + encryption_reduction
        )
        total = max(0.0, min(100.0, raw_total))
        severity = self._determine_severity(total)

        breakdown = ScoreBreakdown(
            data_type_score=data_type_score,
            scale_score=scale_score,
            special_category_bonus=special_category_bonus,
            encryption_reduction=encryption_reduction,
            total=total,
        )

        ico_required, subject_required = self._determine_notification_flags(
            breach, severity, total
        )
        recommended_actions = self._generate_recommended_actions(breach, severity)
        reasoning = self._generate_reasoning(
            breach,
            severity,
            total,
            ico_required,
            subject_required,
        )

        return ClassificationResult(
            severity=severity,
            score=total,
            breakdown=breakdown,
            ico_notification_required=ico_required,
            subject_notification_required=subject_required,
            reasoning=reasoning,
            recommended_actions=recommended_actions,
        )

    def _score_data_type(self, data_type: DataType) -> float:
        return self.DATA_TYPE_WEIGHTS[data_type]

    def _score_scale(self, records_affected: int) -> float:
        if records_affected < 0:
            raise ValueError("records_affected must be non-negative")
        if records_affected == 0:
            warnings.warn("Using 1 as conservative minimum for scale scoring.", UserWarning)
            records_affected = 1
        for threshold, score in self.SCALE_THRESHOLDS:
            if records_affected < threshold:
                return score
        return self.SCALE_THRESHOLDS[-1][1]

    def _score_special_category(self, involved: bool) -> float:
        return self.SPECIAL_CATEGORY_BONUS if involved else 0.0

    def _score_encryption(self, encrypted: bool) -> float:
        return self.ENCRYPTION_REDUCTION if encrypted else 0.0

    def _determine_severity(self, score: float) -> SeverityLevel:
        for upper_bound, level in self.SEVERITY_BANDS:
            if score < upper_bound:
                return level
        return SeverityLevel.CRITICAL

    def _determine_notification_flags(
        self, breach: BreachInput, severity: SeverityLevel, score: float
    ) -> tuple[bool, bool]:
        rules = self._notification_rules
        ico_required = False
        subject_required = False

        if breach.special_category_involved and rules.get("ico_required_on_special_category"):
            ico_required = True

        ico_severities = {item.upper() for item in rules.get("ico_required_on_severity", [])}
        if severity.value in ico_severities:
            ico_required = True

        subject_severities = {
            item.upper() for item in rules.get("subject_required_on_severity", [])
        }
        if severity.value in subject_severities:
            subject_required = True

        if (
            breach.special_category_involved
            and rules.get("subject_required_on_special_category_high_risk")
            and severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}
        ):
            subject_required = True

        return ico_required, subject_required

    def _generate_reasoning(
        self,
        breach: BreachInput,
        severity: SeverityLevel,
        score: float,
        ico_required: bool,
        subject_required: bool,
    ) -> str:
        data_label = breach.data_type.value.replace("_", " ")
        encryption_note = (
            "Data was encrypted at rest, which reduces overall risk."
            if breach.data_encrypted
            else "Affected data was not encrypted, increasing exposure."
        )
        special_note = (
            "Article 9 special category data is involved, raising regulatory sensitivity."
            if breach.special_category_involved
            else "No Article 9 special category data identified in this assessment."
        )
        return (
            f"Severity assessed as {severity.value} (score {score:.1f}/100) "
            f"for breach {breach.breach_id}. Primary data category: {data_label}, "
            f"affecting approximately {breach.records_affected:,} records. "
            f"{special_note} {encryption_note} "
            f"ICO notification {'required' if ico_required else 'not indicated by score alone'}; "
            f"data subject notification {'required' if subject_required else 'not automatically indicated'}."
        )

    def _generate_recommended_actions(
        self, breach: BreachInput, severity: SeverityLevel
    ) -> list[str]:
        actions = [
            "Preserve forensic evidence and maintain an append-only incident log.",
            "Confirm DPO availability and review the 72-hour ICO notification timeline.",
        ]
        if breach.special_category_involved:
            actions.append(
                "Treat as special category data — escalate to DPO and document Art. 9 considerations."
            )
        if severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}:
            actions.extend(
                [
                    "Prepare a draft ICO notification under Article 33(3) for legal review.",
                    "Assess whether affected individuals must be notified under Article 34.",
                ]
            )
        if severity == SeverityLevel.CRITICAL:
            actions.append(
                "Activate crisis communications plan and brief senior leadership immediately."
            )
        if not breach.data_encrypted:
            actions.append(
                "Review encryption controls for data at rest (Art. 32(1)(a)) as a priority remediation."
            )
        return actions

    def _load_notification_rules(self) -> dict:
        if not self.config_path.is_file():
            return {
                "ico_required_on_special_category": True,
                "ico_required_on_severity": ["MEDIUM", "HIGH", "CRITICAL"],
                "subject_required_on_severity": ["CRITICAL"],
                "subject_required_on_special_category_high_risk": True,
            }
        with self.config_path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload.get("notification_rules", {})
