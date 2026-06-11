"""NIST Cybersecurity Framework v1.1 breach-to-control mapper."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from src.models.breach_model import BreachType, DataType, SeverityLevel

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


class NISTFunction(str, Enum):
    """NIST CSF v1.1 core functions."""

    IDENTIFY = "IDENTIFY"
    PROTECT = "PROTECT"
    DETECT = "DETECT"
    RESPOND = "RESPOND"
    RECOVER = "RECOVER"


@dataclass
class ControlFailure:
    """A NIST control that failed during the breach."""

    function: NISTFunction
    category: str
    subcategory: str
    description: str
    gdpr_article: str


@dataclass
class ControlRecommendation:
    """A recommended remediation mapped to NIST and GDPR."""

    function: NISTFunction
    category: str
    subcategory: str
    recommendation: str
    priority: str
    gdpr_article: str


@dataclass
class NISTMappingResult:
    """Full NIST CSF mapping output for a breach."""

    framework_reference: str
    functions_impacted: list[NISTFunction]
    failed_controls: list[ControlFailure]
    recommended_controls: list[ControlRecommendation]


class NISTMapper:
    """Maps breach characteristics to NIST CSF failed controls and remediations."""

    def __init__(self, config_path: Path = CONFIG_DIR / "nist_mappings.json") -> None:
        self.config_path = config_path
        self._config: dict | None = None

    def map_breach(
        self,
        breach_type: BreachType,
        data_type: DataType,
        severity: SeverityLevel,
        root_cause: str = "",
    ) -> NISTMappingResult:
        """Return failed controls and recommendations for the given breach profile."""
        config = self._load_mappings()
        mapping_key = breach_type.name
        mappings = config.get("breach_type_mappings", {})
        if mapping_key not in mappings:
            raise ValueError(f"Unknown breach type mapping: {breach_type.value}")

        mapping = mappings[mapping_key]
        failed_controls = self._identify_failed_controls(breach_type, severity)
        recommended_controls = self._generate_recommendations(
            breach_type, failed_controls, severity
        )

        return NISTMappingResult(
            framework_reference=config.get("version", "NIST CSF v1.1"),
            functions_impacted=self._get_impacted_functions(breach_type),
            failed_controls=failed_controls,
            recommended_controls=recommended_controls,
        )

    def _load_mappings(self) -> dict:
        if self._config is None:
            with self.config_path.open(encoding="utf-8") as handle:
                self._config = json.load(handle)
        return self._config

    def _identify_failed_controls(
        self, breach_type: BreachType, severity: SeverityLevel
    ) -> list[ControlFailure]:
        config = self._load_mappings()
        mapping = config["breach_type_mappings"][breach_type.name]
        failures = [self._parse_failure(entry) for entry in mapping.get("failed_controls", [])]

        escalations = config.get("severity_escalations", {}).get(severity.name, [])
        existing = {item.subcategory for item in failures}
        for subcategory in escalations:
            if subcategory not in existing:
                failures.append(self._escalation_failure(subcategory))
                existing.add(subcategory)

        return failures

    def _generate_recommendations(
        self,
        breach_type: BreachType,
        failed_controls: list[ControlFailure],
        severity: SeverityLevel,
    ) -> list[ControlRecommendation]:
        config = self._load_mappings()
        mapping = config["breach_type_mappings"][breach_type.name]
        recommendations = [
            self._parse_recommendation(entry) for entry in mapping.get("recommendations", [])
        ]

        if severity == SeverityLevel.CRITICAL and not any(
            item.priority == "IMMEDIATE" for item in recommendations
        ):
            recommendations.append(
                ControlRecommendation(
                    function=NISTFunction.RESPOND,
                    category="RS.RP",
                    subcategory="RS.RP-1",
                    recommendation="Execute incident response plan and document regulatory notifications",
                    priority="IMMEDIATE",
                    gdpr_article="Art. 33(1)",
                )
            )

        return recommendations

    def _get_impacted_functions(self, breach_type: BreachType) -> list[NISTFunction]:
        config = self._load_mappings()
        mapping = config["breach_type_mappings"][breach_type.name]
        return [NISTFunction(name) for name in mapping.get("primary_functions", [])]

    @staticmethod
    def _parse_failure(entry: dict) -> ControlFailure:
        return ControlFailure(
            function=NISTFunction(entry["function"]),
            category=entry["category"],
            subcategory=entry["subcategory"],
            description=entry["description"],
            gdpr_article=entry["gdpr_article"],
        )

    @staticmethod
    def _parse_recommendation(entry: dict) -> ControlRecommendation:
        return ControlRecommendation(
            function=NISTFunction(entry["function"]),
            category=entry["category"],
            subcategory=entry["subcategory"],
            recommendation=entry["recommendation"],
            priority=entry["priority"],
            gdpr_article=entry["gdpr_article"],
        )

    @staticmethod
    def _escalation_failure(subcategory: str) -> ControlFailure:
        category = subcategory.rsplit("-", 1)[0]
        function_prefix = category.split(".")[0]
        function_map = {
            "ID": NISTFunction.IDENTIFY,
            "PR": NISTFunction.PROTECT,
            "DE": NISTFunction.DETECT,
            "RS": NISTFunction.RESPOND,
            "RC": NISTFunction.RECOVER,
        }
        return ControlFailure(
            function=function_map.get(function_prefix, NISTFunction.RESPOND),
            category=category,
            subcategory=subcategory,
            description=f"Severity escalation — control {subcategory} requires immediate attention",
            gdpr_article="Art. 32 — security of processing",
        )
