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
        raise NotImplementedError("NIST breach mapping not yet implemented.")

    def _load_mappings(self) -> dict:
        if self._config is None:
            with self.config_path.open(encoding="utf-8") as handle:
                self._config = json.load(handle)
        return self._config

    def _identify_failed_controls(
        self, breach_type: BreachType, severity: SeverityLevel
    ) -> list[ControlFailure]:
        raise NotImplementedError

    def _generate_recommendations(
        self,
        failed_controls: list[ControlFailure],
        severity: SeverityLevel,
    ) -> list[ControlRecommendation]:
        raise NotImplementedError

    def _get_impacted_functions(self, breach_type: BreachType) -> list[NISTFunction]:
        raise NotImplementedError
