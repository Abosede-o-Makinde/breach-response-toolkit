"""Pydantic models for breach input validation and classification output."""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, EmailStr, Field, field_validator


class DataType(str, Enum):
    """Categories of personal data involved in a breach."""

    BASIC_CONTACT = "basic_contact"
    FINANCIAL = "financial"
    HEALTH = "health"
    BIOMETRIC = "biometric"
    CRIMINAL = "criminal"
    CREDENTIALS = "credentials"


class BreachType(str, Enum):
    """CIA triad breach classification."""

    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    COMBINED = "combined"


class SeverityLevel(str, Enum):
    """Breach severity bands derived from the 4-dimension scoring model."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DPOContact(BaseModel):
    """Data Protection Officer or breach contact point (Article 33(3)(b))."""

    name: str
    role: str = "Data Protection Officer"
    email: EmailStr
    telephone: str


class BreachInput(BaseModel):
    """Validated breach incident input — all external data passes through this model."""

    breach_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,50}$")]
    detection_datetime: datetime
    data_type: DataType
    records_affected: int = Field(ge=0)
    special_category_involved: bool = False
    data_encrypted: bool = False
    breach_type: BreachType
    description: str = Field(min_length=20)
    affected_data_categories: list[str] = Field(min_length=1)
    estimated_data_subjects: int = Field(ge=0)
    estimated_records: int = Field(ge=0)
    root_cause: str = ""
    dpo_contact: DPOContact
    likely_consequences: list[str] = Field(min_length=1)
    measures_taken: list[str] = Field(min_length=1)
    controller_name: str
    ico_registration_number: str = ""
    controller_address: str

    @field_validator("ico_registration_number")
    @classmethod
    def validate_ico_registration(cls, value: str) -> str:
        if value and not re.match(r"^Z[A-Z][0-9]{6}$", value):
            raise ValueError("ICO registration number format invalid")
        return value


class ScoreBreakdown(BaseModel):
    """Per-dimension severity score components."""

    data_type_score: float = Field(ge=0, le=45)
    scale_score: float = Field(ge=0, le=25)
    special_category_bonus: float = Field(ge=0, le=20)
    encryption_reduction: float = Field(ge=-15, le=0)
    total: float = Field(ge=0, le=100)


class ClassificationResult(BaseModel):
    """Output of the breach severity classifier."""

    severity: SeverityLevel
    score: float = Field(ge=0, le=100)
    breakdown: ScoreBreakdown
    ico_notification_required: bool
    subject_notification_required: bool
    reasoning: str = Field(min_length=50)
    recommended_actions: list[str] = Field(min_length=1)
