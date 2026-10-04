"""Strict request and response contracts for the audit API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    """Reject undeclared fields and implicit type conversions."""

    model_config = ConfigDict(extra="forbid", strict=True)


class AuditRequest(StrictModel):
    """Code or a Git patch to inspect, with its source language."""

    diff_content: str = Field(min_length=1, max_length=200_000)
    language: str = Field(min_length=1, max_length=50)

    @field_validator("diff_content", "language")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        """Reject whitespace-only inputs while preserving source line numbers."""
        if not value.strip():
            raise ValueError("must contain non-whitespace characters")
        return value


class Vulnerability(StrictModel):
    """A validated security finding from either analysis engine."""

    severity: Literal["HIGH", "MEDIUM", "LOW"]
    category: str = Field(min_length=1)
    description: str = Field(min_length=1)
    line_reference: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    tainted: bool = False


class AuditResponse(StrictModel):
    """The aggregated result of one audit."""

    status: Literal["PASSED", "FAILED"]
    risk_score: int = Field(ge=0, le=100)
    vulnerabilities: list[Vulnerability]
    summary: str = Field(min_length=1)
    static_count: int = Field(ge=0)
    ai_count: int = Field(ge=0)
    latency_ms: float = Field(ge=0)
    model_used: str = Field(min_length=1)


class LLMFinding(Vulnerability):
    """An Ollama finding requires an explicit calibrated confidence value."""

    confidence: float = Field(ge=0.0, le=1.0)
