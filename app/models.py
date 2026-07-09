"""Pydantic data models shared across the phishing triage service."""
from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class EmailInput(BaseModel):
    """Raw email content submitted for analysis."""

    sender: str = Field(..., description="Raw From: header, e.g. 'IT Support <support@paypa1-secure.com>'")
    subject: str = Field(..., description="Email subject line")
    body: str = Field(..., description="Plain-text email body")
    reply_to: Optional[str] = Field(None, description="Reply-To: header, if present")
    received_headers: Optional[List[str]] = Field(
        default=None, description="Raw Received: header lines, if available, for hop analysis"
    )


class IOCReport(BaseModel):
    """Indicators of compromise extracted via static analysis (no LLM call)."""

    urls: List[str] = Field(default_factory=list)
    ip_addresses: List[str] = Field(default_factory=list)
    sender_domain: Optional[str] = None
    display_name: Optional[str] = None
    display_name_mismatch: bool = Field(
        False, description="True if the display name impersonates a brand not matching the sender domain"
    )
    urgency_phrases: List[str] = Field(default_factory=list)
    credential_harvest_phrases: List[str] = Field(default_factory=list)
    suspicious_tld: bool = False
    lookalike_domain: Optional[str] = Field(
        None, description="Known brand this sender domain appears to impersonate, if any"
    )


class ClassificationResult(BaseModel):
    """Final risk verdict for the email, whether produced by the LLM or the heuristic fallback."""

    risk_score: int = Field(..., ge=0, le=100, description="0 = benign, 100 = confirmed phishing")
    verdict: str = Field(..., description="One of: benign, suspicious, likely_phishing, confirmed_phishing")
    reasoning: str = Field(..., description="Human-readable explanation of the verdict")
    recommended_action: str = Field(..., description="What a SOC analyst should do next")
    engine: str = Field(..., description="'openai' or 'heuristic_fallback'")


class AnalysisResponse(BaseModel):
    """Full API response: IOCs + classification + rendered analyst report."""

    iocs: IOCReport
    classification: ClassificationResult
    analyst_report_markdown: str
