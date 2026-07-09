"""FastAPI service: POST an email, get back IOCs, a risk verdict, and a
rendered analyst report. See README.md for setup and example requests."""
from __future__ import annotations

from fastapi import FastAPI

from app.classifier import classify
from app.ioc_extractor import extract_iocs
from app.models import AnalysisResponse, EmailInput
from app.report import render_report

app = FastAPI(
    title="Phishing Triage API",
    description="Extracts IOCs from a raw email and classifies phishing risk "
    "using an LLM (OpenAI) when configured, with a deterministic heuristic "
    "fallback otherwise.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResponse)
def analyze(email: EmailInput) -> AnalysisResponse:
    iocs = extract_iocs(email)
    result = classify(email, iocs)
    report = render_report(email, iocs, result)
    return AnalysisResponse(iocs=iocs, classification=result, analyst_report_markdown=report)
