import os

from app.classifier import classify, heuristic_classify
from app.ioc_extractor import extract_iocs
from app.models import EmailInput


def test_heuristic_flags_phishing_as_high_risk():
    email = EmailInput(
        sender='"PayPal Security" <security@paypa1-account-verify.top>',
        subject="Unusual activity - action required",
        body="Please confirm your identity and update your billing information within 24 hours: "
        "http://paypa1-account-verify.top/confirm",
    )
    iocs = extract_iocs(email)
    result = heuristic_classify(email, iocs)

    assert result.engine == "heuristic_fallback"
    assert result.risk_score >= 45
    assert result.verdict in {"likely_phishing", "confirmed_phishing"}


def test_heuristic_scores_legit_email_low():
    email = EmailInput(
        sender='"Sarah Chen" <sarah.chen@triplepointsecurity.com>',
        subject="Notes from today's patch review",
        body="Quick recap from today's meeting. I'll send the updated tracker by Friday.",
    )
    iocs = extract_iocs(email)
    result = heuristic_classify(email, iocs)

    assert result.engine == "heuristic_fallback"
    assert result.risk_score < 20
    assert result.verdict == "benign"


def test_classify_falls_back_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    email = EmailInput(sender="a@b.com", subject="hi", body="just saying hi")
    iocs = extract_iocs(email)
    result = classify(email, iocs)
    assert result.engine == "heuristic_fallback"
