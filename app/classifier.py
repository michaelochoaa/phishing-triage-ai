"""Risk classification: LLM-based when an OpenAI API key is configured,
otherwise a transparent, weighted heuristic fallback.

Design note: the heuristic fallback is not a lesser demo mode bolted on for
convenience, it's what keeps this service usable and testable without paid
API access, and it also acts as a sanity baseline the LLM path can be
compared against. The IOC extraction (app/ioc_extractor.py) always runs
first and is passed into the LLM prompt as grounding evidence, so the model
is reasoning over structured facts rather than guessing from raw text alone.
"""
from __future__ import annotations

import json
import os
from typing import Optional

from app.models import ClassificationResult, EmailInput, IOCReport

OPENAI_MODEL = os.environ.get("PHISH_TRIAGE_MODEL", "gpt-4o-mini")

SYSTEM_PROMPT = """You are a SOC email security analyst. You are given the raw contents of a \
suspicious email plus a set of indicators of compromise (IOCs) already extracted by static \
analysis. Decide how likely this email is to be phishing.

Respond with ONLY a JSON object matching this exact schema, no prose outside the JSON:
{
  "risk_score": <integer 0-100, 0 = definitely benign, 100 = confirmed phishing>,
  "verdict": <one of "benign", "suspicious", "likely_phishing", "confirmed_phishing">,
  "reasoning": <2-4 sentences citing the specific evidence that drove your score>,
  "recommended_action": <one concrete next step for the analyst, e.g. "Block sender domain and \
notify affected users" or "No action needed, monitor only">
}
"""


def _verdict_from_score(score: int) -> str:
    if score >= 75:
        return "confirmed_phishing"
    if score >= 45:
        return "likely_phishing"
    if score >= 20:
        return "suspicious"
    return "benign"


def _recommended_action(verdict: str) -> str:
    return {
        "confirmed_phishing": "Block sender domain/IP, quarantine the message org-wide, and notify any users who received it.",
        "likely_phishing": "Quarantine the message, block the sender domain, and escalate to a senior analyst for confirmation.",
        "suspicious": "Hold for manual review; do not deliver to inbox until an analyst confirms intent.",
        "benign": "No action needed. Allow delivery.",
    }[verdict]


def heuristic_classify(email: EmailInput, iocs: IOCReport) -> ClassificationResult:
    """Deterministic, explainable scoring used when no OpenAI API key is set."""
    score = 0
    reasons = []

    if iocs.lookalike_domain:
        score += 35
        reasons.append(f"sender domain appears to impersonate '{iocs.lookalike_domain}'")
    if iocs.display_name_mismatch:
        score += 25
        reasons.append("display name references a brand that doesn't match the sending domain")
    if iocs.suspicious_tld:
        score += 15
        reasons.append("sender domain uses a TLD commonly abused for disposable/cheap registrations")
    if iocs.credential_harvest_phrases:
        score += min(30, 10 * len(iocs.credential_harvest_phrases))
        reasons.append(f"contains credential-harvesting language ({', '.join(iocs.credential_harvest_phrases)})")
    if iocs.urgency_phrases:
        score += min(20, 5 * len(iocs.urgency_phrases))
        reasons.append(f"uses urgency/pressure language ({', '.join(iocs.urgency_phrases)})")
    if iocs.ip_addresses:
        score += 15
        reasons.append("references raw IP address(es) rather than a hostname")

    score = min(score, 100)
    verdict = _verdict_from_score(score)

    reasoning = (
        "No indicators of compromise were found; message appears benign."
        if not reasons
        else "Flagged because the message " + "; ".join(reasons) + "."
    )

    return ClassificationResult(
        risk_score=score,
        verdict=verdict,
        reasoning=reasoning,
        recommended_action=_recommended_action(verdict),
        engine="heuristic_fallback",
    )


def _openai_classify(email: EmailInput, iocs: IOCReport) -> Optional[ClassificationResult]:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None

    try:
        from openai import OpenAI
    except ImportError:
        return None

    client = OpenAI(api_key=api_key)

    user_content = (
        f"SENDER: {email.sender}\n"
        f"SUBJECT: {email.subject}\n"
        f"BODY:\n{email.body}\n\n"
        f"EXTRACTED IOCs (from static analysis, already computed, trust these):\n"
        f"{iocs.model_dump_json(indent=2)}"
    )

    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    )

    payload = json.loads(response.choices[0].message.content)
    return ClassificationResult(
        risk_score=int(payload["risk_score"]),
        verdict=payload["verdict"],
        reasoning=payload["reasoning"],
        recommended_action=payload["recommended_action"],
        engine="openai",
    )


def classify(email: EmailInput, iocs: IOCReport) -> ClassificationResult:
    """Try the OpenAI path first; fall back to heuristics if no key is set,
    the SDK isn't installed, or the API call fails for any reason. A triage
    tool that goes down because a third-party API hiccuped is worse than one
    that degrades gracefully."""
    try:
        result = _openai_classify(email, iocs)
        if result is not None:
            return result
    except Exception:
        pass
    return heuristic_classify(email, iocs)
