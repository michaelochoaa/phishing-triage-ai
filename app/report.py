"""Renders a human-readable analyst report from IOC + classification results.

This is the artifact a SOC analyst actually reads. Keeping report rendering
separate from classification logic means the report format can change
(Markdown today, could be Slack blocks or a PDF tomorrow) without touching
any detection logic.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.models import ClassificationResult, EmailInput, IOCReport

VERDICT_EMOJI_FREE_LABEL = {
    "benign": "BENIGN",
    "suspicious": "SUSPICIOUS",
    "likely_phishing": "LIKELY PHISHING",
    "confirmed_phishing": "CONFIRMED PHISHING",
}


def render_report(email: EmailInput, iocs: IOCReport, result: ClassificationResult) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    label = VERDICT_EMOJI_FREE_LABEL.get(result.verdict, result.verdict.upper())

    lines = [
        f"# Phishing Triage Report",
        f"",
        f"**Generated:** {ts}  ",
        f"**Engine:** {result.engine}  ",
        f"**Verdict:** {label}  ",
        f"**Risk score:** {result.risk_score}/100",
        f"",
        f"## Message",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| From | {email.sender} |",
        f"| Subject | {email.subject} |",
        f"| Reply-To | {email.reply_to or '-'} |",
        f"",
        f"## Analyst Summary",
        f"",
        f"{result.reasoning}",
        f"",
        f"**Recommended action:** {result.recommended_action}",
        f"",
        f"## Indicators of Compromise",
        f"",
        f"- Sender domain: `{iocs.sender_domain or 'unknown'}`",
        f"- Display name: {iocs.display_name or '-'}",
        f"- Display name / domain mismatch: {'YES' if iocs.display_name_mismatch else 'no'}",
        f"- Lookalike / impersonated brand: {iocs.lookalike_domain or 'none detected'}",
        f"- Suspicious TLD: {'YES' if iocs.suspicious_tld else 'no'}",
        f"- URLs found: {len(iocs.urls)}",
    ]
    for url in iocs.urls:
        lines.append(f"  - `{url}`")
    lines.append(f"- Raw IP addresses referenced: {len(iocs.ip_addresses)}")
    for ip in iocs.ip_addresses:
        lines.append(f"  - `{ip}`")
    if iocs.urgency_phrases:
        lines.append(f"- Urgency language: {', '.join(iocs.urgency_phrases)}")
    if iocs.credential_harvest_phrases:
        lines.append(f"- Credential-harvest language: {', '.join(iocs.credential_harvest_phrases)}")

    return "\n".join(lines) + "\n"
