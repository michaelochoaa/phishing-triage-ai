"""Static (non-LLM) indicator-of-compromise extraction for raw email content.

This module does the deterministic, explainable part of triage: regex-based
extraction plus a small set of well-known heuristics (lookalike domains,
urgency language, credential-harvest language, suspicious TLDs). Keeping this
separate from the LLM classifier means the service still produces useful,
auditable signal even with no OpenAI API key configured, and gives the LLM
step structured evidence to reason over instead of raw text alone.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import List, Optional

from app.models import EmailInput, IOCReport

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_ADDR_RE = re.compile(r"<?([\w.+-]+@[\w-]+\.[\w.-]+)>?")
DISPLAY_NAME_RE = re.compile(r'^"?([^"<]*)"?\s*<.+>$')

# Brands commonly impersonated in phishing campaigns, mapped to their real
# apex domain. Used for both display-name mismatch and lookalike-domain checks.
KNOWN_BRANDS = {
    "microsoft": "microsoft.com",
    "office 365": "microsoft.com",
    "outlook": "microsoft.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "docusign": "docusign.com",
    "bank of america": "bankofamerica.com",
    "wells fargo": "wellsfargo.com",
    "chase": "chase.com",
    "netflix": "netflix.com",
    "it support": "microsoft.com",  # generic internal-IT spoof, common in real campaigns
    "google": "google.com",
    "linkedin": "linkedin.com",
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ru", ".click", ".zip", ".gq", ".work", ".loan", ".men"}

URGENCY_PHRASES = [
    "act now", "immediate action required", "your account will be suspended",
    "verify your account", "urgent", "as soon as possible", "final notice",
    "account has been locked", "unusual activity", "within 24 hours",
    "failure to comply", "your account will be closed", "response required",
]

CREDENTIAL_HARVEST_PHRASES = [
    "enter your password", "confirm your login", "update your billing information",
    "click here to verify", "reset your password", "confirm your identity",
    "provide your credentials", "sign in to continue", "validate your account",
]


def _extract_domain(address: str) -> Optional[str]:
    match = EMAIL_ADDR_RE.search(address)
    if not match:
        return None
    return match.group(1).split("@")[-1].lower()


def _extract_display_name(sender_header: str) -> Optional[str]:
    match = DISPLAY_NAME_RE.match(sender_header.strip())
    if match:
        name = match.group(1).strip()
        return name or None
    return None


def _similar(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


LEETSPEAK_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "4": "a"})


def _normalize_leetspeak(value: str) -> str:
    """Undo common character-substitution tricks (micros0ft -> microsoft,
    payp4l -> paypal) so lookalike matching catches them like a human would."""
    return value.translate(LEETSPEAK_MAP)


def _check_lookalike(domain: Optional[str]) -> Optional[str]:
    """Return the brand name a domain appears to impersonate, if it's a close
    but non-exact match to a known brand's apex domain (e.g. paypa1-secure.com,
    micros0ft-secure-login.xyz)."""
    if not domain:
        return None
    normalized = _normalize_leetspeak(domain)
    for brand, real_domain in KNOWN_BRANDS.items():
        if domain == real_domain:
            continue  # it IS the real domain, not a lookalike
        root = real_domain.split(".")[0]
        if root in domain or root in normalized:
            if domain != real_domain:
                return brand
        if _similar(domain, real_domain) > 0.75 or _similar(normalized, real_domain) > 0.75:
            return brand
        # root-only comparison catches "micros0ft-secure-login.xyz" against "microsoft"
        domain_root = normalized.split(".")[0].split("-")[0]
        if _similar(domain_root, root) > 0.8:
            return brand
    return None


def _check_display_name_mismatch(display_name: Optional[str], domain: Optional[str]) -> bool:
    if not display_name or not domain:
        return False
    display_lower = display_name.lower()
    for brand, real_domain in KNOWN_BRANDS.items():
        if brand in display_lower and domain != real_domain:
            return True
    return False


def extract_iocs(email: EmailInput) -> IOCReport:
    text = f"{email.subject}\n{email.body}"
    text_lower = text.lower()

    urls = URL_RE.findall(text)
    ips = IP_RE.findall(text)

    domain = _extract_domain(email.sender)
    display_name = _extract_display_name(email.sender)

    suspicious_tld = bool(domain and any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS))
    lookalike = _check_lookalike(domain)
    mismatch = _check_display_name_mismatch(display_name, domain)

    urgency_hits = [p for p in URGENCY_PHRASES if p in text_lower]
    cred_hits = [p for p in CREDENTIAL_HARVEST_PHRASES if p in text_lower]

    return IOCReport(
        urls=urls,
        ip_addresses=ips,
        sender_domain=domain,
        display_name=display_name,
        display_name_mismatch=mismatch,
        urgency_phrases=urgency_hits,
        credential_harvest_phrases=cred_hits,
        suspicious_tld=suspicious_tld,
        lookalike_domain=lookalike,
    )
