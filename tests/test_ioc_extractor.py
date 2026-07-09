from app.ioc_extractor import extract_iocs
from app.models import EmailInput


def test_flags_lookalike_domain_and_urgency():
    email = EmailInput(
        sender='"Microsoft IT Support" <it-support@micros0ft-secure-login.xyz>',
        subject="URGENT: Your account will be suspended within 24 hours",
        body="Please click here to verify: http://micros0ft-secure-login.xyz/verify "
        "Enter your password to confirm your identity.",
    )
    iocs = extract_iocs(email)

    assert iocs.sender_domain == "micros0ft-secure-login.xyz"
    assert iocs.display_name_mismatch is True
    assert iocs.suspicious_tld is True
    assert len(iocs.urls) == 1
    assert "verify your account" in iocs.urgency_phrases or "within 24 hours" in iocs.urgency_phrases
    assert "enter your password" in iocs.credential_harvest_phrases


def test_legit_email_has_no_red_flags():
    email = EmailInput(
        sender='"Sarah Chen" <sarah.chen@triplepointsecurity.com>',
        subject="Notes from today's patch review",
        body="Quick recap from today's meeting. I'll send the updated tracker by Friday.",
    )
    iocs = extract_iocs(email)

    assert iocs.display_name_mismatch is False
    assert iocs.suspicious_tld is False
    assert iocs.lookalike_domain is None
    assert iocs.urgency_phrases == []
    assert iocs.credential_harvest_phrases == []


def test_extracts_raw_ip_addresses():
    email = EmailInput(
        sender="alerts@example.com",
        subject="Login alert",
        body="Login attempt from IP 185.220.101.47 detected.",
    )
    iocs = extract_iocs(email)
    assert "185.220.101.47" in iocs.ip_addresses
