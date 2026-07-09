#!/usr/bin/env python3
"""Command-line entry point: run triage against a sample .eml-style text file
without spinning up the FastAPI server. Useful for quick local testing and
for the test suite.

Usage:
    python cli.py samples/phishing_1.txt
"""
from __future__ import annotations

import sys
from email import message_from_string
from email.policy import default as default_policy

from app.classifier import classify
from app.ioc_extractor import extract_iocs
from app.models import EmailInput
from app.report import render_report


def parse_sample_file(path: str) -> EmailInput:
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    msg = message_from_string(raw, policy=default_policy)
    body = msg.get_body(preferencelist=("plain",))
    body_text = body.get_content() if body else msg.get_payload()
    return EmailInput(
        sender=msg.get("From", "unknown@unknown"),
        subject=msg.get("Subject", "(no subject)"),
        body=body_text,
        reply_to=msg.get("Reply-To"),
    )


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-sample-email>")
        sys.exit(1)

    email = parse_sample_file(sys.argv[1])
    iocs = extract_iocs(email)
    result = classify(email, iocs)
    report = render_report(email, iocs, result)
    print(report)


if __name__ == "__main__":
    main()
