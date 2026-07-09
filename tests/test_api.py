from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_analyze_endpoint_returns_full_shape():
    payload = {
        "sender": '"Microsoft IT Support" <it-support@micros0ft-secure-login.xyz>',
        "subject": "URGENT: verify your account",
        "body": "Click here to verify: http://micros0ft-secure-login.xyz/verify. "
        "Enter your password to confirm your identity.",
    }
    resp = client.post("/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "iocs" in data
    assert "classification" in data
    assert "analyst_report_markdown" in data
    assert data["classification"]["risk_score"] >= 45
