"""eml_parser ve email_auth modül testleri."""

import tempfile
from pathlib import Path

import pytest

from phishlens.eml_parser import parse_eml
from phishlens import analyze_eml_file, PhishLensError


def test_parse_eml_minimal():
    eml = b"""From: test@example.com
Subject: Test
Received: from [192.168.1.1]

Body content.
"""
    data = parse_eml(eml)
    assert data["sender_email"] == "test@example.com"
    assert data["sender_domain"] == "example.com"
    assert "192.168.1.1" in data["received_ips"]
    assert "Body content" in data["body"]


def test_parse_eml_multipart():
    eml = b"""From: a@b.com
Content-Type: multipart/alternative; boundary=x

--x
Content-Type: text/plain

Plain text body.
--x--
"""
    data = parse_eml(eml)
    assert "Plain text body" in data["body"]


def test_analyze_eml_file():
    eml = b"""From: phishing@fake.xyz
Subject: Acil
Received: from [10.0.0.1]

Kartiniz bloke! Hemen https://fake.xyz/link
"""
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
        f.write(eml)
        path = f.name
    try:
        result = analyze_eml_file(path, use_api=False)
        assert "risk" in result
        assert "score" in result
        assert "eml_metadata" in result
        assert "email_auth" in result
        assert result["eml_metadata"]["sender_domain"] == "fake.xyz"
    finally:
        Path(path).unlink(missing_ok=True)


def test_analyze_eml_file_not_found():
    with pytest.raises(PhishLensError):
        analyze_eml_file("/nonexistent/path.eml")
