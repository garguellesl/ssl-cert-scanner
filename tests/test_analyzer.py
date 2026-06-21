"""
test_analyzer.py
Tests for the analyzer that do NOT require network access: we
generate self-signed certificates in memory with different parameters
(validity period, key size) and check that analyzer.py classifies
them correctly.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ssl_cert_scanner.analyzer import analyze_certificate


def _make_self_signed_cert(days_valid: int = 10, key_size: int = 2048) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    # If days_valid is negative (already-expired cert), not_valid_before
    # still has to be earlier than not_valid_after.
    not_before_offset = max(1, abs(days_valid) + 1)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=not_before_offset))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.local")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_detects_self_signed():
    der = _make_self_signed_cert()
    result = analyze_certificate(der, "test.local", 443)
    assert "SELF_SIGNED" in result["flags"]


def test_detects_critical_expiry():
    der = _make_self_signed_cert(days_valid=5)
    result = analyze_certificate(der, "test.local", 443)
    assert result["days_until_expiry"] <= 7
    assert "CRITICAL_EXPIRY" in result["flags"]


def test_detects_warning_expiry():
    der = _make_self_signed_cert(days_valid=20)
    result = analyze_certificate(der, "test.local", 443)
    assert "WARNING_EXPIRY" in result["flags"]


def test_healthy_certificate_has_no_expiry_flags():
    der = _make_self_signed_cert(days_valid=180)
    result = analyze_certificate(der, "test.local", 443)
    expiry_flags = [f for f in result["flags"] if "EXPIR" in f]
    assert expiry_flags == []
    assert result["status"] == "ok"


def test_detects_weak_key_size():
    der = _make_self_signed_cert(days_valid=180, key_size=1024)
    result = analyze_certificate(der, "test.local", 443)
    assert any("WEAK_KEY" in f for f in result["flags"])


def test_metadata_fields_present():
    der = _make_self_signed_cert()
    result = analyze_certificate(der, "test.local", 443)
    for field in ("subject", "issuer", "san", "fingerprint_sha256", "serial_number"):
        assert field in result
    assert "test.local" in result["san"]
