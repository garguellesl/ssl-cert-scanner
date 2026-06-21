"""
analyzer.py
Extracts x.509 metadata from a certificate and evaluates risk
signals: upcoming expiry, weak signature algorithms, short keys,
and self-signed certificates.
"""

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

WEAK_SIGNATURE_ALGORITHMS = {"md5", "sha1"}
MIN_RSA_KEY_SIZE = 2048

CRITICAL_DAYS = 7
WARNING_DAYS = 30


def _not_valid_before(cert: x509.Certificate) -> datetime:
    # cryptography >= 42 exposes the "_utc" variants; older versions
    # use the naive equivalent attribute.
    return getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)


def _not_valid_after(cert: x509.Certificate) -> datetime:
    return getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)


def classify(days_left: int) -> str:
    if days_left < 0:
        return "expired"
    if days_left <= CRITICAL_DAYS:
        return "critical"
    if days_left <= WARNING_DAYS:
        return "warning"
    return "ok"


def analyze_certificate(der_bytes: bytes, host: str, port: int) -> dict:
    cert = x509.load_der_x509_certificate(der_bytes, default_backend())

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    not_before = _not_valid_before(cert)
    not_after = _not_valid_after(cert)
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_list = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_list = []

    sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"

    public_key = cert.public_key()
    key_size = getattr(public_key, "key_size", None)

    flags = []
    if days_left < 0:
        flags.append("EXPIRED")
    elif days_left <= CRITICAL_DAYS:
        flags.append("CRITICAL_EXPIRY")
    elif days_left <= WARNING_DAYS:
        flags.append("WARNING_EXPIRY")

    if sig_algo.lower() in WEAK_SIGNATURE_ALGORITHMS:
        flags.append(f"WEAK_SIGNATURE_ALGORITHM({sig_algo})")

    if key_size and key_size < MIN_RSA_KEY_SIZE:
        flags.append(f"WEAK_KEY({key_size}bits)")

    if subject == issuer:
        flags.append("SELF_SIGNED")

    fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

    return {
        "host": host,
        "port": port,
        "subject": subject,
        "issuer": issuer,
        "san": san_list,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_left,
        "status": classify(days_left),
        "signature_algorithm": sig_algo,
        "key_size": key_size,
        "serial_number": format(cert.serial_number, "x"),
        "fingerprint_sha256": fingerprint_sha256,
        "flags": flags,
    }
