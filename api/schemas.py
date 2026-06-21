"""
schemas.py
Pydantic request/response models for the API.
"""

from typing import Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    targets: list[str] = Field(..., description="Hosts, IPs, domains, or CIDR ranges to scan")
    ports: list[int] = Field(default=[443], description="TLS ports to check")


class ScanCreated(BaseModel):
    scan_id: str
    status: str


class CertificateResult(BaseModel):
    host: str
    port: int
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_after: Optional[str] = None
    days_until_expiry: Optional[int] = None
    status: Optional[str] = None
    signature_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    flags: Optional[str] = None


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    created_at: str
    target_count: int
    certificates: list[CertificateResult] = []
