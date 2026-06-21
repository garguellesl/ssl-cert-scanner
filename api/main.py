"""
api/main.py
REST API for ssl-cert-scanner: turns the CLI tool into a service that
can trigger scans on demand and expose results to other systems
(dashboards, CMDBs, scheduled automation jobs). This is what lets the
scanner be embedded as a feature of a larger certificate management
platform instead of a one-off script.

Run locally with:
    uvicorn api.main:app --reload

Endpoints:
    GET  /health                 liveness probe
    POST /scans                  start a new scan (async, returns immediately)
    GET  /scans/{scan_id}        check status / results of a scan
    GET  /certificates           latest known state of every host:port ever scanned
"""

import uuid

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query

from ssl_cert_scanner import analyzer, scanner

from . import storage
from .schemas import CertificateResult, ScanCreated, ScanRequest, ScanStatus

app = FastAPI(
    title="ssl-cert-scanner API",
    description="On-demand TLS certificate discovery, analysis, and monitoring.",
    version="0.1.0",
)


@app.on_event("startup")
def on_startup() -> None:
    storage.init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


def _run_scan(scan_id: str, targets: list[str], ports: list[int]) -> None:
    """Executed in the background so the HTTP request returns immediately."""
    try:
        raw_certs = scanner.discover(targets, ports=ports)
        results = [
            analyzer.analyze_certificate(c["der"], c["host"], c["port"])
            for c in raw_certs
        ]
        storage.complete_scan(scan_id, results)
    except Exception as exc:  # noqa: BLE001 - we want to persist any failure, not crash the worker
        storage.fail_scan(scan_id, str(exc))


@app.post("/scans", response_model=ScanCreated, status_code=202)
def create_scan(req: ScanRequest, background_tasks: BackgroundTasks) -> ScanCreated:
    """
    Starts a scan in the background and returns immediately with a
    scan_id. Poll GET /scans/{scan_id} for the result - scanning a
    CIDR range can take longer than is reasonable for a single
    synchronous HTTP request.
    """
    if not req.targets:
        raise HTTPException(status_code=400, detail="targets must not be empty")

    scan_id = str(uuid.uuid4())
    storage.create_scan(scan_id, target_count=len(req.targets))
    background_tasks.add_task(_run_scan, scan_id, req.targets, req.ports)
    return ScanCreated(scan_id=scan_id, status="pending")


@app.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan(scan_id: str) -> ScanStatus:
    data = storage.get_scan(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatus(
        scan_id=data["scan"]["id"],
        status=data["scan"]["status"],
        created_at=data["scan"]["created_at"],
        target_count=data["scan"]["target_count"],
        certificates=[CertificateResult(**c) for c in data["certificates"]],
    )


@app.get("/certificates", response_model=list[CertificateResult])
def list_certificates(
    status: str | None = Query(default=None, description="Filter by status: ok, warning, critical, expired"),
) -> list[CertificateResult]:
    """Returns the latest known state for every host:port pair ever scanned."""
    certs = storage.list_latest_certificates()
    if status:
        certs = [c for c in certs if c["status"] == status]
    return [CertificateResult(**c) for c in certs]
