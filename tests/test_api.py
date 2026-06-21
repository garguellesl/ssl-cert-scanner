"""
test_api.py
API tests using FastAPI's TestClient. These run in CI (see
.github/workflows/ci.yml) where fastapi/httpx are installed; they are
skipped locally if those packages aren't available, so the rest of
the test suite still runs fine in a minimal environment.
"""

import importlib.util
import os
import time

import pytest

if importlib.util.find_spec("fastapi") is None:
    pytest.skip("fastapi not installed in this environment", allow_module_level=True)

from fastapi.testclient import TestClient  # noqa: E402

os.environ.setdefault("SSL_CERT_SCANNER_TEST_DB", "1")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from api import storage

    # Point storage at a throwaway DB so tests never touch the real one.
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "test_api.db")

    from api.main import app

    storage.init_db()
    return TestClient(app)


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_create_scan_returns_pending(client):
    resp = client.post("/scans", json={"targets": ["127.0.0.1"], "ports": [65000]})
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "pending"
    assert "scan_id" in body


def test_scan_eventually_completes(client):
    resp = client.post("/scans", json={"targets": ["127.0.0.1"], "ports": [65000]})
    scan_id = resp.json()["scan_id"]

    # The scan runs in a background task; poll briefly until it's done.
    # Port 65000 on localhost has nothing listening, so this resolves
    # fast with zero certificates found - that's still a "completed" scan.
    for _ in range(20):
        status_resp = client.get(f"/scans/{scan_id}")
        if status_resp.json()["status"] != "pending":
            break
        time.sleep(0.2)

    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "completed"


def test_get_unknown_scan_returns_404(client):
    resp = client.get("/scans/does-not-exist")
    assert resp.status_code == 404


def test_create_scan_rejects_empty_targets(client):
    resp = client.post("/scans", json={"targets": [], "ports": [443]})
    assert resp.status_code == 400
