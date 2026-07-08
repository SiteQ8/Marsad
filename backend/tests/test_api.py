"""End-to-end API tests exercising auth, RBAC, workflow and scanner import."""
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

# Isolated temp DB per test session.
_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"

from app.main import app  # noqa: E402
from app.database import init_db, SessionLocal  # noqa: E402
from app import models  # noqa: E402
from app.auth import hash_password  # noqa: E402

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_users():
    init_db()
    db = SessionLocal()
    db.add_all([
        models.User(email="admin@t.local", full_name="Admin", role=models.Role.admin,
                    hashed_password=hash_password("password123")),
        models.User(email="analyst@t.local", full_name="Analyst", role=models.Role.analyst,
                    hashed_password=hash_password("password123")),
        models.User(email="viewer@t.local", full_name="Viewer", role=models.Role.viewer,
                    hashed_password=hash_password("password123")),
    ])
    db.commit(); db.close()
    yield
    os.close(_db_fd); os.unlink(_db_path)


def tok(email):
    r = client.post("/api/auth/login", data={"username": email, "password": "password123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_health():
    assert client.get("/api/health").json()["status"] == "ok"


def test_login_bad_password():
    r = client.post("/api/auth/login", data={"username": "admin@t.local", "password": "wrong"})
    assert r.status_code == 401


def test_viewer_cannot_create_asset():
    r = client.post("/api/assets", json={"name": "x"}, headers=tok("viewer@t.local"))
    assert r.status_code == 403


def test_analyst_can_create_asset_and_vuln_scores_cvss():
    h = tok("analyst@t.local")
    a = client.post("/api/assets", json={"name": "srv1", "ip_address": "10.0.0.1",
                                         "criticality": 4, "internet_facing": True}, headers=h)
    assert a.status_code == 201
    v = client.post("/api/vulnerabilities", json={
        "title": "Test RCE", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }, headers=h)
    assert v.status_code == 201
    body = v.json()
    assert body["cvss_score"] == 9.8 and body["severity"] == "Critical"

    f = client.post("/api/findings", json={"asset_id": a.json()["id"],
                                           "vulnerability_id": body["id"]}, headers=h)
    assert f.status_code == 201
    # crit(4) * internet-facing on a 9.8 → capped at 100
    assert f.json()["risk_score"] == 100.0


def test_invalid_cvss_rejected():
    r = client.post("/api/vulnerabilities", json={"title": "bad", "cvss_vector": "AV:Z/x"},
                    headers=tok("analyst@t.local"))
    assert r.status_code == 422


def test_remediation_workflow_and_comment_trail():
    h = tok("analyst@t.local")
    a = client.post("/api/assets", json={"name": "wf-asset"}, headers=h).json()
    v = client.post("/api/vulnerabilities", json={"title": "WF vuln",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}, headers=h).json()
    f = client.post("/api/findings", json={"asset_id": a["id"], "vulnerability_id": v["id"]}, headers=h).json()

    r = client.patch(f"/api/findings/{f['id']}/status",
                     json={"status": "remediated", "assigned_to": "IT Ops"}, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "remediated"

    detail = client.get(f"/api/findings/{f['id']}", headers=h).json()
    assert detail["resolved_at"] is not None
    # status change auto-logged a comment
    assert any("remediated" in c["body"] for c in detail["comments"])


def test_viewer_cannot_change_status():
    h = tok("analyst@t.local")
    a = client.post("/api/assets", json={"name": "ro-asset"}, headers=h).json()
    v = client.post("/api/vulnerabilities", json={"title": "RO vuln",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}, headers=h).json()
    f = client.post("/api/findings", json={"asset_id": a["id"], "vulnerability_id": v["id"]}, headers=h).json()
    r = client.patch(f"/api/findings/{f['id']}/status", json={"status": "accepted"},
                     headers=tok("viewer@t.local"))
    assert r.status_code == 403


def test_csv_import_dedupes_on_reimport():
    h = tok("analyst@t.local")
    csv = (b"host,ip,cve,name,cvss_vector,port\n"
           b"web-x,192.0.2.9,CVE-2021-44228,Log4Shell,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H,8080\n")
    r1 = client.post("/api/findings/import", files={"file": ("scan.csv", csv, "text/csv")}, headers=h)
    assert r1.status_code == 200 and r1.json()["findings_created"] == 1
    # same scan again → updated, not duplicated
    r2 = client.post("/api/findings/import", files={"file": ("scan.csv", csv, "text/csv")}, headers=h)
    assert r2.json()["findings_created"] == 0 and r2.json()["findings_updated"] == 1


def test_dashboard_shape():
    d = client.get("/api/dashboard", headers=tok("viewer@t.local")).json()
    for key in ("totals", "by_severity", "by_status", "top_risks"):
        assert key in d
    assert d["totals"]["assets"] >= 1
