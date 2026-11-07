import json
import re

import pytest
from fastapi.testclient import TestClient

from accessguard.config import Settings
from accessguard.storage import Store
from accessguard.web.app import create_app


def make_client(tmp_path, **settings_kw):
    settings = Settings(data_dir=tmp_path, **settings_kw)
    return TestClient(create_app(settings, Store(tmp_path)))


def csrf(client, path="/", **kw):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(path, **kw).text).group(1)


@pytest.fixture
def scanned(tmp_path):
    client = make_client(tmp_path)
    resp = client.post("/scan", data={"csrf": csrf(client), "mode": "demo"}, follow_redirects=False)
    assert resp.status_code == 303
    return client


def first_fingerprint(client):
    return re.search(r"/findings/([0-9a-f]{16})", client.get("/findings").text).group(1)


def test_empty_state_offers_demo(tmp_path):
    resp = make_client(tmp_path).get("/")
    assert resp.status_code == 200 and "Run a demo scan" in resp.text


def test_security_headers(tmp_path):
    resp = make_client(tmp_path).get("/")
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_dashboard_and_pages_render(scanned):
    assert "Contoso Health (demo)" in scanned.get("/").text
    for path in ["/findings", "/findings?state=all&severity=critical", "/identities", "/identities?kind=nonhuman", "/scans"]:
        assert scanned.get(path).status_code == 200, path


def test_scan_rejects_bad_csrf(tmp_path):
    client = make_client(tmp_path)
    assert client.post("/scan", data={"csrf": "wrong", "mode": "demo"}).status_code == 403


def test_live_scan_without_config_is_explained(tmp_path):
    client = make_client(tmp_path)
    resp = client.post("/scan", data={"csrf": csrf(client), "mode": "live"})
    assert resp.status_code == 400 and "Tenant not connected" in resp.text


def test_review_requires_justification_for_risk_acceptance(scanned):
    fp, token = first_fingerprint(scanned), csrf(scanned, "/")
    bad = scanned.post(f"/findings/{fp}/review", data={"csrf": token, "decision": "accepted_risk", "reviewer": "Ola"})
    assert bad.status_code == 400 and "justification is required" in bad.text
    ok = scanned.post(f"/findings/{fp}/review", follow_redirects=False,
                      data={"csrf": token, "decision": "accepted_risk", "reviewer": "Ola", "justification": "Break-glass"})
    assert ok.status_code == 303
    page = scanned.get(f"/findings/{fp}").text
    assert "Risk accepted" in page and "Break-glass" in page


def test_remediated_finding_reopens_when_still_detected(scanned):
    fp, token = first_fingerprint(scanned), csrf(scanned, "/")
    scanned.post(f"/findings/{fp}/review", data={"csrf": token, "decision": "remediated", "reviewer": "Ola"})
    scanned.post("/scan", data={"csrf": token, "mode": "demo"})
    page = scanned.get(f"/findings/{fp}").text
    assert "Reopened automatically" in page


def test_exports(scanned):
    csv_body = scanned.get("/export/report.csv").text
    assert csv_body.startswith("Fingerprint,Rule,Title")
    data = json.loads(scanned.get("/export/report.json").text)
    assert data["summary"]["total"] == len(data["findings"]) > 0
    html = scanned.get("/export/report.html")
    assert "evidence pack" in html.text.lower() and "unsafe-inline" in html.headers["content-security-policy"]
    assert "attachment" in scanned.get("/export/report.html?download=1").headers["content-disposition"]


def test_basic_auth_when_password_set(tmp_path):
    client = make_client(tmp_path, ui_password="s3cret")
    assert client.get("/").status_code == 401
    assert client.get("/", auth=("admin", "wrong")).status_code == 401
    assert client.get("/", auth=("admin", "s3cret")).status_code == 200
    assert client.get("/healthz").status_code == 200
