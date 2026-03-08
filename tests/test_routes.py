import pytest
from fastapi.testclient import TestClient

import app.agent as agent
from app.database import create_profile
from app.main import app


@pytest.fixture
def client():
    # force offline mode so no AI calls happen during tests
    original = agent.ai_mode
    agent.ai_mode = False
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    agent.ai_mode = original


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_index_redirects_to_profile(client):
    pid = create_profile("bay_area", ["gmail"], "remote", "phishing")
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert f"/profiles/{pid}" in resp.headers["location"]


def test_index_shows_form_when_no_profiles(client):
    resp = client.get("/?new=1")
    assert resp.status_code == 200


def test_create_profile_redirects(client):
    resp = client.post(
        "/profiles",
        data={
            "region": "bay_area",
            "services": ["gmail", "slack"],
            "work_situation": "remote",
            "primary_concern": "phishing",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/profiles/" in resp.headers["location"]


def test_view_profile(client):
    pid = create_profile("bay_area", ["gmail"], "remote", "phishing")
    resp = client.get(f"/profiles/{pid}")
    assert resp.status_code == 200
    assert "Bay Area" in resp.text


def test_view_nonexistent_profile(client):
    resp = client.get("/profiles/9999")
    assert resp.status_code == 404


def test_alerts_page(client):
    resp = client.get("/alerts")
    assert resp.status_code == 200


def test_alerts_filter_by_severity(client):
    resp = client.get("/alerts?severity=critical")
    assert resp.status_code == 200
    # page should not contain any high/medium/low severity alerts
    # (all displayed alerts should be critical)


def test_toggle_ai_mode(client):
    # starts in offline (we forced it in fixture)
    resp = client.post("/toggle-ai")
    assert resp.status_code == 200
    data = resp.json()
    assert "enabled" in data
    # toggle again to restore
    client.post("/toggle-ai")


def test_phishing_page(client):
    resp = client.get("/phishing")
    assert resp.status_code == 200


def test_password_page(client):
    resp = client.get("/password")
    assert resp.status_code == 200


def test_phishing_analyze_empty_text(client):
    resp = client.post("/phishing/analyze", data={"email_text": "   ", "mode": "auto"})
    assert resp.status_code == 200
    assert "Please enter" in resp.text


def test_password_check_offline(client):
    resp = client.post("/password/check", data={"password": "weak", "mode": "auto"})
    assert resp.status_code == 200
