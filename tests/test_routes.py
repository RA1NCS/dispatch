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
    assert "Create" in resp.text


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


def test_update_profile_route(client):
    pid = create_profile("bay_area", ["gmail"], "remote", "phishing")
    resp = client.post(
        f"/profiles/{pid}",
        data={
            "region": "chicago",
            "services": ["outlook", "microsoft"],
            "work_situation": "office",
            "primary_concern": "data_breaches",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    # follow redirect and verify updated data shows
    view = client.get(f"/profiles/{pid}")
    assert "Chicago" in view.text


def test_update_nonexistent_profile(client):
    resp = client.post(
        "/profiles/9999",
        data={
            "region": "bay_area",
            "services": ["gmail"],
            "work_situation": "remote",
            "primary_concern": "phishing",
        },
    )
    assert resp.status_code == 404


def test_profiles_list_page(client):
    create_profile("bay_area", ["gmail"], "remote", "phishing")
    resp = client.get("/profiles")
    assert resp.status_code == 200
    assert "Bay Area" in resp.text


def test_edit_profile_page(client):
    pid = create_profile("bay_area", ["gmail"], "remote", "phishing")
    resp = client.get(f"/profiles/{pid}/edit")
    assert resp.status_code == 200
    assert "bay_area" in resp.text


def test_alerts_page(client):
    resp = client.get("/alerts")
    assert resp.status_code == 200
    assert "ALERTS" in resp.text or "alerts" in resp.text.lower()


def test_alerts_filter_by_severity(client):
    resp = client.get("/alerts?severity=critical")
    assert resp.status_code == 200
    assert "critical" in resp.text.lower()


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
    assert "phishing" in resp.text.lower()


def test_password_page(client):
    resp = client.get("/password")
    assert resp.status_code == 200
    assert "password" in resp.text.lower()


def test_phishing_analyze_empty_text(client):
    resp = client.post("/phishing/analyze", data={"email_text": "   ", "mode": "auto"})
    assert resp.status_code == 200
    assert "Please enter" in resp.text


def test_phishing_analyze_offline(client):
    resp = client.post(
        "/phishing/analyze",
        data={"email_text": "URGENT: Your account has been suspended. Click here.", "mode": "auto"},
    )
    assert resp.status_code == 200
    assert "suspicious" in resp.text.lower() or "phishing" in resp.text.lower()


def test_password_check_offline(client):
    resp = client.post("/password/check", data={"password": "weak", "mode": "auto"})
    assert resp.status_code == 200
    assert "weak" in resp.text.lower()


def test_password_check_strong(client):
    resp = client.post("/password/check", data={"password": "K9$mPx!qR2vL", "mode": "auto"})
    assert resp.status_code == 200
    assert "strong" in resp.text.lower()


def test_audit_page(client):
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert "AUDIT" in resp.text or "audit" in resp.text.lower()
