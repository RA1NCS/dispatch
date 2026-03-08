import os

# set dummy api key before agent module tries to create pydantic-ai agents
os.environ.setdefault("GOOGLE_API_KEY", "test-key-not-real")

import pytest

from app import database


# every test gets a fresh temp database
@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)
    database.init_db()
    yield db_path


@pytest.fixture
def sample_profile():
    return {
        "id": 1,
        "region": "bay_area",
        "services": ["gmail", "slack", "paypal"],
        "work_situation": "remote",
        "primary_concern": "phishing",
    }


@pytest.fixture
def sample_alerts():
    return [
        {
            "id": "ALT-001",
            "title": "Gmail Phishing Campaign",
            "category": "phishing",
            "severity": "critical",
            "region": "national",
            "affected_services": ["gmail"],
            "date": "2026-03-06",
            "source": "Test",
            "description": "Test phishing alert targeting gmail users",
        },
        {
            "id": "ALT-002",
            "title": "Bay Area Wi-Fi Attack",
            "category": "vulnerability",
            "severity": "high",
            "region": "bay_area",
            "affected_services": ["slack"],
            "date": "2026-03-05",
            "source": "Test",
            "description": "Test vulnerability in bay area",
        },
        {
            "id": "ALT-003",
            "title": "Chicago School Breach",
            "category": "data_breach",
            "severity": "high",
            "region": "chicago",
            "affected_services": ["microsoft"],
            "date": "2026-03-04",
            "source": "Test",
            "description": "Test breach in chicago schools",
        },
        {
            "id": "ALT-004",
            "title": "National PayPal Scam",
            "category": "scam",
            "severity": "medium",
            "region": "national",
            "affected_services": ["paypal"],
            "date": "2026-03-03",
            "source": "Test",
            "description": "Test scam targeting paypal users",
        },
        {
            "id": "ALT-005",
            "title": "Zoom Vulnerability",
            "category": "vulnerability",
            "severity": "low",
            "region": "national",
            "affected_services": ["zoom"],
            "date": "2026-03-02",
            "source": "Test",
            "description": "Test zoom vulnerability",
        },
    ]
