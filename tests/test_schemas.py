import pytest
from pydantic import ValidationError

from app.schemas import ProfileCreate, search_threats


# --- ProfileCreate validation ---


def test_valid_profile():
    p = ProfileCreate(
        region="bay_area",
        services=["gmail", "slack"],
        work_situation="remote",
        primary_concern="phishing",
    )
    assert p.region == "bay_area"
    assert p.services == ["gmail", "slack"]
    assert p.work_situation == "remote"
    assert p.primary_concern == "phishing"


def test_invalid_region():
    with pytest.raises(ValidationError, match="Region must be one of"):
        ProfileCreate(
            region="mars",
            services=["gmail"],
            work_situation="remote",
            primary_concern="phishing",
        )


def test_empty_services():
    with pytest.raises(ValidationError, match="At least one service"):
        ProfileCreate(
            region="bay_area",
            services=[],
            work_situation="remote",
            primary_concern="phishing",
        )


def test_invalid_service_in_list():
    with pytest.raises(ValidationError, match="Invalid service"):
        ProfileCreate(
            region="bay_area",
            services=["gmail", "fakebook"],
            work_situation="remote",
            primary_concern="phishing",
        )


def test_invalid_work_situation():
    with pytest.raises(ValidationError, match="Work situation must be one of"):
        ProfileCreate(
            region="bay_area",
            services=["gmail"],
            work_situation="unemployed",
            primary_concern="phishing",
        )


def test_invalid_concern():
    with pytest.raises(ValidationError, match="Primary concern must be one of"):
        ProfileCreate(
            region="bay_area",
            services=["gmail"],
            work_situation="remote",
            primary_concern="everything",
        )


# --- search_threats filtering ---


def test_search_matches_by_region(sample_alerts):
    # bay_area profile with no services should still match regional + national alerts
    results = search_threats("bay_area", [], sample_alerts)
    ids = {a["id"] for a in results}
    assert "ALT-002" in ids  # bay_area region
    assert "ALT-001" in ids  # national region


def test_search_matches_by_service(sample_alerts):
    # chicago profile with gmail service should pick up gmail alerts from other regions
    results = search_threats("chicago", ["gmail"], sample_alerts)
    ids = {a["id"] for a in results}
    assert "ALT-001" in ids  # gmail service match + national
    assert "ALT-003" in ids  # chicago region match


def test_search_excludes_unrelated(sample_alerts):
    # chicago + gmail should NOT include bay_area slack-only alert
    results = search_threats("chicago", ["gmail"], sample_alerts)
    ids = {a["id"] for a in results}
    assert "ALT-002" not in ids  # bay_area + slack, no overlap


def test_search_or_logic(sample_alerts):
    # OR logic: region match alone is enough, service match alone is enough
    results = search_threats("bay_area", ["microsoft"], sample_alerts)
    ids = {a["id"] for a in results}
    assert "ALT-002" in ids  # region match (bay_area), not service
    assert "ALT-003" in ids  # service match (microsoft), not region


def test_search_no_matches():
    # custom alert that only matches chicago + microsoft
    alerts = [
        {
            "id": "X-001",
            "title": "Chicago Only",
            "category": "phishing",
            "severity": "high",
            "region": "chicago",
            "affected_services": ["microsoft"],
            "date": "2026-01-01",
        }
    ]
    results = search_threats("bay_area", ["gmail"], alerts)
    assert len(results) == 0
