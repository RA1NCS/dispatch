from app.database import (
    create_profile,
    get_audit_log,
    get_profile,
    list_profiles,
    log_audit,
    update_profile,
)


def test_create_and_get_profile():
    pid = create_profile("bay_area", ["gmail", "slack"], "remote", "phishing")
    profile = get_profile(pid)
    assert profile is not None
    assert profile["region"] == "bay_area"
    assert profile["services"] == ["gmail", "slack"]
    assert profile["work_situation"] == "remote"
    assert profile["primary_concern"] == "phishing"


def test_get_nonexistent_profile():
    assert get_profile(9999) is None


def test_update_profile():
    pid = create_profile("bay_area", ["gmail"], "remote", "phishing")
    original = get_profile(pid)

    update_profile(pid, "chicago", ["outlook", "microsoft"], "office", "data_breaches")
    updated = get_profile(pid)

    assert updated["region"] == "chicago"
    assert updated["services"] == ["outlook", "microsoft"]
    assert updated["work_situation"] == "office"
    assert updated["primary_concern"] == "data_breaches"
    assert updated["updated_at"] > original["updated_at"]


def test_list_profiles_ordered():
    id1 = create_profile("bay_area", ["gmail"], "remote", "phishing")
    id2 = create_profile("chicago", ["outlook"], "office", "all")

    # update first profile so it has a newer updated_at
    update_profile(id1, "bay_area", ["gmail", "slack"], "remote", "phishing")

    profiles = list_profiles()
    assert len(profiles) == 2
    # most recently updated should be first
    assert profiles[0]["id"] == id1


def test_audit_log():
    log_audit("test_tool", "test input", "test output", 42, "test_model")
    log_audit("another_tool", "input2", "output2", 100, "model2")
    entries = get_audit_log()
    assert len(entries) == 2
    # newest first
    assert entries[0]["tool_name"] == "another_tool"
    assert entries[0]["latency_ms"] == 100
    assert entries[1]["tool_name"] == "test_tool"
