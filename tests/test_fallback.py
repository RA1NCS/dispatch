from app.fallback import (
    analyze_phishing_offline,
    check_password_offline,
    generate_briefing,
    triage_alerts,
)


# --- triage_alerts scoring ---


def test_triage_service_overlap_scores_high(sample_profile, sample_alerts):
    results = triage_alerts(sample_alerts, sample_profile)
    scores = {r.alert_id: r.relevance_score for r in results}
    # ALT-001 (gmail) and ALT-004 (paypal) overlap with profile services
    assert scores["ALT-001"] >= 0.8
    assert scores["ALT-004"] >= 0.8


def test_triage_region_match_scores_mid(sample_profile, sample_alerts):
    results = triage_alerts(sample_alerts, sample_profile)
    scores = {r.alert_id: r.relevance_score for r in results}
    # ALT-002 is bay_area + slack (service overlap + region) -> should be 1.0
    assert scores["ALT-002"] == 1.0


def test_triage_no_overlap_scores_low(sample_profile, sample_alerts):
    results = triage_alerts(sample_alerts, sample_profile)
    scores = {r.alert_id: r.relevance_score for r in results}
    # ALT-005 is national + zoom (no service overlap, national only)
    assert scores["ALT-005"] <= 0.5


def test_triage_sorted_by_score(sample_profile, sample_alerts):
    results = triage_alerts(sample_alerts, sample_profile)
    scores = [r.relevance_score for r in results]
    assert scores == sorted(scores, reverse=True)


def test_triage_concern_boost(sample_alerts):
    # phishing concern should slightly boost phishing category alerts
    profile = {
        "id": 1,
        "region": "nyc_metro",
        "services": [],
        "work_situation": "office",
        "primary_concern": "phishing",
    }
    results = triage_alerts(sample_alerts, profile)
    scores = {r.alert_id: r.relevance_score for r in results}
    # ALT-001 is phishing category, should get concern boost
    # ALT-005 is vulnerability category, no concern boost
    assert scores["ALT-001"] > scores["ALT-005"]


# --- generate_briefing ---


def test_briefing_red_shield_on_critical(sample_profile, sample_alerts):
    triaged = triage_alerts(sample_alerts, sample_profile)
    briefing = generate_briefing(sample_profile, sample_alerts, triaged)
    # ALT-001 is critical + high relevance -> shield should be red
    assert briefing.shield_status == "red"


def test_briefing_green_shield_on_low_only():
    profile = {
        "id": 1,
        "region": "nyc_metro",
        "services": ["zoom"],
        "work_situation": "student",
        "primary_concern": "all",
    }
    alerts = [
        {
            "id": "LOW-001",
            "title": "Low Severity Alert",
            "category": "scam",
            "severity": "low",
            "region": "national",
            "affected_services": ["zoom"],
            "date": "2026-01-01",
        }
    ]
    triaged = triage_alerts(alerts, profile)
    briefing = generate_briefing(profile, alerts, triaged)
    assert briefing.shield_status == "green"


def test_briefing_has_correlations(sample_profile):
    # two alerts targeting the same service should produce a correlation
    alerts = [
        {
            "id": "C-001",
            "title": "Gmail Attack 1",
            "category": "phishing",
            "severity": "critical",
            "region": "national",
            "affected_services": ["gmail"],
            "date": "2026-03-06",
        },
        {
            "id": "C-002",
            "title": "Gmail Attack 2",
            "category": "data_breach",
            "severity": "high",
            "region": "national",
            "affected_services": ["gmail"],
            "date": "2026-03-05",
        },
    ]
    triaged = triage_alerts(alerts, sample_profile)
    briefing = generate_briefing(sample_profile, alerts, triaged)
    assert any("gmail" in c.lower() for c in briefing.correlations)


def test_briefing_filters_low_relevance():
    # alert with 0 service/region overlap should be excluded (score < 0.4)
    profile = {
        "id": 1,
        "region": "bay_area",
        "services": ["gmail"],
        "work_situation": "remote",
        "primary_concern": "vulnerabilities",
    }
    alerts = [
        {
            "id": "SKIP-001",
            "title": "Chicago Microsoft Breach",
            "category": "data_breach",
            "severity": "critical",
            "region": "chicago",
            "affected_services": ["microsoft"],
            "date": "2026-03-06",
        },
    ]
    triaged = triage_alerts(alerts, profile)
    briefing = generate_briefing(profile, alerts, triaged)
    assert len(briefing.findings) == 0


# --- phishing detection ---


def test_phishing_detects_urgency():
    text = "URGENT: Your account has been suspended immediately. Verify now."
    result = analyze_phishing_offline(text)
    assert result.verdict in ("phishing", "suspicious")
    assert any("urgency" in f.lower() for f in result.red_flags)


def test_phishing_detects_freemail_sender():
    text = "From: support@gmail.com\nYour Chase bank account has been locked."
    result = analyze_phishing_offline(text)
    assert any("free email" in f.lower() for f in result.red_flags)


def test_phishing_detects_suspicious_tld():
    text = "Click here to verify: https://paypal-secure.xyz/login"
    result = analyze_phishing_offline(text)
    assert any(".xyz" in f for f in result.red_flags)


def test_phishing_clean_email_is_legitimate():
    text = "Hi, just checking in about the meeting tomorrow. Let me know if 2pm works."
    result = analyze_phishing_offline(text)
    assert result.verdict == "legitimate"


def test_phishing_multiple_flags_means_phishing():
    text = (
        "From: security@gmail.com\n"
        "URGENT: Your PayPal account has been suspended immediately!\n"
        "Verify your password at https://paypal-verify.xyz/login\n"
        "ACT NOW or your account will be PERMANENTLY DISABLED"
    )
    result = analyze_phishing_offline(text)
    assert result.verdict == "phishing"
    assert result.confidence >= 0.5


# --- password strength ---


def test_password_weak_short():
    result = check_password_offline("abc")
    assert result.strength == "weak"


def test_password_weak_single_type():
    result = check_password_offline("abcdefgh")
    assert result.strength in ("weak", "fair")
    assert any("character" in r.lower() for r in result.reasons)


def test_password_strong():
    result = check_password_offline("K9$mPx!qR2vL")
    assert result.strength == "strong"


def test_password_detects_sequences():
    result = check_password_offline("abc123xyz!")
    assert any("sequential" in r.lower() for r in result.reasons)


def test_password_detects_repeats():
    result = check_password_offline("aaabbb111!")
    assert any("repeated" in r.lower() for r in result.reasons)
