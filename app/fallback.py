import re

from app.schemas import (
    CATEGORY_ACTIONS,
    CONCERN_TO_CATEGORIES,
    SEVERITY_RANK,
    URL_PATTERN,
    VALID_SERVICES,
    BriefingOutput,
    PasswordResult,
    PhishingResult,
    ThreatFinding,
    TriageResult,
)


# scores each alert's relevance to the user's profile using rules
def triage_alerts(alerts, profile):
    results = []
    concern_cats = CONCERN_TO_CATEGORIES.get(profile["primary_concern"], set())
    for alert in alerts:
        score = 0.2

        # service overlap is the strongest signal
        service_overlap = set(alert["affected_services"]) & set(profile["services"])
        if service_overlap:
            score = 0.8

        # region match boosts score, combo with services = max
        if alert["region"] == profile["region"]:
            score = max(score, 0.6)
            if service_overlap:
                score = 1.0
        elif alert["region"] == "national" and not service_overlap:
            score = max(score, 0.4)

        # small boost if alert matches user's primary concern
        if alert["category"] in concern_cats:
            score = min(score + 0.1, 1.0)
        reason = _build_reason(alert, profile, service_overlap)
        results.append(
            TriageResult(
                alert_id=alert["id"],
                relevance_score=round(score, 1),
                relevance_reason=reason,
            )
        )
    return sorted(results, key=lambda r: r.relevance_score, reverse=True)


# builds a human-readable explanation for why an alert scored the way it did
def _build_reason(alert, profile, service_overlap):
    parts = []
    if service_overlap:
        names = ", ".join(sorted(service_overlap))
        parts.append(f"directly affects {names}")
    if alert["region"] == profile["region"]:
        parts.append(f"targets {profile['region']} region")
    elif alert["region"] == "national":
        parts.append("national scope")
    if not parts:
        parts.append("limited relevance to profile")
    return "; ".join(parts).capitalize()


# assembles a full security briefing from triage results
def generate_briefing(profile, alerts, triage_results):
    triage_map = {t.alert_id: t for t in triage_results}

    # only include alerts that scored 0.4+, sorted by severity then relevance
    relevant = [
        (a, triage_map[a["id"]])
        for a in alerts
        if a["id"] in triage_map and triage_map[a["id"]].relevance_score >= 0.4
    ]
    relevant.sort(
        key=lambda x: (-_severity_rank(x[0]["severity"]), -x[1].relevance_score)
    )

    # build findings from top 10 relevant alerts
    findings = []
    for alert, triage in relevant[:10]:
        actions = CATEGORY_ACTIONS.get(
            alert["category"], ["Review this alert carefully"]
        )
        findings.append(
            ThreatFinding(
                alert_id=alert["id"],
                title=alert["title"],
                severity=alert["severity"],
                category=alert["category"],
                relevance_score=triage.relevance_score,
                explanation=triage.relevance_reason,
                action_items=actions,
            )
        )

    alert_map = {a["id"]: a for a in alerts}
    shield_status = _compute_shield(findings)
    correlations = _find_correlations(findings, alert_map)
    immediate = _top_actions(findings)

    critical_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    status_summary = f"{len(findings)} relevant threats found: {critical_count} critical, {high_count} high severity"

    return BriefingOutput(
        shield_status=shield_status,
        status_summary=status_summary,
        findings=findings,
        correlations=correlations,
        immediate_actions=immediate,
    )


# converts severity string to numeric rank for sorting
def _severity_rank(severity):
    return SEVERITY_RANK.get(severity, 0)


# determines overall shield color from the worst finding
def _compute_shield(findings):
    if any(f.severity == "critical" for f in findings):
        return "red"
    if any(f.severity == "high" for f in findings):
        return "yellow"
    return "green"


# looks for patterns across findings (same service hit multiple times, etc)
def _find_correlations(findings, alert_map):
    service_counts = {}
    category_counts = {}
    for f in findings:
        category_counts[f.category] = category_counts.get(f.category, 0) + 1
        alert = alert_map.get(f.alert_id, {})
        for svc in alert.get("affected_services", []):
            service_counts[svc] = service_counts.get(svc, 0) + 1

    correlations = []
    # flag services targeted by 2+ alerts
    for svc, count in service_counts.items():
        if count >= 2:
            correlations.append(
                f"{svc.capitalize()} appears in {count} alerts, suggesting coordinated or persistent targeting of this service"
            )
    # flag categories with 3+ alerts
    for cat, count in category_counts.items():
        if count >= 3:
            correlations.append(
                f"{count} {cat.replace('_', ' ')} alerts detected, indicating elevated risk in this category"
            )
    if not correlations:
        correlations.append(
            "No strong cross-alert correlations detected in current threat data"
        )
    return correlations


# picks the top 5 most urgent actions from highest-severity findings
def _top_actions(findings):
    seen = set()
    actions = []
    for f in sorted(findings, key=lambda f: _severity_rank(f.severity), reverse=True):
        for action in f.action_items:
            if action not in seen:
                seen.add(action)
                actions.append(action)
            if len(actions) >= 5:
                return actions
    return actions or ["No immediate actions required based on current threat data"]


# --- phishing detection (rule-based) ---

URGENCY_WORDS = {
    "immediately", "urgent", "suspended", "verify", "confirm",
    "locked", "unauthorized", "expire", "disabled", "restricted",
    "act now", "within 24 hours", "within 48 hours",
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".buzz", ".tk", ".ml", ".ga", ".cf"}

FREEMAIL_DOMAINS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"}

SENSITIVE_REQUESTS = {
    "social security", "ssn", "password", "credit card",
    "bank account", "credentials", "login",
}

EMAIL_FROM_PATTERN = re.compile(r'From:\s*\S+@(\S+)', re.IGNORECASE)


# scans email text for phishing red flags using keywords and patterns
def analyze_phishing_offline(text):
    flags = []
    text_lower = text.lower()

    # check for pressure/urgency language
    for word in URGENCY_WORDS:
        if word in text_lower:
            flags.append(f"Urgency language detected: \"{word}\"")
            break

    # check sender domain for freemail or brand mismatch
    from_match = EMAIL_FROM_PATTERN.search(text)
    if from_match:
        domain = from_match.group(1).lower()
        if domain in FREEMAIL_DOMAINS:
            flags.append(f"Sender uses free email provider ({domain})")
        brand_keywords = list(VALID_SERVICES) + ["chase", "bank", "google"]
        for brand in brand_keywords:
            if brand in text_lower and brand not in domain:
                flags.append(f"Email mentions {brand} but sender domain is {domain}")
                break

    # check urls for sketchy tlds
    urls = URL_PATTERN.findall(text)
    for url in urls:
        for tld in SUSPICIOUS_TLDS:
            if tld in url.lower():
                flags.append(f"Suspicious URL with {tld} domain: {url[:80]}")
                break

    # check for requests for sensitive info
    for term in SENSITIVE_REQUESTS:
        if term in text_lower:
            flags.append(f"Requests sensitive information: \"{term}\"")
            break

    # excessive ALL CAPS is a red flag (ignoring common acronyms)
    all_caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
    all_caps_words = [w for w in all_caps_words if w not in {"FROM", "SUBJECT", "HTTP", "HTTPS", "HTML"}]
    if len(all_caps_words) >= 2:
        flags.append("Excessive use of ALL CAPS words")

    # verdict based on how many flags tripped
    if len(flags) >= 3:
        verdict = "phishing"
        confidence = min(0.5 + len(flags) * 0.1, 0.95)
    elif len(flags) >= 1:
        verdict = "suspicious"
        confidence = 0.3 + len(flags) * 0.1
    else:
        verdict = "legitimate"
        confidence = 0.6

    explanation = (
        f"Offline analysis found {len(flags)} red flag(s). "
        + ("This email shows strong indicators of a phishing attempt." if verdict == "phishing"
           else "Some suspicious elements detected, but not conclusive." if verdict == "suspicious"
           else "No significant phishing indicators found.")
    )

    return PhishingResult(
        verdict=verdict,
        confidence=round(confidence, 2),
        red_flags=flags if flags else ["No red flags detected"],
        explanation=explanation,
    )


# --- password strength check (rule-based) ---


# evaluates password strength based on length, variety, and patterns
def check_password_offline(password):
    reasons = []

    # length check
    if len(password) < 8:
        reasons.append("Too short (minimum 8 characters)")
    elif len(password) < 12:
        reasons.append("Length is acceptable but 12+ characters recommended")

    # character variety (upper, lower, digit, special)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^A-Za-z0-9]', password))
    variety = sum([has_upper, has_lower, has_digit, has_special])

    if variety < 2:
        reasons.append("Uses only one character type (add uppercase, digits, or symbols)")
    elif variety < 3:
        reasons.append("Limited character variety (add digits or symbols)")

    # pattern detection
    if re.search(r'(.)\1{2,}', password):
        reasons.append("Contains repeated characters (e.g. 'aaa')")

    if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def|qwe|wer|ert)', password.lower()):
        reasons.append("Contains sequential characters")

    # overall strength verdict
    if len(password) >= 12 and variety >= 3 and not reasons:
        strength = "strong"
    elif len(password) >= 8 and variety >= 2:
        strength = "fair"
    else:
        strength = "weak"

    if not reasons:
        reasons.append("Password meets basic strength requirements")

    return PasswordResult(
        strength=strength,
        reasons=reasons,
    )
