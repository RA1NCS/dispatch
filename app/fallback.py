from app.schemas import (
    CATEGORY_ACTIONS,
    CONCERN_TO_CATEGORIES,
    SEVERITY_RANK,
    BriefingOutput,
    ThreatFinding,
    TriageResult,
)


def triage_alerts(alerts, profile):
    results = []
    concern_cats = CONCERN_TO_CATEGORIES.get(profile["primary_concern"], set())
    for alert in alerts:
        score = 0.2
        service_overlap = set(alert["affected_services"]) & set(profile["services"])
        if service_overlap:
            score = 0.8
        if alert["region"] == profile["region"]:
            score = max(score, 0.6)
            if service_overlap:
                score = 1.0
        elif alert["region"] == "national" and not service_overlap:
            score = max(score, 0.4)
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


def generate_briefing(profile, alerts, triage_results):
    triage_map = {t.alert_id: t for t in triage_results}
    relevant = [
        (a, triage_map[a["id"]])
        for a in alerts
        if a["id"] in triage_map and triage_map[a["id"]].relevance_score >= 0.4
    ]
    relevant.sort(
        key=lambda x: (-_severity_rank(x[0]["severity"]), -x[1].relevance_score)
    )

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


def _severity_rank(severity):
    return SEVERITY_RANK.get(severity, 0)


def _compute_shield(findings):
    if any(f.severity == "critical" for f in findings):
        return "red"
    if any(f.severity == "high" for f in findings):
        return "yellow"
    return "green"


def _find_correlations(findings, alert_map):
    service_counts = {}
    category_counts = {}
    for f in findings:
        category_counts[f.category] = category_counts.get(f.category, 0) + 1
        alert = alert_map.get(f.alert_id, {})
        for svc in alert.get("affected_services", []):
            service_counts[svc] = service_counts.get(svc, 0) + 1

    correlations = []
    for svc, count in service_counts.items():
        if count >= 2:
            correlations.append(
                f"{svc.capitalize()} appears in {count} alerts, suggesting coordinated or persistent targeting of this service"
            )
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
