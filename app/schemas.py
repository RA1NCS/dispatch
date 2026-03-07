import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, field_validator

VALID_REGIONS = ["bay_area", "nyc_metro", "philadelphia", "chicago", "national"]
VALID_SERVICES = [
    "gmail",
    "outlook",
    "comcast",
    "verizon",
    "paypal",
    "amazon",
    "apple",
    "microsoft",
    "slack",
    "zoom",
]
VALID_WORK_SITUATIONS = ["remote", "hybrid", "office", "student"]
VALID_CONCERNS = ["phishing", "data_breaches", "vulnerabilities", "all"]

REGION_LABELS = {
    "bay_area": "Bay Area",
    "nyc_metro": "NYC Metro",
    "philadelphia": "Philadelphia",
    "chicago": "Chicago",
    "national": "National",
}

SERVICE_LABELS = {
    "gmail": "Gmail",
    "outlook": "Outlook",
    "comcast": "Comcast",
    "verizon": "Verizon",
    "paypal": "PayPal",
    "amazon": "Amazon",
    "apple": "Apple",
    "microsoft": "Microsoft",
    "slack": "Slack",
    "zoom": "Zoom",
}

WORK_LABELS = {
    "remote": "Remote",
    "hybrid": "Hybrid",
    "office": "Office",
    "student": "Student",
}

CONCERN_LABELS = {
    "phishing": "Phishing & Scams",
    "data_breaches": "Data Breaches",
    "vulnerabilities": "Software Vulnerabilities",
    "all": "All Threats",
}


class ProfileCreate(BaseModel):
    region: str
    services: list[str]
    work_situation: str
    primary_concern: str

    @field_validator("region")
    @classmethod
    def validate_region(cls, v):
        if v not in VALID_REGIONS:
            raise ValueError(f"Region must be one of: {VALID_REGIONS}")
        return v

    @field_validator("services")
    @classmethod
    def validate_services(cls, v):
        if not v:
            raise ValueError("At least one service is required")
        for s in v:
            if s not in VALID_SERVICES:
                raise ValueError(
                    f"Invalid service: {s}. Must be one of: {VALID_SERVICES}"
                )
        return v

    @field_validator("work_situation")
    @classmethod
    def validate_work_situation(cls, v):
        if v not in VALID_WORK_SITUATIONS:
            raise ValueError(f"Work situation must be one of: {VALID_WORK_SITUATIONS}")
        return v

    @field_validator("primary_concern")
    @classmethod
    def validate_concern(cls, v):
        if v not in VALID_CONCERNS:
            raise ValueError(f"Primary concern must be one of: {VALID_CONCERNS}")
        return v


class TriageResult(BaseModel):
    alert_id: str
    relevance_score: float
    relevance_reason: str


class ThreatFinding(BaseModel):
    alert_id: str
    title: str
    severity: str
    category: str
    relevance_score: float
    explanation: str
    action_items: list[str]


class BriefingOutput(BaseModel):
    shield_status: Literal["green", "yellow", "red"]
    status_summary: str
    findings: list[ThreatFinding]
    correlations: list[str]
    immediate_actions: list[str]


ALERT_SEVERITIES = ["critical", "high", "medium", "low"]
ALERT_CATEGORIES = ["phishing", "data_breach", "vulnerability", "malware", "scam"]
SEVERITY_RANK = {s: len(ALERT_SEVERITIES) - i for i, s in enumerate(ALERT_SEVERITIES)}

CATEGORY_LABELS = {
    "phishing": "Phishing",
    "data_breach": "Data Breach",
    "vulnerability": "Vulnerability",
    "malware": "Malware",
    "scam": "Scam",
}

CONCERN_TO_CATEGORIES = {
    "phishing": {"phishing", "scam"},
    "data_breaches": {"data_breach"},
    "vulnerabilities": {"vulnerability"},
    "all": set(ALERT_CATEGORIES),
}

CATEGORY_ACTIONS = {
    "phishing": [
        "Do not click links in unsolicited emails claiming account issues",
        "Verify sender email addresses carefully before responding",
        "Enable 2FA on all affected accounts",
    ],
    "data_breach": [
        "Change passwords on affected services immediately",
        "Monitor account activity for unauthorized access",
        "Consider freezing credit if personal data was exposed",
    ],
    "vulnerability": [
        "Update all affected software to the latest version",
        "Check vendor security advisories for patches",
        "Disable affected features until patches are applied",
    ],
    "malware": [
        "Run a full antivirus scan on all devices",
        "Avoid opening attachments from unknown senders",
        "Disconnect affected devices from the network",
    ],
    "scam": [
        "Never provide remote access to unsolicited callers",
        "Verify charges directly through official service websites",
        "Report scam attempts to the FTC",
    ],
}

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def load_alerts():
    with open(DATA_DIR / "alerts_seed.json") as f:
        return sorted(json.load(f), key=lambda a: a["date"], reverse=True)


def search_threats(region, services, alerts):
    results = []
    for alert in alerts:
        region_match = alert["region"] == region or alert["region"] == "national"
        service_match = not alert["affected_services"] or any(
            s in services for s in alert["affected_services"]
        )
        if region_match or service_match:
            results.append(alert)
    return results
