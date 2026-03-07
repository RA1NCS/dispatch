from pydantic import BaseModel, field_validator

VALID_REGIONS = ["bay_area", "nyc_metro", "philadelphia", "chicago", "national"]
VALID_SERVICES = ["gmail", "outlook", "comcast", "verizon", "paypal", "amazon", "apple", "microsoft", "slack", "zoom"]
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
                raise ValueError(f"Invalid service: {s}. Must be one of: {VALID_SERVICES}")
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


class ProfileUpdate(ProfileCreate):
    pass
