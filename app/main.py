from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.database import (
    create_profile,
    get_profile,
    init_db,
    list_profiles,
    update_profile,
)
from app.schemas import (
    CONCERN_LABELS,
    REGION_LABELS,
    SERVICE_LABELS,
    VALID_CONCERNS,
    VALID_REGIONS,
    VALID_SERVICES,
    VALID_WORK_SITUATIONS,
    WORK_LABELS,
    ProfileCreate,
)

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="Guardian", version="0.1.0")


@app.on_event("startup")
def startup():
    init_db()


def form_context():
    return {
        "regions": VALID_REGIONS,
        "region_labels": REGION_LABELS,
        "services": VALID_SERVICES,
        "service_labels": SERVICE_LABELS,
        "work_situations": VALID_WORK_SITUATIONS,
        "work_labels": WORK_LABELS,
        "concerns": VALID_CONCERNS,
        "concern_labels": CONCERN_LABELS,
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index(request: Request):
    profiles = list_profiles()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "profiles": profiles,
            **form_context(),
        },
    )


@app.post("/profiles")
def post_profile(
    region: str = Form(...),
    services: list[str] = Form(...),
    work_situation: str = Form(...),
    primary_concern: str = Form(...),
):
    profile = ProfileCreate(
        region=region,
        services=services,
        work_situation=work_situation,
        primary_concern=primary_concern,
    )
    profile_id = create_profile(
        profile.region,
        profile.services,
        profile.work_situation,
        profile.primary_concern,
    )
    return RedirectResponse(url=f"/profiles/{profile_id}", status_code=303)


@app.get("/profiles/{profile_id}")
def view_profile(request: Request, profile_id: int):
    profile = get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "profile": profile,
            **form_context(),
        },
    )


@app.post("/profiles/{profile_id}")
def post_update_profile(
    profile_id: int,
    region: str = Form(...),
    services: list[str] = Form(...),
    work_situation: str = Form(...),
    primary_concern: str = Form(...),
):
    existing = get_profile(profile_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Profile not found")
    profile = ProfileCreate(
        region=region,
        services=services,
        work_situation=work_situation,
        primary_concern=primary_concern,
    )
    update_profile(
        profile_id,
        profile.region,
        profile.services,
        profile.work_situation,
        profile.primary_concern,
    )
    return RedirectResponse(url=f"/profiles/{profile_id}", status_code=303)
