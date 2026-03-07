import asyncio
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app.agent import run_analysis, toggle_ai_mode
from app.database import (
    create_profile,
    get_audit_log,
    get_profile,
    init_db,
    list_profiles,
    update_profile,
)
from app.schemas import (
    ALERT_CATEGORIES,
    ALERT_SEVERITIES,
    CATEGORY_LABELS,
    CONCERN_LABELS,
    REGION_LABELS,
    SERVICE_LABELS,
    VALID_CONCERNS,
    VALID_REGIONS,
    VALID_SERVICES,
    VALID_WORK_SITUATIONS,
    WORK_LABELS,
    ProfileCreate,
    load_alerts,
)

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

SEVERITY_COLORS = {
    "critical": "bg-status-red",
    "high": "bg-status-orange",
    "medium": "bg-status-yellow",
    "low": "bg-status-blue",
}


def build_filter_url(**params):
    qs = "&".join(f"{k}={v}" for k, v in params.items() if v)
    return f"/alerts?{qs}" if qs else "/alerts"


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


templates.env.globals["filter_url"] = build_filter_url

app = FastAPI(title="Guardian", version="0.1.0")


@app.on_event("startup")
def startup():
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index(request: Request, new: str | None = None):
    profiles = list_profiles()
    if profiles and new is None:
        return RedirectResponse(url=f"/profiles/{profiles[0]['id']}", status_code=302)
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            **form_context(),
        },
    )


@app.get("/alerts")
def alerts_page(
    request: Request,
    severity: str | None = None,
    category: str | None = None,
    service: str | None = None,
):
    alerts = load_alerts()
    if severity:
        alerts = [a for a in alerts if a["severity"] == severity]
    if category:
        alerts = [a for a in alerts if a["category"] == category]
    if service:
        alerts = [a for a in alerts if service in a["affected_services"]]
    return templates.TemplateResponse(
        "alerts.html",
        {
            "request": request,
            "alerts": alerts,
            "severities": ALERT_SEVERITIES,
            "categories": ALERT_CATEGORIES,
            "category_labels": CATEGORY_LABELS,
            "severity_colors": SEVERITY_COLORS,
            "services": VALID_SERVICES,
            "service_labels": SERVICE_LABELS,
            "active_severity": severity,
            "active_category": category,
            "active_service": service,
        },
    )


@app.get("/profiles")
def profiles_list(request: Request):
    profiles = list_profiles()
    return templates.TemplateResponse(
        "profiles.html",
        {
            "request": request,
            "profiles": profiles,
            **form_context(),
        },
    )


@app.get("/profiles/{profile_id}/edit")
def edit_profile_page(request: Request, profile_id: int):
    profile = get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return templates.TemplateResponse(
        "edit.html",
        {
            "request": request,
            "profile": profile,
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


def format_sse(event, data):
    msg = f"event: {event}\n"
    for line in data.split("\n"):
        msg += f"data: {line}\n"
    msg += "\n"
    return msg


FREEZE_TIMERS = '<script>document.querySelectorAll(".live-timer").forEach(function(e){e.classList.remove("live-timer")})</script>'


def render_tool_event(event_type, data):
    tool = data["tool"]
    if event_type == "tool_start":
        return FREEZE_TIMERS + (
            '<div class="flex items-center gap-2.5 px-4 py-2.5 font-mono text-[12px] timeline-enter">'
            f'<span class="text-accent">▸</span>'
            f'<span class="text-white">{tool}</span>'
            f'<span class="text-dim flex-1">{data["description"]}</span>'
            '<span class="live-timer tabular-nums text-dim flex-shrink-0"></span>'
            "</div>"
        )
    latency = data.get("latency", "")
    latency_html = (
        f'<span class="tabular-nums text-dim flex-shrink-0">{latency}s</span>'
        if latency
        else ""
    )
    return FREEZE_TIMERS + (
        '<div class="flex items-center gap-2.5 px-4 py-2.5 font-mono text-[12px] timeline-enter">'
        f'<span class="text-status-green">✓</span>'
        f'<span class="text-white">{tool}</span>'
        f'<span class="text-muted flex-1">{data["summary"]}</span>'
        f"{latency_html}"
        "</div>"
    )


@app.get("/analyze/{profile_id}")
async def analyze_init(profile_id: int):
    profile = get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    html = (
        '<div id="run-btn-wrap" hx-swap-oob="innerHTML">'
        '<div class="py-6 border border-border-1 bg-white/[0.02] analyzing-pulse">'
        '<div class="flex items-center justify-center gap-2">'
        '<span class="text-[16px] text-dim uppercase tracking-[0.25em]">Analyzing</span>'
        '<span class="text-dim text-[16px]">...</span>'
        "</div></div>"
        "</div>"
        f'<div hx-ext="sse" sse-connect="/analyze/{profile_id}/stream" sse-close="close">'
        '<div id="agent-activity" class="max-w-md mx-auto">'
        '<div class="text-[11px] text-dim uppercase tracking-widest mb-3 mt-6 font-mono">'
        '<span class="text-accent mr-1.5">//</span>AGENT ACTIVITY'
        "</div>"
        '<div sse-swap="timeline" hx-swap="beforeend" class="border border-border-1 divide-y divide-border-1 mb-6"></div>'
        "</div>"
        '<div sse-swap="briefing"></div>'
        "</div>"
    )
    return HTMLResponse(html)


@app.get("/analyze/{profile_id}/stream")
async def analyze_stream(profile_id: int):
    profile = get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    async def generate():
        queue = asyncio.Queue()

        async def callback(event_type, data):
            await queue.put((event_type, data))

        async def run():
            result = await run_analysis(profile, event_callback=callback)
            await queue.put(("done", result))

        asyncio.create_task(run())

        while True:
            event_type, data = await queue.get()
            if event_type == "done":
                briefing = data
                html = templates.env.get_template("_briefing.html").render(
                    briefing=briefing,
                    severity_colors=SEVERITY_COLORS,
                )
                yield format_sse("timeline", FREEZE_TIMERS)
                yield format_sse("briefing", html)
                yield format_sse("close", "")
                break
            yield format_sse("timeline", render_tool_event(event_type, data))

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/toggle-ai")
async def toggle_ai():
    enabled = toggle_ai_mode()
    return {"enabled": enabled}


@app.get("/audit")
def audit_page(request: Request):
    entries = get_audit_log()
    return templates.TemplateResponse(
        "audit.html",
        {"request": request, "entries": entries},
    )
