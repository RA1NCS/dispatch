import asyncio
from pathlib import Path

from dotenv import load_dotenv

# load env before anything else touches os.environ
load_dotenv()

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

import app.agent as agent
from app.agent import (
    analyze_phishing,
    analyze_phishing_api,
    check_password,
    run_analysis,
    toggle_ai_mode,
)
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
    load_phishing_samples,
)

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# tailwind classes for severity dot colors
SEVERITY_COLORS = {
    "critical": "bg-status-red",
    "high": "bg-status-orange",
    "medium": "bg-status-yellow",
    "low": "bg-status-blue",
}


# builds alert filter urls preserving active params
def build_filter_url(**params):
    qs = "&".join(f"{k}={v}" for k, v in params.items() if v)
    return f"/alerts?{qs}" if qs else "/alerts"


# shared template context for profile create/edit forms
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
templates.env.globals["ai_mode"] = lambda: agent.ai_mode

# cached briefing results per profile (cleared on mode toggle)
_briefing_cache: dict[int, tuple] = {}

app = FastAPI(title="Dispatch", version="0.1.0")


# initialize database tables on server start
@app.on_event("startup")
def startup():
    init_db()


# basic liveness check
@app.get("/health")
def health():
    return {"status": "ok"}


# landing page: redirects to latest profile, or shows create form
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


# alert feed with severity/category/service filter pills
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


# --- profile crud ---


# profile list with collapsed create form
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


# creates a new profile and redirects to analysis page
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


# main analysis page with hero button and profile chip
@app.get("/profiles/{profile_id}")
def view_profile(request: Request, profile_id: int):
    profile = get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    cached = _briefing_cache.get(profile_id)
    briefing, mode_label = cached if cached else (None, None)
    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "profile": profile,
            "briefing": briefing,
            "mode_label": mode_label,
            "severity_colors": SEVERITY_COLORS,
            **form_context(),
        },
    )


# edit profile form
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


# updates profile and redirects back
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


# --- sse streaming ---


# formats a server-sent event with event name and data lines
def format_sse(event, data):
    msg = f"event: {event}\n"
    for line in data.split("\n"):
        msg += f"data: {line}\n"
    msg += "\n"
    return msg


# injected before each timeline row to stop previous live timers
FREEZE_TIMERS = '<script>document.querySelectorAll(".live-timer").forEach(function(e){e.classList.remove("live-timer")})</script>'


# builds html for a tool start or tool result row in the timeline
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


# swaps the run button to "analyzing" and injects the sse container
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


# streams tool events via sse, then sends the final briefing
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
            try:
                result = await run_analysis(profile, event_callback=callback)
                await queue.put(("done", result))
            except Exception as e:
                await queue.put(("error", str(e)))

        asyncio.create_task(run())

        # drain queue until analysis is done
        while True:
            event_type, data = await queue.get()
            if event_type == "done":
                briefing = data
                mode_label = "Gemini Flash" if agent.ai_mode else "Rule-based"
                _briefing_cache[profile_id] = (briefing, mode_label)
                html = templates.env.get_template("_briefing.html").render(
                    briefing=briefing,
                    severity_colors=SEVERITY_COLORS,
                    mode_label=mode_label,
                )
                yield format_sse("timeline", FREEZE_TIMERS)
                yield format_sse("briefing", html)
                yield format_sse("close", "")
                break
            if event_type == "error":
                error_html = (
                    FREEZE_TIMERS
                    + '<div class="flex items-center gap-2.5 px-4 py-2.5 font-mono text-[12px] timeline-enter">'
                    + '<span class="text-status-red">✗</span>'
                    + f'<span class="text-status-red">Analysis failed: {data}</span>'
                    + "</div>"
                )
                yield format_sse("timeline", error_html)
                yield format_sse("close", "")
                break
            yield format_sse("timeline", render_tool_event(event_type, data))

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# flips global ai_mode toggle and clears cached briefings
@app.post("/toggle-ai")
async def toggle_ai():
    _briefing_cache.clear()
    enabled = toggle_ai_mode()
    return {"enabled": enabled}


# --- phishing + password tools ---


# phishing analyzer page with sample picker
@app.get("/phishing")
def phishing_page(request: Request):
    samples = load_phishing_samples()
    return templates.TemplateResponse(
        "phishing.html",
        {"request": request, "samples": samples},
    )


# analyzes email text, returns partial result html
@app.post("/phishing/analyze")
async def phishing_analyze(
    request: Request, email_text: str = Form(...), mode: str = Form("auto")
):
    if not email_text.strip():
        return HTMLResponse(
            '<div class="text-dim text-[13px]">Please enter email text to analyze.</div>'
        )
    # route to the right analysis mode
    if mode == "api":
        result = await analyze_phishing_api(email_text)
        mode_label = "Safe Browsing"
    else:
        result = await analyze_phishing(email_text)
        mode_label = "AI + Safe Browsing" if agent.ai_mode else "Offline"
    return templates.TemplateResponse(
        "_phishing_result.html",
        {"request": request, "result": result, "mode_label": mode_label},
    )


# password checker page
@app.get("/password")
def password_page(request: Request):
    return templates.TemplateResponse(
        "password.html",
        {"request": request},
    )


# checks password strength, returns partial result html
# passwords never leave the server, online adds hibp breach check
@app.post("/password/check")
async def password_check(request: Request, password: str = Form(...)):
    if not password.strip():
        return HTMLResponse(
            '<div class="text-dim text-[13px]">Please enter a password to check.</div>'
        )
    result = await check_password(password)
    mode_label = "Breach Scan" if agent.ai_mode else "Offline"
    return templates.TemplateResponse(
        "_password_result.html",
        {"request": request, "result": result, "mode_label": mode_label},
    )


# audit log table showing all tool calls
@app.get("/audit")
def audit_page(request: Request):
    entries = get_audit_log()
    return templates.TemplateResponse(
        "audit.html",
        {"request": request, "entries": entries},
    )
