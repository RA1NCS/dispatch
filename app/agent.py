import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import yaml
from pydantic_ai import Agent, RunContext

from app.database import log_audit
from app.fallback import (
    analyze_phishing_offline,
    check_password_offline,
    generate_briefing,
    triage_alerts as fallback_triage,
)
from app.schemas import (
    URL_PATTERN,
    BriefingOutput,
    PhishingResult,
    TriageResult,
    load_alerts,
    search_threats as filter_threats,
)

# --- config ---

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

# model ids for pydantic-ai agents
DISPATCH_MODEL = "google-gla:gemini-3-flash-preview"
TRIAGE_MODEL = "google-gla:gemini-3.1-flash-lite-preview"

# load system prompts from yaml (externalized for easy editing)
with open(CONFIG_DIR / "prompts.yaml") as f:
    PROMPTS = yaml.safe_load(f)

# deps injected into the dispatch agent via RunContext
@dataclass
class ProfileDeps:
    profile: dict
    alerts: list[dict]
    matched_alerts: list[dict] | None = None


# global toggle for ai vs offline mode
ai_mode = True


# flips between ai and offline mode
def toggle_ai_mode():
    global ai_mode
    ai_mode = not ai_mode
    return ai_mode


# --- agent definitions ---

# main orchestrator agent, calls tools and synthesizes briefing
dispatch_agent = Agent(
    DISPATCH_MODEL,
    deps_type=ProfileDeps,
    output_type=BriefingOutput,
    instructions=PROMPTS["dispatch_system"],
    model_settings={"temperature": 0.0},
)

# sub-agent for scoring alert relevance to a profile
triage_agent = Agent(
    TRIAGE_MODEL,
    output_type=list[TriageResult],
    instructions=PROMPTS["triage_system"],
    model_settings={"temperature": 0.0},
)

# analyzes emails for phishing indicators
phishing_agent = Agent(
    TRIAGE_MODEL,
    output_type=PhishingResult,
    instructions=PROMPTS["phishing_system"],
    model_settings={"temperature": 0.0},
)



# --- dispatch agent tools ---


# filters the threat db by region and services, stores results in deps
@dispatch_agent.tool
async def search_threats(ctx: RunContext[ProfileDeps]) -> str:
    """Search the threat database for alerts relevant to the user's region and services."""
    start = time.time()
    profile = ctx.deps.profile
    results = filter_threats(profile["region"], profile["services"], ctx.deps.alerts)
    ctx.deps.matched_alerts = results
    latency = int((time.time() - start) * 1000)
    log_audit(
        "search_threats",
        f"region={profile['region']}, services={profile['services']}",
        f"{len(results)} alerts found",
        latency,
        "local",
    )
    return f"Found {len(results)} alerts matching the user's profile."


# delegates to the triage sub-agent to score alerts stored in deps
@dispatch_agent.tool
async def triage_alerts(ctx: RunContext[ProfileDeps]) -> list[dict]:
    """Classify and score the matched alerts for relevance to the user's profile. Call after search_threats."""
    alerts = ctx.deps.matched_alerts or []
    start = time.time()
    profile = ctx.deps.profile
    prompt = (
        f"User profile: region={profile['region']}, services={profile['services']}, "
        f"work_situation={profile['work_situation']}, primary_concern={profile['primary_concern']}\n\n"
        f"Alerts to triage:\n{json.dumps(alerts, indent=2)}"
    )
    result = await triage_agent.run(prompt, usage=ctx.usage)
    latency = int((time.time() - start) * 1000)
    log_audit(
        "triage_alerts",
        f"{len(alerts)} alerts for profile #{profile['id']}",
        f"{len(result.output)} results, top score={max((r.relevance_score for r in result.output), default=0):.1f}",
        latency,
        TRIAGE_MODEL,
    )
    # merge triage scores with original alert data so the agent has full context
    alert_map = {a["id"]: a for a in alerts}
    enriched = []
    for r in result.output:
        alert = alert_map.get(r.alert_id, {})
        enriched.append({
            **r.model_dump(),
            "title": alert.get("title", ""),
            "severity": alert.get("severity", ""),
            "category": alert.get("category", ""),
            "affected_services": alert.get("affected_services", []),
            "description": alert.get("description", ""),
        })
    return enriched


# --- sse streaming helpers ---


# helper to fire sse events if a callback is provided
async def emit(callback, event_type, data):
    if callback:
        await callback(event_type, data)


# friendly labels for the agent activity timeline
TOOL_DESCRIPTIONS = {
    "search_threats": "Filtering threat database...",
    "triage_alerts": "Classifying alert relevance...",
    "generate_briefing": "Compiling security briefing...",
}


# streams tool start/result events from an agent tool call node
async def stream_tool_events(node, ctx, event_callback):
    current_tool = "unknown"
    tool_start_time = None
    async with node.stream(ctx) as stream:
        async for event in stream:
            if hasattr(event, "part") and hasattr(event.part, "tool_name"):
                current_tool = event.part.tool_name
                tool_start_time = time.time()
                await emit(
                    event_callback,
                    "tool_start",
                    {
                        "tool": current_tool,
                        "description": TOOL_DESCRIPTIONS.get(
                            current_tool, "Processing..."
                        ),
                    },
                )
            if not hasattr(event, "result"):
                continue
            latency = f"{time.time() - tool_start_time:.1f}" if tool_start_time else ""
            await emit(
                event_callback,
                "tool_result",
                {
                    "tool": current_tool,
                    "summary": summarize_result(current_tool, event.result),
                    "latency": latency,
                },
            )


# turns a raw tool result into a short human-readable summary
def summarize_result(tool_name, result):
    # extract content from ToolReturnPart if needed
    raw = getattr(result, "content", result)
    if tool_name == "search_threats":
        return str(raw) if raw else "Threats filtered"
    # pydantic-ai streams results as serialized strings, try to parse
    data = raw
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            data = raw
    count = len(data) if isinstance(data, (list, dict)) else None
    if tool_name == "triage_alerts":
        return f"Scored {count} alerts by risk" if count else "Alerts classified"
    return f"{count} results" if count else "Complete"


# --- analysis pipeline ---


# entry point: routes to ai or fallback based on mode toggle
async def run_analysis(profile, event_callback=None):
    alerts = load_alerts()
    if ai_mode:
        return await run_ai_analysis(profile, alerts, event_callback)
    return await run_fallback_analysis(profile, alerts, event_callback)


# runs the full analysis using rule-based logic (no ai calls)
async def run_fallback_analysis(profile, alerts, event_callback):
    await emit(
        event_callback,
        "tool_start",
        {"tool": "search_threats", "description": TOOL_DESCRIPTIONS["search_threats"]},
    )
    t = time.time()
    matched = filter_threats(profile["region"], profile["services"], alerts)
    latency = f"{time.time() - t:.1f}"
    log_audit(
        "search_threats",
        f"region={profile['region']}",
        f"{len(matched)} found",
        0,
        "offline",
    )
    await emit(
        event_callback,
        "tool_result",
        {
            "tool": "search_threats",
            "summary": f"Found {len(matched)} relevant alerts",
            "latency": latency,
        },
    )

    await emit(
        event_callback,
        "tool_start",
        {"tool": "triage_alerts", "description": TOOL_DESCRIPTIONS["triage_alerts"]},
    )
    t = time.time()
    triaged = fallback_triage(matched, profile)
    latency = f"{time.time() - t:.1f}"
    log_audit(
        "triage_alerts",
        f"{len(matched)} alerts",
        f"{len(triaged)} triaged",
        0,
        "offline",
    )
    await emit(
        event_callback,
        "tool_result",
        {
            "tool": "triage_alerts",
            "summary": f"Scored {len(triaged)} alerts",
            "latency": latency,
        },
    )

    await emit(
        event_callback,
        "tool_start",
        {"tool": "generate_briefing", "description": TOOL_DESCRIPTIONS["generate_briefing"]},
    )
    t = time.time()
    briefing = generate_briefing(profile, matched, triaged)
    latency = f"{time.time() - t:.1f}"
    log_audit(
        "generate_briefing",
        f"profile #{profile['id']}",
        briefing.shield_status,
        0,
        "offline",
    )
    await emit(
        event_callback,
        "tool_result",
        {
            "tool": "generate_briefing",
            "summary": f"Shield status: {briefing.shield_status}",
            "latency": latency,
        },
    )

    return briefing


# runs the full analysis using the dispatch agent (ai mode)
async def run_ai_analysis(profile, alerts, event_callback):
    deps = ProfileDeps(profile=profile, alerts=alerts)
    user_prompt = (
        f"Analyze threats for this user and generate a security briefing.\n"
        f"Profile: region={profile['region']}, services={profile['services']}, "
        f"work_situation={profile['work_situation']}, primary_concern={profile['primary_concern']}"
    )

    # stream agent nodes, emitting sse events for each tool call
    tool_rounds = 0
    thinking_start = None
    async with dispatch_agent.iter(user_prompt, deps=deps) as run:
        async for node in run:
            # close out any pending thinking phase
            if thinking_start is not None:
                latency = f"{time.time() - thinking_start:.1f}"
                await emit(
                    event_callback,
                    "tool_result",
                    {"tool": "dispatch", "summary": "Done", "latency": latency},
                )
                thinking_start = None

            if Agent.is_call_tools_node(node):
                await stream_tool_events(node, run.ctx, event_callback)
                tool_rounds += 1
            elif Agent.is_model_request_node(node) and tool_rounds > 0:
                label = (
                    "Generating security briefing..."
                    if tool_rounds >= 2
                    else "Analyzing threat data..."
                )
                await emit(
                    event_callback,
                    "tool_start",
                    {"tool": "dispatch", "description": label},
                )
                thinking_start = time.time()

        # close final thinking phase
        if thinking_start is not None:
            latency = f"{time.time() - thinking_start:.1f}"
            await emit(
                event_callback,
                "tool_result",
                {"tool": "dispatch", "summary": "Briefing ready", "latency": latency},
            )

    result = run.result
    log_audit(
        "dispatch_agent",
        f"profile #{profile['id']}",
        result.output.shield_status,
        0,
        DISPATCH_MODEL,
    )
    return result.output


# --- external api helpers ---

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
HIBP_URL = "https://api.pwnedpasswords.com/range/"


# checks urls against google safe browsing api
async def _scan_urls(text):
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
    urls = URL_PATTERN.findall(text)
    if not api_key or not urls:
        return {"urls_found": len(urls), "api_configured": bool(api_key), "threats": []}

    body = {
        "client": {"clientId": "dispatch", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:10]],
        },
    }

    start = time.time()
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(f"{SAFE_BROWSING_URL}?key={api_key}", json=body)
    latency = int((time.time() - start) * 1000)

    if resp.status_code != 200:
        log_audit("safe_browsing", f"{len(urls)} URLs", f"error {resp.status_code}", latency, "api")
        return {"urls_found": len(urls), "api_configured": True, "threats": [], "error": resp.status_code}

    matches = resp.json().get("matches", [])
    log_audit("safe_browsing", f"{len(urls)} URLs", f"{len(matches)} threats", latency, "api")
    return {"urls_found": len(urls), "api_configured": True, "threats": matches}


# checks password against have i been pwned using k-anonymity
async def _check_hibp(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    start = time.time()
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{HIBP_URL}{prefix}")
    latency = int((time.time() - start) * 1000)

    if resp.status_code != 200:
        log_audit("hibp", "password check", f"error {resp.status_code}", latency, "api")
        return {"breached": None, "count": 0, "error": resp.status_code}

    breach_count = 0
    for line in resp.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            breach_count = int(count)
            break

    log_audit("hibp", "password check", f"breached={breach_count > 0}", latency, "api")
    return {"breached": breach_count > 0, "count": breach_count}


# --- phishing analysis (3 modes: ai, api-only, offline) ---


# ai mode runs safe browsing first, then feeds results to gemini
async def analyze_phishing(text):
    if ai_mode:
        scan = await _scan_urls(text)
        return await _analyze_phishing_ai(text, scan)
    return analyze_phishing_offline(text)


# builds context from url scan and sends to phishing agent
async def _analyze_phishing_ai(text, url_scan):
    scan_context = ""
    if url_scan["threats"]:
        flagged = {m["threat"]["url"] for m in url_scan["threats"]}
        types = {m["threatType"] for m in url_scan["threats"]}
        scan_context = (
            f"\n\nGoogle Safe Browsing results: {len(url_scan['threats'])} threat(s) detected.\n"
            f"Flagged URLs: {', '.join(flagged)}\n"
            f"Threat types: {', '.join(types)}"
        )
    elif url_scan["urls_found"] > 0 and url_scan["api_configured"]:
        scan_context = f"\n\nGoogle Safe Browsing results: {url_scan['urls_found']} URL(s) scanned, no threats found."
    elif not url_scan["api_configured"]:
        scan_context = "\n\nGoogle Safe Browsing: not configured."

    start = time.time()
    result = await phishing_agent.run(f"Analyze this email:\n\n{text}{scan_context}")
    latency = int((time.time() - start) * 1000)
    log_audit("analyze_phishing", f"{len(text)} chars", result.output.verdict, latency, TRIAGE_MODEL)
    return result.output


# api-only mode: safe browsing scan + offline rules (no ai)
async def analyze_phishing_api(text):
    scan = await _scan_urls(text)
    result = analyze_phishing_offline(text)

    if not scan["api_configured"]:
        result.red_flags.insert(0, "Google Safe Browsing API key not configured")
        return result

    if not scan["urls_found"]:
        result.red_flags.insert(0, "No URLs found to check")
        return result

    if "error" in scan:
        result.red_flags.insert(0, f"Safe Browsing API returned status {scan['error']}")
        return result

    if scan["threats"]:
        flagged = {m["threat"]["url"] for m in scan["threats"]}
        types = {m["threatType"] for m in scan["threats"]}
        for url in flagged:
            result.red_flags.insert(0, f"Google Safe Browsing flagged: {url[:80]}")
        result.verdict = "phishing"
        result.confidence = min(0.95, result.confidence + 0.3)
        result.explanation = (
            f"Safe Browsing detected {len(scan['threats'])} threat(s) "
            f"({', '.join(types)}). {result.explanation}"
        )
    else:
        result.red_flags.insert(0, f"URLs scanned: no threats found ({scan['urls_found']} URL(s))")

    return result


# --- password check (2 modes: hibp + rules, or rules only) ---
# passwords never leave the server. no AI involved for privacy.


# online mode: hibp breach scan + offline rules
async def check_password(password):
    if ai_mode:
        return await check_password_api(password)
    return check_password_offline(password)


# hibp breach scan + offline rules (no ai)
async def check_password_api(password):
    hibp = await _check_hibp(password)
    result = check_password_offline(password)

    if "error" in hibp:
        result.reasons.insert(0, f"HIBP API returned status {hibp['error']}")
        return result

    result.breached = hibp["breached"]
    result.breach_count = hibp["count"]

    if hibp["breached"]:
        result.reasons.insert(0, f"Found in {hibp['count']:,} data breaches (HIBP)")
        if result.strength != "weak":
            result.strength = "weak"
    else:
        result.reasons.insert(0, "Not found in any known data breaches (HIBP)")

    return result
