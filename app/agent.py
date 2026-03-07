import json
import time
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic_ai import Agent, RunContext

from app.database import log_audit
from app.fallback import generate_briefing, triage_alerts as fallback_triage
from app.schemas import (
    BriefingOutput,
    TriageResult,
    load_alerts,
    search_threats as filter_threats,
)

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

GUARDIAN_MODEL = "google-gla:gemini-3-flash-preview"
TRIAGE_MODEL = "google-gla:gemini-3.1-flash-lite-preview"

with open(CONFIG_DIR / "prompts.yaml") as f:
    PROMPTS = yaml.safe_load(f)


@dataclass
class ProfileDeps:
    profile: dict
    alerts: list[dict]


ai_mode = True

guardian_agent = Agent(
    GUARDIAN_MODEL,
    deps_type=ProfileDeps,
    output_type=BriefingOutput,
    instructions=PROMPTS["guardian_system"],
)

triage_agent = Agent(
    TRIAGE_MODEL,
    output_type=list[TriageResult],
    instructions=PROMPTS["triage_system"],
)


@guardian_agent.tool
async def search_threats(ctx: RunContext[ProfileDeps]) -> list[dict]:
    """Search the threat database for alerts relevant to the user's region and services."""
    start = time.time()
    profile = ctx.deps.profile
    results = filter_threats(profile["region"], profile["services"], ctx.deps.alerts)
    latency = int((time.time() - start) * 1000)
    log_audit(
        "search_threats",
        f"region={profile['region']}, services={profile['services']}",
        f"{len(results)} alerts found",
        latency,
        "none",
    )
    return results


@guardian_agent.tool
async def triage_alerts(ctx: RunContext[ProfileDeps], alerts: list[dict]) -> list[dict]:
    """Classify and score a list of alerts for relevance to the user's profile using AI."""
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
        f"{len(result.output)} results, top score={max(r.relevance_score for r in result.output):.1f}",
        latency,
        TRIAGE_MODEL,
    )
    return [r.model_dump() for r in result.output]


def toggle_ai_mode():
    global ai_mode
    ai_mode = not ai_mode
    return ai_mode


async def emit(callback, event_type, data):
    if callback:
        await callback(event_type, data)


async def run_analysis(profile, event_callback=None):
    alerts = load_alerts()
    if ai_mode:
        return await run_ai_analysis(profile, alerts, event_callback)
    return await run_fallback_analysis(profile, alerts, event_callback)


async def run_fallback_analysis(profile, alerts, event_callback):
    await emit(
        event_callback,
        "tool_start",
        {"tool": "search_threats", "description": "Filtering threat database..."},
    )
    t = time.time()
    matched = filter_threats(profile["region"], profile["services"], alerts)
    latency = f"{time.time() - t:.1f}"
    log_audit(
        "search_threats",
        f"region={profile['region']}",
        f"{len(matched)} found",
        0,
        "fallback",
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
        {"tool": "triage_alerts", "description": "Classifying alert relevance..."},
    )
    t = time.time()
    triaged = fallback_triage(matched, profile)
    latency = f"{time.time() - t:.1f}"
    log_audit(
        "triage_alerts",
        f"{len(matched)} alerts",
        f"{len(triaged)} triaged",
        0,
        "fallback",
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
        {"tool": "generate_briefing", "description": "Compiling security briefing..."},
    )
    t = time.time()
    briefing = generate_briefing(profile, matched, triaged)
    latency = f"{time.time() - t:.1f}"
    log_audit(
        "generate_briefing",
        f"profile #{profile['id']}",
        briefing.shield_status,
        0,
        "fallback",
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


async def run_ai_analysis(profile, alerts, event_callback):
    deps = ProfileDeps(profile=profile, alerts=alerts)
    user_prompt = (
        f"Analyze threats for this user and generate a security briefing.\n"
        f"Profile: region={profile['region']}, services={profile['services']}, "
        f"work_situation={profile['work_situation']}, primary_concern={profile['primary_concern']}"
    )

    tool_rounds = 0
    async with guardian_agent.iter(user_prompt, deps=deps) as run:
        async for node in run:
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
                    {"tool": "guardian", "description": label},
                )

    result = run.result
    log_audit(
        "guardian_agent",
        f"profile #{profile['id']}",
        result.output.shield_status,
        0,
        GUARDIAN_MODEL,
    )
    return result.output


TOOL_DESCRIPTIONS = {
    "search_threats": "Filtering threat database...",
    "triage_alerts": "Classifying alert relevance...",
}


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


def summarize_result(tool_name, result):
    count = len(result) if isinstance(result, (list, dict)) else None
    if tool_name == "search_threats":
        return f"Found {count} relevant alerts" if count else "Threats filtered"
    if tool_name == "triage_alerts":
        return f"Scored {count} alerts by risk" if count else "Alerts classified"
    return f"{count} results" if count else "Complete"
