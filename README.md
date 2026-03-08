Candidate Name: Shreyan Gupta   
Scenario Chosen: Community Safety & Digital Wellness   
Estimated Time Spent: ~6 hours

## Dispatch

Security alerts are noisy. Most people don't have time to figure out which ones actually matter to them. Dispatch is a personal security advisor that filters that noise based on your actual digital profile: what services you use, where you live, how you work.

You create a profile, hit analyze, and watch the AI investigate in real time. It searches a threat database, scores each alert against your specific profile, finds patterns across multiple alerts, and hands you a briefing with things you actually need to do. There's also a phishing email analyzer and a password breach checker built in.

If the AI is unavailable or you just don't trust it, flip the toggle in the navbar. Everything switches to deterministic rules instead. Same interface, same output format, no degraded experience.

### Quick Start

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # add your API keys
uvicorn app.main:app --reload
```

Works without API keys. Everything runs on rule-based fallbacks when AI is off.

```bash
pytest tests/ -v
```

### Video

[Watch the demo on YouTube](https://youtu.be/cMhSQhtzYa8)

### Tech Stack

- **Backend:** FastAPI, Jinja2, raw sqlite3
- **AI:** PydanticAI agents on Gemini 3 Flash (orchestration) and Gemini 3.1 Flash-Lite (triage + phishing)
- **Frontend:** HTMX + Tailwind CDN, no build step
- **Streaming:** SSE via FastAPI StreamingResponse
- **External APIs:** Google Safe Browsing (phishing URLs), HIBP Pwned Passwords (breach check, k-Anonymity)

### The Design

The core is a PydanticAI agent on Gemini Flash with two tools: `search_threats` filters the threat database, `triage_alerts` scores relevance. For triage, the main agent delegates to a lighter sub-agent on Flash-Lite, so Dispatch decides _when_ to classify and the sub-agent does the actual scoring. Everything streams to the UI via SSE.

The phishing analyzer has three modes: AI (Safe Browsing + Gemini reasoning), API-only (Safe Browsing scan, no AI), and offline (keyword rules). The password checker uses HIBP for breach lookups and local rules for strength. Passwords never touch any AI model, that's a deliberate privacy choice.

Every AI feature has a complete rule-based fallback. Not stubs. Real output.

**Why this stack:**
- HTMX + Jinja2 over a React SPA: a separate frontend would mean a separate server, CORS config, and a build pipeline for something that doesn't need client-side state. Server-rendered templates with HTMX partial swaps do everything this prototype needs.
- PydanticAI over LangChain: PydanticAI abstracts tool registration, agent delegation, and structured output into decorators and type hints. Less wiring code, more focus on the actual agent logic.
- Dual-model split: Flash for orchestration (decides what to investigate, synthesizes the briefing), Flash-Lite for classification (scores alerts). Optimized for latency and cost without sacrificing reasoning quality where it matters.
- Raw sqlite3: two tables, parameterized queries, about 30 lines total. No migration files, no session management, no ORM config. Right tool for the scale.

![Architecture](docs/architecture.png)

### Tradeoffs & Prioritization

**What got cut:**
- Real-time threat feeds from Government Databases (28 seed alerts are enough to demo correlation and triage)
- User authentication (prototype scope)
- Audit log filtering and export
- Email header/attachment parsing in the phishing analyzer

**Future enhancements:**
- Live threat ingestion from NVD, CISA KEV so briefings reflect real-world threats
- Zip code-level localization: users enter a zip code and get threat data scoped to their area
- SPF/DKIM/DMARC checking for phishing analysis
- Historical briefing comparison to track how a user's threat landscape changes over time
- Proactive notifications when new threats match a profile

**Known limitations:**
- Seed data is static, so correlations are limited to the 28 alerts
- Gemini temperature=0 isn't truly deterministic across sessions, so AI results can vary slightly
- No rate limiting on phishing and password endpoints

### AI Disclosure

**Did you use an AI assistant?**
Yes. Claude Code handled implementation, but I was in the loop at every stage. I defined the architecture, chose the models, decided what to build and what to cut. Every piece of generated code went through manual review. I used sub-agents and automated skill checks throughout the process to double-check code quality, catch regressions, and verify that changes in one file didn't break assumptions elsewhere. The final verification pass ran dedicated agents in parallel across backend, templates, config, and rubric compliance. That pass caught two critical bugs: the SSE stream hanging forever on agent errors, and the triage audit log crashing on empty result sets. Both were fixed before submission.

**How did you verify the output?**
55 automated tests across four files, all running fully offline with no API keys:
- Input validation, triage scoring, briefing generation
- Phishing detection rules, password strength checks
- Database CRUD, every major route (status codes + response content)

Beyond automated tests, I manually tested the full analysis flow in both AI and offline modes, ran the phishing analyzer against obvious scams and clean emails, and verified the password checker against known-breached and strong passwords. The verification pass also caught hardcoded color values that broke the theme toggle, accessibility gaps on interactive elements, and a stale dependency left over from a model switch.

**What did you reject or change?**
- The AI initially generated the password checker to send plaintext passwords to a Gemini agent for strength analysis. I caught this during review and removed it entirely. Passwords now never leave the server. Breach checks use HIBP k-Anonymity (only 5 chars of a SHA-1 hash are sent), and strength scoring is pure local rules.
- Switched from Claude Sonnet to Gemini Flash after profiling showed Sonnet taking 40-50s per analysis. Flash brings it under 8 seconds with no meaningful quality loss for this use case.
- The triage prompt was silently boosting relevance scores for Slack and Zoom for all remote workers, even when those services weren't in the user's profile. This produced misleading briefings. I added a hard rule: zero service overlap with the user's profile means the relevance score is capped at 0.4.
- Rejected a suggestion to use SQLAlchemy. Two tables and five queries don't need an ORM. Raw sqlite3 with parameterized queries is about 30 lines total.
