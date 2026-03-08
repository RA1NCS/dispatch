Candidate Name: Shreyan Gupta   
Scenario Chosen: Community Safety & Digital Wellness  
Estimated Time Spent: ~6 hours

## Guardian

Security alerts are noisy. Most people don't have time to figure out which ones actually matter to them. Guardian is a personal security advisor that filters that noise based on your actual digital profile: what services you use, where you live, how you work.

You create a profile, hit analyze, and watch the AI investigate in real time. It searches a threat database, scores each alert against your specific profile, finds patterns across multiple alerts, and hands you a briefing with things you actually need to do. There's also a phishing email analyzer and a password breach checker built in.

If the AI is unavailable or you just don't trust it, flip the toggle in the navbar. Everything switches to deterministic rules instead. Same interface, same output format, no degraded experience.

### Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # add your API keys
uvicorn app.main:app --reload
```

Works without API keys. Everything runs on rule-based fallbacks when AI is off.

### How it works

The core is a PydanticAI agent running on Gemini 3 Flash. It has tools it can call, `search_threats` to filter the threat database and `triage_alerts` to score relevance. For triage, it delegates to a lighter sub-agent on Gemini Flash-Lite, so the main agent decides _when_ to classify and the sub-agent does the actual scoring. The whole thing streams to the UI via SSE so you see each tool call happen live.

The phishing analyzer and password checker work the same way. AI mode calls the external API first (Google Safe Browsing for phishing, HIBP for passwords), then feeds those results to a Gemini agent as context. So you get both the hard data from the API and the reasoning from the model. There's also an API-only button if you just want the raw scan without AI interpretation.

Every AI feature has a complete rule-based fallback. The phishing fallback checks urgency words, sender domain mismatches, suspicious TLDs. The password fallback checks length, character variety, sequential patterns. The triage fallback scores based on service overlap and region matching. None of these are stubs. They produce real, useful output.

![Architecture](docs/architecture.png)

### AI Disclosure

**Did you use an AI assistant?**  
Yes. Claude Code handled implementation and debugging. The architecture, design decisions, what to build and what to cut were mine. I reviewed every piece of generated code and ran a full verification pass at the end that caught two critical bugs the AI had introduced: the SSE stream would hang forever if the agent errored out, and the triage audit log would crash on an empty result set. Both were fixed before submission. This was alongside probably a couple hundred other errors.

**How did you verify the output?**  
55 automated tests across four files covering input validation, triage scoring logic, briefing generation, phishing detection rules, password strength checks, database CRUD, and every major route. All tests run fully offline with no API keys needed. Beyond automated tests, I manually tested the full analysis flow in both AI and offline modes, ran the phishing analyzer against obvious scams, subtle social engineering, and clean emails, and verified the password checker against known-breached passwords and strong ones. The verification pass also caught hardcoded color values that broke the accent color toggle, accessibility gaps on interactive elements, and an unused dependency left over from a model switch.

**What did you reject or change?**  
Switched from Claude Sonnet to Gemini Flash as the main model because Sonnet took 40-50 seconds per analysis while Flash brings it under 8. The triage prompt originally boosted scores for Slack and Zoom for all remote workers even when they did not use those services, producing misleading results. I added a hard rule: zero service overlap with the user profile means the score cannot exceed 0.4. Rejected a suggestion to use SQLAlchemy since raw sqlite3 was about 30 lines versus 100+ for a two-table schema. Also removed the Anthropic SDK from dependencies entirely once Gemini was confirmed working.

### Tradeoffs & Prioritization

**What got cut?**  
No real-time threat feeds. The 28 seed alerts are enough to demonstrate the agent's correlation and triage capabilities, but production would pull from NVD, CISA KEV, and similar sources. No user authentication since this is a prototype. The audit log records every tool call but has no filtering or export. Phishing analyzer only examines body text, not email headers or attachments.

**What would come next?**  
Live threat ingestion so briefings reflect current threats instead of seed data. Email header parsing for the phishing analyzer to check SPF, DKIM, and DMARC records. Historical briefing comparison so users could track how their threat landscape changes over time. Proactive notifications when new threats match a profile instead of requiring manual analysis runs.

**Known limitations:**  
Seed data is static, so the agent can only find correlations within the 28 alerts it has. In AI mode the plaintext password is sent to Google Gemini for analysis, which is a privacy tradeoff. For breach checking only the first 5 characters of the SHA-1 hash leave the server via HIBP k-Anonymity. Gemini temperature=0 is not truly deterministic across sessions, so AI results can vary slightly between runs. No rate limiting on the phishing and password endpoints.
