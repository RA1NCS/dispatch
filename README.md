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

The core is a PydanticAI agent running on Gemini 3 Flash. It has tools it can call, `search_threats` to filter the threat database and `triage_alerts` to score relevance. For triage, it delegates to a lighter sub-agent on Gemini Flash-Lite, so the main agent decides *when* to classify and the sub-agent does the actual scoring. The whole thing streams to the UI via SSE so you see each tool call happen live.

The phishing analyzer and password checker work the same way. AI mode calls the external API first (Google Safe Browsing for phishing, HIBP for passwords), then feeds those results to a Gemini agent as context. So you get both the hard data from the API and the reasoning from the model. There's also an API-only button if you just want the raw scan without AI interpretation.

Every AI feature has a complete rule-based fallback. The phishing fallback checks urgency words, sender domain mismatches, suspicious TLDs. The password fallback checks length, character variety, sequential patterns. The triage fallback scores based on service overlap and region matching. None of these are stubs. They produce real, useful output.

![Architecture](docs/architecture.png)

### AI Disclosure

**Did you use an AI assistant?** Yes. Claude Code handled implementation and debugging. The design decisions, what to build, how to structure it, what to prioritize, were mine. Every piece of generated code was reviewed and tested manually.

**How did you verify the output?** Tested every feature in both AI and offline modes. Ran the phishing analyzer against obvious scams, subtle social engineering, and legitimate emails. Checked that fallback outputs match the same Pydantic schemas as AI outputs. Verified form validation rejects bad data. Ran the password checker against known-breached passwords and strong ones.

**What did you reject or change?** Originally used Claude Sonnet as the main model but it took 40-50 seconds per analysis, so I switched to Gemini Flash which brought it down to around 8 seconds. Rejected a suggestion to use SQLAlchemy since raw sqlite3 was 30 lines vs 100+ for a 2-table schema. The triage prompt originally boosted scores for Slack and Zoom for all remote workers even if they didn't use those services, which produced misleading results. Added a hard rule: if an alert has zero service overlap with the user's profile, it can't score above 0.4.

### Tradeoffs & Prioritization

**What got cut?** No real-time threat feeds. The 28 seed alerts are enough to show the agent's correlation and triage abilities, but a real version would pull from NVD, CISA KEV, and similar sources. No user authentication since it's a prototype. The audit log is write-only with no filtering or export. Phishing analyzer only looks at body text, not headers or attachments.

**What would come next?** Live threat ingestion so briefings reflect actual current threats. Email header parsing for the phishing analyzer so it could check SPF/DKIM/DMARC. Historical briefing comparison so you could track how your threat landscape changes over time. And proactive notifications when new threats match your profile instead of requiring manual analysis runs.

**Known limitations:** Seed data is static, so the agent can only correlate within the 28 alerts it has. The password checker briefly holds the plaintext password on the server during the HIBP check (only the first 5 chars of the SHA-1 hash leave the server via k-Anonymity). Gemini's temperature=0 isn't truly deterministic across sessions, so AI results can vary slightly between runs. No rate limiting on the phishing and password endpoints.
