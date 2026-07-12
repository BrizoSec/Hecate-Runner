# sec7669

Autonomous hunt draft orchestrator for the [Nebulock Agentic Threat Hunting Framework (ATHF)](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework).

`sec7669` sits on top of ATHF and turns it into a persistent, 24/7 hunting loop:

1. Pulls fresh CTI from a configured source (file queue, AlienVault OTX, RSS/Atom feeds, or MISP)
2. Calls the ATHF `hypothesis-generator` agent (which uses a local Ollama-served LLM)
3. Writes structured draft hunt records into your ATHF workspace
4. Never auto-executes queries — a human proposes a bounded query and separately approves running it (see [Query execution](#query-execution-propose-dont-run) below); nothing runs unattended

Runs as a systemd timer on a hunting host, or manually via `sec7669 run`.

## Design principles

- **Read-context, not hard dependency on ATHF.** `sec7669` shells out to the `athf` CLI; it does not import ATHF as a library. ATHF and `sec7669` version independently.
- **Human-in-the-loop by default.** Every generated hunt is `status: planning` with a "review required" banner. Nothing auto-executes.
- **Guardrails first.** Daily draft quotas, hard timeouts on LLM calls, structured logs, per-run state persistence.
- **Testable in isolation.** No network, no LLM, no ATHF required to run unit tests locally.

## Architecture

```
                        cti_queue/next.txt         <-- CTI provider (file or OTX)
                                |
                                v
+------------------+     +--------------+     +----------------------+     +----------------+
| systemd timer    | --> | sec7669 run  | --> | athf research new    | --> | Ollama (local) |
| every 6h + boot  |     | (this repo)  |     | (5-skill, web-search  |     | qwen2.5:14b    |
+------------------+     +--------------+     | grounded via Tavily)  |     +----------------+
                                |              +----------------------+
                                |                        |
                                |                 research_id (R-XXXX)
                                v                        |
                     +--------------------------+        |
                     | athf hypothesis-generator | <------+
                     +--------------------------+
                                |
                                v
                     hunts/production/YYYY/QN/H-XXXX.md  (spawned_from: R-XXXX)
                     research/R-XXXX.md
                     logs/orchestrator.log
                     .orchestrator_state.json
```

Research grounding runs before hypothesis generation on every cycle by default (`SEC7669_RESEARCH_ENABLED=true`). **A research failure aborts the cycle** (refunds the quota, leaves the CTI queued for retry) rather than falling back to an ungrounded hypothesis: `athf eval` measured ungrounded generation at ~30% accuracy on known-answer MITRE technique fixtures, so an ungrounded draft isn't a degraded-but-useful fallback, it's an unreliable one. Set `SEC7669_RESEARCH_ENABLED=false` to explicitly opt out of research and always generate ungrounded (e.g. for offline testing) — that's a deliberate choice, different from a research call failing mid-cycle.

## Query execution: propose, don't run

A draft hunt's CHECK section still says "sec7669 DOES NOT auto-generate queries" — that hasn't changed, and won't until query *authoring* has its own eval-backed accuracy check the way hypothesis generation now does. What's new is a bounded bridge for the query a *human* writes, so running it doesn't mean dropping to a raw SIEM CLI:

```
sec7669 propose H-0016 --query '...' --data-source splunk \
  --time-range-days 7 --limit 100 --justification '...'
    |
    v   guardrails checked (time range, result limit, non-empty) -- reject outright if violated
.pending_queries/H-0016.json
    |
    v   sec7669 pending          (see what's staged)
    v   sec7669 approve H-0016   (re-checks guardrails, prompts to confirm, then executes)
    v   sec7669 reject H-0016    (discard without running)
    |
    v
QueryProvider.execute()  -->  mock (default) | splunk (shells out to `athf splunk search`)
```

Guardrails (`SEC7669_MAX_QUERY_TIME_RANGE_DAYS`, default 7; `SEC7669_MAX_QUERY_LIMIT`, default 1000) mirror ATHF's own `AGENTS.md` Query Guardrails section, and are re-checked at `approve` time, not just at `propose` time — if the staged file was hand-edited or the ceilings changed in between, `approve` refuses rather than trusting the earlier check.

**`SEC7669_QUERY_PROVIDER=mock` is the default and, as of this writing, the only backend that's actually been run.** There is no live Splunk instance in this environment to validate `SplunkQueryProvider` against yet — it shells out to `athf splunk search` (same subprocess pattern as `AthfClient`) and is unit-tested against a fake `athf` binary, but nothing here has touched a real SIEM. Treat it as ready-to-wire, not proven, until it has. Switching from mock to a real backend is meant to be a config change (`SEC7669_QUERY_PROVIDER=splunk` + `SPLUNK_HOST`/`SPLUNK_TOKEN` in the ATHF workspace `.env`), not new code — `sec7669 doctor` checks for both when the provider is set to `splunk`.

## Quickstart (local dev)

```bash
# Clone
git clone https://github.com/BrizoSec/sec7669.git
cd sec7669

# uv installs Python + venv + deps in one shot
uv sync --dev

# Copy env template and edit
cp .env.example .env
# edit .env to point ATHF_WORKSPACE at wherever your ATHF workspace lives

# Run tests
uv run pytest

# Preview an orchestrator cycle (uses your local ATHF workspace)
uv run sec7669 run --dry-run

# Real run (invokes athf hypothesis-generator + writes a draft hunt)
uv run sec7669 run
```

## Deploy to k3s-core

```bash
# Push repo
git push origin main

# On k3s-core
cd ~
git clone https://github.com/BrizoSec/sec7669.git
cd sec7669

# Install with uv (recommended) or pip
uv sync

# Env
cp .env.example .env
$EDITOR .env

# Install systemd units
sudo ./scripts/install-systemd.sh

# Prime a CTI blurb and force a run
echo "APT actor X observed using T1053.005 scheduled tasks" > $ATHF_WORKSPACE/cti_queue/next.txt
sudo systemctl start sec7669-orchestrator.service

# Enable persistent scheduling
sudo systemctl enable --now sec7669-orchestrator.timer
sudo systemctl list-timers sec7669-orchestrator.timer
```

### Optional: AlienVault OTX CTI provider

Instead of (or alongside) hand-dropping CTI into `cti_queue/next.txt`, `sec7669` can pull it from [AlienVault OTX](https://otx.alienvault.com) pulses you're subscribed to.

```bash
# Get a free-tier API key at https://otx.alienvault.com/settings, then:
echo 'OTX_API_KEY=your-key-here' >> .env

# One-off: route the next high-signal pulse into the CTI queue
uv run sec7669 otx-poll

# Persistent: poll hourly, independent of the orchestrator's 6h cycle
sudo systemctl enable --now sec7669-otx-poller.timer
```

The poller filters for high-signal pulses (TLP white/green, has a MITRE ATT&CK mapping, not older than `SEC7669_OTX_MAX_PULSE_AGE_DAYS`) and routes the oldest unrouted one into `cti_queue/next.txt`, so the existing orchestrator picks it up on its normal schedule — OTX polling frequency and hypothesis-generation frequency stay decoupled. A cursor file (`.otx_cursor_state.json` in the ATHF workspace) tracks the last pulse routed so nothing is re-ingested.

You can also skip the file queue entirely and have the orchestrator pull directly from OTX every cycle by setting `SEC7669_CTI_PROVIDER=otx` — in that mode you don't need the poller timer at all.

### RSS/Atom CTI provider (no API key required)

Unlike OTX, this needs no signup or credential — it polls a configured list of security research blog feeds directly.

```bash
# Works out of the box with four verified defaults (The DFIR Report, Talos,
# Unit42, Microsoft Security Blog) -- override with your own list:
# SEC7669_RSS_FEED_URLS=https://a.example.com/feed/,https://b.example.com/feed/

# One-off: route the oldest unrouted entry across all configured feeds
uv run sec7669 rss-poll

# Persistent: poll hourly, independent of the orchestrator's 6h cycle
sudo systemctl enable --now sec7669-rss-poller.timer
```

Unlike OTX's crowdsourced pulse firehose (filtered by TLP + ATT&CK mapping), the "high signal" filter here is mostly the curation itself — every URL in the list is a feed you picked, not an open subscription. Entries are only filtered by age (`SEC7669_RSS_MAX_ENTRY_AGE_DAYS`, default 30) and dedup (`.rss_cursor_state.json`, one cursor per feed URL). A MITRE technique ID is still extracted from the title/summary when present and included as metadata, but its absence doesn't exclude an entry.

One feed being down or blocking automated requests doesn't stop entries from the others — CISA's advisory feed was tried while building this and excluded from the defaults for exactly that reason (403s on every path tried, with or without a browser-like User-Agent).

Same dual-mode support as OTX: `SEC7669_CTI_PROVIDER=rss` pulls directly from the configured feeds every orchestrator cycle instead of routing through the file queue via the poller timer.

### MISP CTI provider

```bash
# Point at your MISP instance and a dedicated automation key (Administration
# -> List Auth Keys -> Add authentication key in the MISP UI -- not a
# personal user's key):
# MISP_BASE_URL=https://localhost:8443
# MISP_API_KEY=...
# SEC7669_MISP_VERIFY_SSL=false   # only for self-signed dev/test instances

# One-off: route the oldest unrouted published event
uv run sec7669 misp-poll

# Persistent: poll hourly, independent of the orchestrator's 6h cycle
sudo systemctl enable --now sec7669-misp-poller.timer
```

Polls `POST /events/restSearch`, filtered to `published` events, incrementally synced via a `timestamp`-based cursor (`.misp_cursor_state.json`) the same way OTX's `modified_since` works. TLP is tag-based in MISP (`tlp:white`/`tlp:red`/etc.) rather than a dedicated field like OTX has — an event with an explicit `tlp:red` or `tlp:amber` tag is excluded, but an event with **no** TLP tag at all defaults to safe/included, matching how `OtxProvider` treats a missing TLP field. Like RSS (and unlike OTX), an event doesn't need a MITRE Galaxy/technique mapping to be considered high signal — a curated MISP instance is itself the filter. When a Galaxy cluster *is* attached, technique IDs are read from `GalaxyCluster.meta.external_id` (confirmed against MISP's own bundled ATT&CK galaxy library), with a regex fallback across tag names in case a given MISP/galaxy version omits that field.

Same dual-mode support as OTX/RSS: `SEC7669_CTI_PROVIDER=misp` pulls directly from MISP every orchestrator cycle instead of routing through the file queue via the poller timer.

**Standing up a local MISP instance for dev/test:** see [MISP/misp-docker](https://github.com/MISP/misp-docker) — `docker compose up`, then create a dedicated Auth key as above. If it's sharing a host with a k3s cluster running Traefik as ingress, note that Traefik claims ports 80/443 system-wide via iptables NAT (including loopback-originated traffic) — invisible to `ss`, confirmed only by comparing TLS certificate identity. Use non-standard host ports (e.g. 8080/8443) and set `BASE_URL` (MISP's own env var) to match.

## Configuration

All config comes from environment variables (or a `.env` file in the working directory). See [.env.example](.env.example) for the full list.

Key ones:

| Var | Purpose | Default |
|-----|---------|---------|
| `ATHF_WORKSPACE` | Path to the ATHF workspace | `~/agentic-threat-hunting-framework` |
| `ATHF_BIN` | Path to the `athf` CLI | `<workspace>/.venv/bin/athf` |
| `SEC7669_MAX_DRAFTS_PER_DAY` | Cap on drafts per 24h | `4` |
| `SEC7669_LLM_TIMEOUT_SEC` | Hard timeout on any single `athf` invocation (research call and hypothesis call each get their own budget) | `600` |
| `SEC7669_RESEARCH_ENABLED` | Run `athf research new` (web-grounded) before hypothesis generation | `true` |
| `SEC7669_RESEARCH_DEPTH` | `basic` (~5 min) or `advanced` (~15-20 min) research depth | `basic` |
| `SEC7669_CTI_PROVIDER` | Which CTI source to use (`file`, `otx`, `rss`, or `misp`) | `file` |
| `OTX_API_KEY` | AlienVault OTX API key — required for `cti_provider=otx` and `sec7669 otx-poll` | — |
| `SEC7669_RSS_FEED_URLS` | Comma-separated RSS/Atom feed URLs — no API key needed | 4 verified defaults, see `.env.example` |
| `SEC7669_RSS_MAX_ENTRY_AGE_DAYS` | Ignore RSS entries older than this | `30` |
| `MISP_BASE_URL` / `MISP_API_KEY` | MISP instance + dedicated automation Auth key — required for `cti_provider=misp` and `sec7669 misp-poll` | — |
| `SEC7669_MISP_VERIFY_SSL` | Set false only for self-signed dev/test MISP instances | `true` |
| `SEC7669_QUERY_PROVIDER` | Backend for `sec7669 approve` (`mock` or `splunk`) — see [Query execution](#query-execution-propose-dont-run) | `mock` |
| `SEC7669_MAX_QUERY_TIME_RANGE_DAYS` | Hard ceiling on a proposed query's time range | `7` |
| `SEC7669_MAX_QUERY_LIMIT` | Hard ceiling on a proposed query's result limit | `1000` |
| `SEC7669_SLACK_WEBHOOK_URL` | Slack incoming webhook — posts on every draft creation, no-op if unset | — |

## Development

- Python 3.11+
- Managed with [uv](https://docs.astral.sh/uv/)
- Linted with [ruff](https://docs.astral.sh/ruff/), type-checked with [mypy](https://mypy.readthedocs.io/)
- Tested with pytest — run `uv run pytest` for full suite with coverage

### VS Code

Open the folder in VS Code. Recommended extensions live in `.vscode/extensions.json` and will be suggested on first open. Run/debug configs live in `.vscode/launch.json` — pick "Run orchestrator (dry-run)" from the Run panel.

## Roadmap

- [x] Phase 4a: file-based CTI queue + orchestrator + systemd
- [x] Phase 4b/5: AlienVault OTX CTI provider + poller timer
- [x] Phase 4c: RSS/Atom CTI provider + poller timer, no API key required (4 verified default feeds; CISA's advisory feed tried and excluded — blocks automated requests on every path regardless of User-Agent).
- [~] Phase 4d: MISP CTI provider + poller timer — built and unit-tested against field shapes verified from MISP's own bundled test fixtures (not guessed), but not yet live-verified against a real instance the way RSS was. A local misp-docker instance exists in this environment for exactly that purpose; live verification is the next step once a dedicated automation Auth key is available.
- [x] Phase 5b: notification hooks — Slack webhook on draft creation (`SEC7669_SLACK_WEBHOOK_URL`, no-op if unset); email still open
- [x] Phase 6a: web-search grounding via TAVILY (`athf research new` wired into the orchestrator, mandatory when enabled — a research failure aborts the cycle rather than falling back to ungrounded) + model swap to qwen2.5:14b
- [x] Phase 6b: eval harness (`athf eval` — known-answer fixtures replacing manual spot checks; found ungrounded generation scores ~30% on MITRE technique recall, which is why research grounding is mandatory-when-enabled rather than a soft fallback)
- [x] Phase 6c: ATT&CK STIX grounding in research prompts (`athf attack lookup` fed into HuntResearcherAgent's tradecraft/telemetry/synthesis skills instead of asking the model to recall technique metadata — closed cold-recall's ~30% accuracy to 100% on the same model, per `athf eval --grounded`)
- [~] Phase 7a: propose/approve query execution bridge (`sec7669 propose` / `pending` / `approve` / `reject`) — guardrail enforcement and the approval flow are built and tested; the `splunk` backend is unvalidated against a real instance since none exists in this environment yet. `mock` remains the default until it does. Query *authoring* is still human-only — no LLM drafts or approves a query.
- [ ] Phase 7b: Level 3 execution — MCP connector for CrowdStrike (or whichever EDR/SIEM materializes first) so Observe queries can eventually be proposed automatically, still gated by the approval step above

## License

MIT
