# hecate-runner

Autonomous hunt draft orchestrator for the Agentic Threat Hunting Framework (Hecate), whose workspace lives in [Hecate-Core](https://github.com/BrizoSec/Hecate-Core).

`hecate-runner` sits on top of Hecate and turns it into a persistent, 24/7 hunting loop:

1. Pulls fresh CTI from a configured source (file queue, AlienVault OTX, RSS/Atom feeds, or MISP)
2. Calls the Hecate `hypothesis-generator` agent (which uses a local Ollama-served LLM)
3. Writes structured draft hunt records into your Hecate workspace
4. Never auto-executes queries — a human proposes a bounded query and separately approves running it (see [Query execution](#query-execution-propose-dont-run) below); nothing runs unattended

Runs as a systemd timer on a hunting host, or manually via `hecate-runner run`.

## Design principles

- **Read-context, not hard dependency on Hecate.** `hecate-runner` shells out to the `hecate-agent` CLI; it does not import Hecate as a library. Hecate and `hecate-runner` version independently.
- **Human-in-the-loop by default.** Every generated hunt is `status: planning` with a "review required" banner. Nothing auto-executes.
- **Guardrails first.** Daily draft quotas, hard timeouts on LLM calls, structured logs, per-run state persistence.
- **Testable in isolation.** No network, no LLM, no Hecate required to run unit tests locally.

## Architecture

```
  CTI provider: file | otx | rss | misp | multi
  (file reads cti_queue/next.txt; the rest poll their source directly)
                                |
                                v
+------------------+     +---------------+     +-----------------------+     +----------------+
| systemd timer    | --> | hecate-runner | --> | hecate-agent research new     | --> | Ollama (local) |
| hourly + 2m boot |     | run           |     | (5-skill, web-search  |     | qwen2.5:14b    |
+------------------+     +---------------+     |  grounded via Tavily) |     +----------------+
                                |              +-----------------------+
                                |                        |
                                |                 research_id (R-XXXX)
                                v                        |
                     +---------------------------+       |
                     | hecate hypothesis-generator | <-----+
                     +---------------------------+
                                |
                                v
                     hunts/YYYY/QN/H-XXXX.md   (spawned_from: R-XXXX)
                     research/R-XXXX.md
                     logs/orchestrator.log
                     .orchestrator_state.json
```

Research grounding runs before hypothesis generation on every cycle by default (`HECATE_RUNNER_RESEARCH_ENABLED=true`). **A research failure aborts the cycle** (refunds the quota, leaves the CTI queued for retry) rather than falling back to an ungrounded hypothesis: `hecate-agent eval` measured ungrounded generation at ~30% accuracy on known-answer MITRE technique fixtures, so an ungrounded draft isn't a degraded-but-useful fallback, it's an unreliable one. Set `HECATE_RUNNER_RESEARCH_ENABLED=false` to explicitly opt out of research and always generate ungrounded (e.g. for offline testing) — that's a deliberate choice, different from a research call failing mid-cycle.

One exception is automatic: when the CTI is a bare indicator dump with a parseable inventory (a ThreatFox-style feed event), the draft is built deterministically from the indicator list with no LLM call, and research is skipped along with it. There is no behavior described for research to ground, and running it anyway produced documents whose every section said so.

## Grounding

A generated hunt is only worth acting on if its claims trace back to evidence. That is enforced at three points, not one:

**Intake** decides what is worth hunting at all — the galaxy, ATT&CK-technique and org filters above, so a draft starts from a curated event rather than a feed dump.

**Generation** carries the evidence forward. A curated MISP event's indicator *values* reach the model (it previously saw only type counts — "url (9)" — and so wrote hunts that could have been written without reading the CTI). The source's own technique list is merged into the draft rather than replaced by the two or three the hypothesis reasoned about, and sub-technique precision is preserved, since `T1059.003` is Windows-only where bare `T1059` spans five platforms. Research findings citing a CVE that appears in none of the retrieved sources are dropped before they can reach a hunt. Revoked ATT&CK IDs resolve to their replacements instead of vanishing — CTI keeps emitting `T1574.002` years after it was folded into `T1574.001`.

**Audit** re-reads the finished draft and classifies every claim it can check, writing the result into the hunt's own Grounding section:

| Status | Meaning |
|--------|---------|
| `asserted` | The source CTI contains this verbatim — primary evidence |
| `corroborated` | Absent from the CTI, present in the research document. Research is generated, so this is a claim *about* evidence, not evidence |
| `derived` | In no source text but legitimately inferable — a technique the hypothesis reasoned to |
| `unsupported` | Specific, checkable, and absent from every source — the fabrication class, including ATT&CK IDs that do not exist |

**Expect RSS-sourced hunts to score lower, by design.** MISP and OTX items carry structured indicators; RSS entries do not — measured across 30 live entries, feed summaries contained no IPs, hashes or domains at all. Those indicators live in the linked article, and fetching it is deliberately not done: it would mean making outbound requests to arbitrary third-party URLs. So an RSS hunt derives its data sources from ATT&CK techniques alone and shows fewer `asserted` claims. That is the source being poorer in checkable facts, not the audit misfiring.

Evidence is ranked because it is not equally trustworthy. Treating a research document as proof lets a fabrication launder itself: a CVE invented during research and written into `R-0611` came back as "asserted" in any hunt built from that research, which is circular. The CTI exists independently of this pipeline; the research does not.

What gets checked: ATT&CK technique IDs (including whether they exist in the current matrix), CVEs, indicators inside generated Sigma rules, and named entities in prose — actor designators like `APT41`, `<Name> backdoor`-style collocations, and CamelCase families like `PureRAT`. Entity checking is precision-first: "adversaries deploy a backdoor" names nothing and is ignored, because a section full of false alarms is one a reviewer learns to skip.

The audit reports rather than blocks, because a hunt that generalises beyond its CTI is doing its job. What it catches is the opposite: an assertion specific enough to *read* as evidence that nothing supports — a fabricated CVE, or a Sigma rule matching a C2 domain no intelligence mentions. Only traceable shapes are examined: a rule matching `\powershell.exe` is behaviour, while one matching `203.0.113.99` is a claim.

## Query execution: propose, don't run

Two separate things live here, and the distinction is the whole design: **detection logic is now drafted automatically; execution is still human-initiated and always will be.**

### Sigma drafting (automatic, before review)

After the hypothesis lands, the orchestrator runs `hecate-agent agent run sigma-generator` and writes one Sigma rule per applicable log source into `$HECATE_WORKSPACE/queries/H-XXXX/`, embedding them in the draft's CHECK section. An operator therefore reviews a hunt that already has candidate detection logic rather than an empty query block.

Sigma rather than SPL or KQL because this program has no committed query platform. `sigma convert -t <backend>` retargets a rule to Splunk, Elastic, CrowdStrike or Defender later, so drafting now commits to nothing — and correspondingly, **a Sigma rule cannot be executed by the propose/approve path below.** It is review material, not a runnable query.

Which log sources are "applicable" is derived deterministically from the hunt's ATT&CK techniques and the indicator types the CTI actually carried, not asked of the model — a backdoor whose event carries nine C2 URLs gets network and DNS rules whether or not the prose mentioned them. The model returns JSON and this code renders the YAML, so a malformed rule is impossible by construction; rules whose `condition` names an undefined selection are rejected rather than emitted, because pySigma would only reject them much later, after the hunt had been reviewed around them.

Generation failing leaves the draft standing with its placeholder query section — the CTI has already been consumed and the quota already spent by that point, so losing the hunt over it would be the wrong trade. Disable with `HECATE_RUNNER_SIGMA_GENERATION_ENABLED=false`.

### Re-auditing hunts already on disk

The grounding audit runs while a hunt is drafted, so a hunt written before a
given version of it was graded by an older one. `hecate-runner audit` re-grades
finished hunts:

```
hecate-runner audit                 # every hunt on disk
hecate-runner audit H-0616          # one
hecate-runner audit --update        # rewrite each hunt's Grounding section
hecate-runner audit --strict        # exit 1 if any claim traces to no source
hecate-runner audit --check-attack  # also validate technique IDs against ATT&CK
```

`--check-attack` is opt-in because it costs one `hecate-agent` subprocess per technique.
A hunt whose CTI cannot be recovered is reported as such rather than scored —
every claim would grade unsupported for want of evidence, which reads like a
fabrication finding and is not one.

### Query execution (human-initiated, unchanged)

A bounded bridge for the query a *human* writes, so running it doesn't mean dropping to a raw SIEM CLI:

```
hecate-runner propose H-0016 --query '...' --data-source splunk \
  --time-range-days 7 --limit 100 --justification '...'
    |
    v   guardrails checked (time range, result limit, non-empty) -- reject outright if violated
.pending_queries/H-0016.json
    |
    v   hecate-runner pending          (see what's staged)
    v   hecate-runner approve H-0016   (re-checks guardrails, prompts to confirm, then executes)
    v   hecate-runner reject H-0016    (discard without running)
    |
    v
QueryProvider.execute()  -->  mock (default) | splunk (shells out to `hecate-agent splunk search`)
```

Guardrails (`HECATE_RUNNER_MAX_QUERY_TIME_RANGE_DAYS`, default 7; `HECATE_RUNNER_MAX_QUERY_LIMIT`, default 1000) mirror Hecate's own `AGENTS.md` Query Guardrails section, and are re-checked at `approve` time, not just at `propose` time — if the staged file was hand-edited or the ceilings changed in between, `approve` refuses rather than trusting the earlier check.

**`HECATE_RUNNER_QUERY_PROVIDER=mock` is the default and, as of this writing, the only backend that's actually been run.** There is no live Splunk instance in this environment to validate `SplunkQueryProvider` against yet — it shells out to `hecate-agent splunk search` (same subprocess pattern as `HecateClient`) and is unit-tested against a fake `hecate-agent` binary, but nothing here has touched a real SIEM. Treat it as ready-to-wire, not proven, until it has. Switching from mock to a real backend is meant to be a config change (`HECATE_RUNNER_QUERY_PROVIDER=splunk` + `SPLUNK_HOST`/`SPLUNK_TOKEN` in the Hecate workspace `.env`), not new code — `hecate-runner doctor` checks for both when the provider is set to `splunk`.

## Quickstart (local dev)

```bash
# Clone
git clone https://github.com/BrizoSec/Hecate-Runner.git
cd Hecate-Runner

# uv installs Python + venv + deps in one shot
uv sync --dev

# Copy env template and edit
cp .env.example .env
# edit .env to point HECATE_WORKSPACE at wherever your Hecate workspace lives

# Run tests
uv run pytest

# Preview an orchestrator cycle (uses your local Hecate workspace)
uv run hecate-runner run --dry-run

# Real run (invokes hecate hypothesis-generator + writes a draft hunt)
uv run hecate-runner run
```

## Deploy to k3s-core

```bash
# Push repo
git push origin main

# On k3s-core
cd ~
git clone https://github.com/BrizoSec/Hecate-Runner.git
cd Hecate-Runner

# Install with uv (recommended) or pip
uv sync

# Env
cp .env.example .env
$EDITOR .env

# Install systemd units
sudo ./scripts/install-systemd.sh

# Prime a CTI blurb and force a run
echo "APT actor X observed using T1053.005 scheduled tasks" > $HECATE_WORKSPACE/cti_queue/next.txt
sudo systemctl start hecate-runner-orchestrator.service

# Enable persistent scheduling
sudo systemctl enable --now hecate-runner-orchestrator.timer
sudo systemctl list-timers hecate-runner-orchestrator.timer
```

### Optional: AlienVault OTX CTI provider

Instead of (or alongside) hand-dropping CTI into `cti_queue/next.txt`, `hecate-runner` can pull it from [AlienVault OTX](https://otx.alienvault.com) pulses you're subscribed to.

```bash
# Get a free-tier API key at https://otx.alienvault.com/settings, then:
echo 'OTX_API_KEY=your-key-here' >> .env

# One-off: route the next high-signal pulse into the CTI queue
uv run hecate-runner otx-poll
```

The poller filters for high-signal pulses (TLP white/green, has a MITRE ATT&CK mapping, not older than `HECATE_RUNNER_OTX_MAX_PULSE_AGE_DAYS`) and routes the oldest unrouted one into `cti_queue/next.txt`, so the existing orchestrator picks it up on its normal schedule — OTX polling frequency and hypothesis-generation frequency stay decoupled. A cursor file (`.otx_cursor_state.json` in the Hecate workspace) tracks the last pulse routed so nothing is re-ingested.

You can also skip the file queue entirely and have the orchestrator pull directly from OTX every cycle by setting `HECATE_RUNNER_CTI_PROVIDER=otx`, or by including `otx` in `HECATE_RUNNER_CTI_MULTI_PROVIDERS` under `multi` — which is how this deployment runs, and why there are no poller timers to install.

### RSS/Atom CTI provider (no API key required)

Unlike OTX, this needs no signup or credential — it polls a configured list of security research blog feeds directly.

```bash
# Works out of the box with four verified defaults (The DFIR Report, Talos,
# Unit42, Microsoft Security Blog) -- override with your own list:
# HECATE_RUNNER_RSS_FEED_URLS=https://a.example.com/feed/,https://b.example.com/feed/

# One-off: route the oldest unrouted entry across all configured feeds
uv run hecate-runner rss-poll
```

Unlike OTX's crowdsourced pulse firehose (filtered by TLP + ATT&CK mapping), the "high signal" filter here is mostly the curation itself — every URL in the list is a feed you picked, not an open subscription. Entries are only filtered by age (`HECATE_RUNNER_RSS_MAX_ENTRY_AGE_DAYS`, default 30) and dedup (`.rss_cursor_state.json`, one cursor per feed URL). A MITRE technique ID is still extracted from the title/summary when present and included as metadata, but its absence doesn't exclude an entry.

One feed being down or blocking automated requests doesn't stop entries from the others — CISA's advisory feed was tried while building this and excluded from the defaults for exactly that reason (403s on every path tried, with or without a browser-like User-Agent).

Same dual-mode support as OTX: `HECATE_RUNNER_CTI_PROVIDER=rss` pulls directly from the configured feeds every orchestrator cycle instead of routing through the file queue via a separate `rss-poll` run.

### MISP CTI provider

```bash
# Point at your MISP instance and a dedicated automation key (Administration
# -> List Auth Keys -> Add authentication key in the MISP UI -- not a
# personal user's key):
# MISP_BASE_URL=https://localhost:8443
# MISP_API_KEY=...
# HECATE_RUNNER_MISP_VERIFY_SSL=false   # only for self-signed dev/test instances

# One-off: route the oldest unrouted published event
uv run hecate-runner misp-poll
```

Polls `POST /events/restSearch` for `published` events, incrementally synced via a `timestamp` cursor (`.misp_cursor_state.json`) the same way OTX's `modified_since` works. Pages are fetched metadata-only — attributes are the bulk of the payload and selection doesn't need them — and only the chosen event is re-fetched in full. TLP is tag-based rather than a dedicated field: an explicit `tlp:red`/`tlp:amber` tag excludes an event, while no TLP tag at all defaults to included, matching how `OtxProvider` treats a missing TLP field. ATT&CK technique IDs are read from `GalaxyCluster.meta.external_id` (confirmed against MISP's own bundled galaxy library), with a regex fallback across tag names.

Same dual-mode support as OTX/RSS: `HECATE_RUNNER_CTI_PROVIDER=misp` pulls directly from MISP every orchestrator cycle instead of routing through the file queue via a separate `misp-poll` run.

**Three knobs decide what actually gets routed, and they work together.** `HECATE_RUNNER_MISP_REQUIRE_GALAXY` (default on) skips events carrying no galaxy cluster. Galaxy presence is the cleanest separator between a curated, analyst-written event and a bulk indicator dump — on the reference instance every curated event carried clusters and averaged ~25 attributes, while every ThreatFox event carried none and averaged ~734. `HECATE_RUNNER_MISP_BACKFILL` drops the 30-day freshness floor so the archive can be walked oldest-first, for an instance whose curated events predate that window; seed the cursor file to choose where the walk starts. The cursor advances every poll and converges back into normal freshness-floored behavior once it reaches the present — turn backfill off then, since with it on a lost cursor restarts from the beginning of the archive.

`HECATE_RUNNER_MISP_ORG_ALLOWLIST` covers what galaxy presence cannot. Galaxy separates curated events from dumps, but not a *high-volume curated feed* from the handful of analyst-written events beside it: on the reference instance one org accounts for 856 of 872 routable events, so at any sane `MAX_DRAFTS_PER_DAY` the other 16 sit behind a year of queue. Listing the orgs you actually read surfaces those first. It restricts rather than ranks — skipped events are walked past permanently, since the cursor advances over them — so widen the list before a backfill, or reseed the cursor to revisit what it stepped over.

Used alone each is a trap: requiring galaxies on a dump-heavy recent window starves the poll, and backfilling without the filter simply works through the dumps too.

**Standing up a local MISP instance for dev/test:** see [MISP/misp-docker](https://github.com/MISP/misp-docker) — `docker compose up`, then create a dedicated Auth key as above. On a host already running an ingress controller, bind non-standard ports (e.g. 8080/8443) and set `BASE_URL` to match: Traefik claims 80/443 system-wide via iptables NAT including loopback, which `ss` does not show.

## Configuration

All config comes from environment variables (or a `.env` file in the working directory). See [.env.example](.env.example) for the full list.

**Two `.env` files, different jobs.** This repo's `.env` configures the orchestrator. The Hecate workspace has its own, which `hecate-agent` loads itself — that is where `TAVILY_API_KEY`, `HECATE_LLM_PROVIDER` and `HECATE_LLM_MODEL` belong, so manual `hecate-agent` runs and orchestrated ones use the same model. `hecate-runner` passes only `HECATE_WORKSPACE` through by default. No variable appears in both `.env.example` files, so there is never a question of which copy wins — the settings still exist to override `HECATE_LLM_*` from here, but they are deliberately absent from the example, since setting them splits manual and orchestrated runs onto different models.

Key ones:

| Var | Purpose | Default |
|-----|---------|---------|
| `HECATE_WORKSPACE` | Path to the Hecate workspace (Hecate-Core) | `~/betas/Hecate-Core` |
| `HECATE_BIN` | Path to the `hecate-agent` CLI | `<workspace>/.venv/bin/hecate-agent` |
| `HECATE_RUNNER_MAX_DRAFTS_PER_DAY` | Cap on drafts per 24h | `4` |
| `HECATE_RUNNER_MAX_RESEARCH_RUNS_PER_DAY` | Cap on web-searching research runs per UTC day; not refunded on a failed cycle, so retries can't drain the Tavily quota | `7` |
| `HECATE_RUNNER_LLM_TIMEOUT_SEC` | Hard timeout on any single `hecate-agent` invocation (research call and hypothesis call each get their own budget) | `1500` |
| `HECATE_RUNNER_RESEARCH_ENABLED` | Run `hecate-agent research new` (web-grounded) before hypothesis generation | `true` |
| `HECATE_RUNNER_RESEARCH_DEPTH` | `basic` (~5 min) or `advanced` (~15-20 min) research depth | `advanced` |
| `HECATE_RUNNER_CTI_PROVIDER` | Which CTI source to use (`file`, `otx`, `rss`, `misp`, or `multi`) | `file` |
| `HECATE_RUNNER_CTI_MULTI_PROVIDERS` | Sub-providers to rotate through when `CTI_PROVIDER=multi` | `rss,otx,misp` |
| `OTX_API_KEY` | AlienVault OTX API key — required for `cti_provider=otx` and `hecate-runner otx-poll` | — |
| `HECATE_RUNNER_RSS_FEED_URLS` | Comma-separated RSS/Atom feed URLs — no API key needed | 4 verified defaults, see `.env.example` |
| `HECATE_RUNNER_RSS_MAX_ENTRY_AGE_DAYS` | Ignore RSS entries older than this | `30` |
| `MISP_BASE_URL` / `MISP_API_KEY` | MISP instance + dedicated automation Auth key — required for `cti_provider=misp` and `hecate-runner misp-poll` | — |
| `HECATE_RUNNER_MISP_VERIFY_SSL` | Set false only for self-signed dev/test MISP instances | `true` |
| `HECATE_RUNNER_MISP_REQUIRE_GALAXY` | Only route MISP events carrying a galaxy cluster — keeps bulk indicator dumps (ThreatFox-style) out, since they describe no behavior | `true` |
| `HECATE_RUNNER_LOG_MAX_BYTES` | Rotate the orchestrator log past this size (copy-and-truncate, since systemd co-writes the file) | `5242880` |
| `HECATE_RUNNER_LOG_BACKUP_COUNT` | Rotated logs to keep | `5` |
| `HECATE_RUNNER_SIGMA_GENERATION_ENABLED` | Draft Sigma rules per applicable log source before operator review | `true` |
| `HECATE_RUNNER_SIGMA_TIMEOUT_SEC` | Timeout for the Sigma drafting subprocess (one LLM call per log source) | `1800` |
| `HECATE_RUNNER_MISP_REQUIRE_ATTACK_TECHNIQUE` | Only route MISP events that map to an ATT&CK technique — stricter than the galaxy check, which any cluster satisfies | `false` |
| `HECATE_RUNNER_MISP_ORG_ALLOWLIST` | Comma-separated MISP org names; only these are routable. Empty = every org. Keeps one high-volume feed from burying the rest | _(empty)_ |
| `HECATE_RUNNER_MISP_BACKFILL` | Ignore the freshness floor and walk the MISP archive oldest-first. Reset the cursor file to start from the beginning | `false` |
| `HECATE_RUNNER_MISP_MAX_PAGES_PER_POLL` | How many event pages one poll may walk before giving up (pages are fetched metadata-only) | `25` |
| `HECATE_RUNNER_QUERY_PROVIDER` | Backend for `hecate-runner approve` (`mock` or `splunk`) — see [Query execution](#query-execution-propose-dont-run) | `mock` |
| `HECATE_RUNNER_MAX_QUERY_TIME_RANGE_DAYS` | Hard ceiling on a proposed query's time range | `7` |
| `HECATE_RUNNER_MAX_QUERY_LIMIT` | Hard ceiling on a proposed query's result limit | `1000` |
| `HECATE_RUNNER_SLACK_WEBHOOK_URL` | Slack incoming webhook — posts on every draft creation, no-op if unset | — |

## Development

- Python 3.11+
- Managed with [uv](https://docs.astral.sh/uv/)
- Linted with [ruff](https://docs.astral.sh/ruff/), type-checked with [mypy](https://mypy.readthedocs.io/)
- Tested with pytest — run `uv run pytest` for full suite with coverage

### VS Code

Open the folder in VS Code. Recommended extensions live in `.vscode/extensions.json` and will be suggested on first open. Run/debug configs live in `.vscode/launch.json` — pick "Run orchestrator (dry-run)" from the Run panel.

## Roadmap

Done:

- **4a** file-based CTI queue, orchestrator, systemd timer
- **4b/5** AlienVault OTX provider
- **4c** RSS/Atom provider, no API key needed (4 verified default feeds; CISA's advisory feed was tried and excluded — it blocks automated requests on every path regardless of User-Agent)
- **4d** MISP provider, live-verified against a real instance, with galaxy filtering and archive backfill
- **5b** Slack webhook on draft creation (email still open)
- **6a** web-search grounding via Tavily, mandatory when enabled — a research failure aborts the cycle rather than falling back to ungrounded
- **6b** eval harness (`hecate-agent eval`), which is what measured ungrounded generation at ~30% MITRE technique recall and made grounding mandatory rather than a soft fallback
- **6c** ATT&CK STIX grounding fed into the research skills instead of asking the model to recall technique metadata — closed that ~30% to 100% on the same model

In progress:

- **7a** propose/approve query bridge — guardrails and the approval flow are built and tested; the `splunk` backend is written but has never touched a real SIEM, so `mock` stays the default. Query *authoring* remains human-only.
- **7b** Level 3 execution — an MCP connector for whichever EDR/SIEM materializes first, so Observe queries can eventually be proposed automatically, still gated by the approval step above

## License

MIT
