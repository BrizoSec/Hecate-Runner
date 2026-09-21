# Hecate: application flow and agentic process

How the two repositories fit together, what one orchestrator cycle actually
does, and where the model is allowed to decide things.

Written 2026-09-21 against the live deployment.

---

## The two repositories

**Hecate-Core** (`hecate_agent`) is the agent library and CLI. It owns the LLM
agents, the ATT&CK matrix, the hunt document format, Sigma generation and the
research corpus. It knows nothing about scheduling or intelligence feeds.

**Hecate-Runner** (`hecate_runner`) is the autonomous driver. It polls threat
intelligence, decides what is worth hunting, calls into Core, writes drafts and
enforces quotas and guardrails.

They are siblings on disk, and the Runner depends on Core as an editable path
dependency with all extras: `hecate-agent[all]`.

**One thing to understand before anything else.** The Runner calls Core
**in-process**, importing `hecate_agent.api` directly. It does not shell out to
the `hecate-agent` CLI, even though `HECATE_BIN` still points at it. This means
Core's optional capabilities -- ATT&CK STIX data, scikit-learn, Tavily, pySigma
-- must be installed in the *Runner's* environment. Installing them in Core's
virtualenv has no effect on what the pipeline can do.

```
  CTI feeds                Hecate-Runner                    Hecate-Core
 ┌──────────┐            ┌───────────────┐              ┌────────────────┐
 │ RSS      │            │ orchestrator  │  in-process  │ hunt_researcher│
 │ OTX      │──poll────▶ │  triage       │─────────────▶│ hypothesis_gen │
 │ MISP     │            │  quota        │  api.py      │ sigma_generator│
 │ file     │            │  grounding    │◀─────────────│ attack_matrix  │
 └──────────┘            └───────┬───────┘              └────────────────┘
                                 │ writes
                                 ▼
                    hunts/YYYY/Qn/H-XXXX.md
                    research/R-XXXX.md
                    queries/H-XXXX/*.yml
```

---

## Intake: choosing what to hunt

Six providers implement one interface (`next_item`, `acknowledge`): `rss`,
`otx`, `misp`, `cisa_kev`, `abuse_ch` and `file`. `multi` composes any subset
of them behind the same interface, so the orchestrator never knows it is
talking to more than one source. The deployment currently runs
`multi` over `rss, otx, misp`; `hecate-runner sources` manages the set.

**Round-robin, persisted.** `MultiProvider` keeps a cursor so a high-volume
source (ten RSS feeds) cannot crowd out a slow one (a MISP instance with few
new events). The rotation decides tie-break order only; a source is skipped in
a cycle only if it genuinely has nothing new.

The rotation advances on **acknowledge**, not on pick. Every sub-provider
already moves its own cursor that way, and it means an unacknowledged item --
a dry run, or a cycle that dies mid-draft -- is re-offered from the same
source rather than silently consuming a slot.

**Triage parks rather than discards.** `cti_triage.triage()` parks conference
announcements, vendor commentary and similar non-actionable items into
`cti_queue/parked/` with a reason attached. `hecate-runner parked` lists them
and `parked restore` puts one back. Nothing is ever thrown away.

**The narrative gate.** `has_narrative()` asks whether an item carries anything
beyond a bare indicator dump and a title: a human-written summary or
description, or an explicit ATT&CK technique list. This one answer gates two
later decisions, and is the single most consequential branch in the cycle.

---

## One orchestrator cycle

`hecate-runner run` executes exactly one cycle. It never raises; it always
returns a `RunResult` with an outcome.

1. **Prune parked items** older than the configured age.
2. **Pick the next actionable item.** Skipped items are acknowledged so the
   cursor moves past them. Walking past an item is not a draft and does not
   cost quota.
3. **Reserve quota.** `max_drafts_per_day` is checked and reserved *before* any
   model call. Exceeding it leaves the intelligence queued for the next cycle.
4. **Branch on the narrative gate.**
   - *No narrative but a parseable indicator inventory* → a deterministic
     **sweep draft**, built from the indicators alone. No LLM call at all, so
     there is no opportunity for the model to invent a delivery vector.
   - *Otherwise* → the LLM path below.
5. **Research** (`generate_research`), unless disabled. Produces `R-XXXX.md`
   and grounds the hypothesis that follows.
6. **Hypothesis generation** (`generate_hypothesis`), constrained by whether
   narrative was present. An empty hypothesis refunds the quota and leaves the
   intelligence queued.
7. **Resolve techniques against the live ATT&CK matrix.** Tactics, platforms
   and data sources are derived deterministically from the resolved techniques,
   merged with what the source asserted. Technique IDs that do not resolve are
   dropped so they cannot reach the frontmatter.
8. **Allocate a hunt ID and write the draft** under a lock. The ID is burned at
   allocation, so a crash leaves a gap rather than a collision.
9. **Generate Sigma rules** (`generate_sigma`), one per applicable log source.
10. **Audit grounding**, render the section, notify Slack, acknowledge the
    item.

---

## Where the model decides, and where it does not

This is the heart of the design: **the model proposes, deterministic code
disposes.**

| Decision | Made by |
|---|---|
| Which source to poll | Round-robin cursor |
| Whether an item is actionable | Triage rules and the narrative gate |
| Applicable log sources | Technique→logsource map |
| Data sources / telemetry | Technique and indicator maps, then platform-filtered |
| Tactics and platforms | Live ATT&CK matrix lookup |
| Hunt ID and file location | Counter under a lock |
| **The hypothesis** | **LLM** |
| **Research prose** | **LLM** |
| **Sigma detection logic** | **LLM**, then validated |
| Whether a rule survives | Validators, then pySigma |
| Grounding classification | Regex extraction and source matching |

Every model output passes through a deterministic check before it reaches a
draft. A generated Sigma rule is rejected if it matches on scaffolding values,
reproduces a supplied indicator only as a fragment, excludes the hypothesis's
own attack path, or puts a hostname in an address field. Empty filter blocks
are repaired rather than rejected. A rejected rule is not retried, so the draft
keeps a placeholder query section instead of a wrong rule.

---

## The research agent: five skills

`HuntResearcherAgent` runs five skills in sequence:

1. **System research** -- how the targeted technology works. Web search.
2. **Adversary tradecraft** -- how it is abused. Web search.
3. **Telemetry mapping** -- what data sources would show it.
4. **Related work** -- similar past hunts, via TF-IDF similarity over the
   existing corpus.
5. **Synthesis** -- assembles the research document.

Skills 1 and 2 call Tavily when the narrative gate allowed web search. Skill 4
needs scikit-learn. Both degrade rather than fail, and both now say so in the
log when they do -- a silent degradation here produces a document that looks
finished and is not.

---

## The hunt document

Drafts follow the LEARN / OBSERVE / CHECK / KEEP structure, land in
`hunts/YYYY/Qn/H-XXXX.md`, and always start at `status: planning` with a
banner telling the reader not to execute anything yet.

Each draft carries a **grounding audit**: every checkable claim -- techniques,
CVEs, indicators, actor names -- classified as asserted by the source,
research-only, inferred, or unsupported. Unsupported claims are listed in a
warning block at the top. `hecate-runner audit` re-grades drafts on disk at any
time.

---

## The query loop: human in the loop by design

Drafting a hunt never runs a query. Execution is a separate, deliberately
gated flow:

```
propose ──▶ guardrails ──▶ pending ──▶ approve ──▶ execute
                │                          │
                └── rejected outright       └── reject: discard
```

`validate_guardrails` rejects a query outright for an empty query body, a
non-positive or over-long time range (7 days by default), a non-positive or
over-large row limit, or a missing data source. A query that passes is *staged*,
not run. `hecate-runner approve` is a separate human action.

The deployment runs `query_provider=mock`, so approval cannot touch a real
system until a Splunk backend is configured.

---

## Scheduling and safety rails

A systemd timer (`hecate-runner-orchestrator.timer`) fires the cycle hourly.

Four independent limits bound autonomous behaviour:

- **Daily draft quota**, reserved before any model call and refunded on failure.
- **Skip limit** of 5 per cycle, so a run cannot spin forever walking past
  items that have nothing to hunt.
- **Consecutive failure tracking** in the orchestrator state.
- **Query guardrails**, which apply regardless of who proposes the query.

Run `hecate-runner doctor` before trusting a deployment. It verifies paths,
credentials, and -- importantly -- that the optional capabilities are
importable *in the Runner's interpreter* and that ATT&CK STIX data is actually
present. A credential without its client library is a failed check, because
that combination is precisely how grounding sat silently switched off.
