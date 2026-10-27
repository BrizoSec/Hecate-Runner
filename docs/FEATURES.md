# Hecate Platform Feature Guide

A complete reference of capabilities across the Hecate threat hunting and detection engineering platform.

---

## 1. Feature Matrix Overview

| Subsystem | Feature | Capability Description | Primary Implementation |
|---|---|---|---|
| **CTI Intake** | 20+ Feed Ingestors | Automated polling of RSS, OTX, MISP, KEV, ThreatFox, AnyRun, Censys, Certstream, Cloud Threat, DFIR Report, First.org, GitHub PoC, MalwareBazaar, MSRC, OpenCTI, Shadowserver, VulnCheck, VX-Underground. | [`hecate_runner.cti`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/cti) |
| **CTI Intake** | Deduplication & Cursoring | Prevents redundant drafting using SHA-256 fingerprinting, persistent cursors, and feed-specific state trackers. | [`hecate_runner.orchestrator`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/orchestrator.py) |
| **Scheduling** | Dual-Track Priority Queue | Segregates fast IoC sweeps from complex narrative threat research with independent cooldowns and quotas. | [`hecate_runner.config`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/config.py) |
| **Generation** | Deterministic Sweep Engine | Instantaneous, zero-token, zero-cost Sigma rule generation for pure IoC feeds (hashes, IPs, domains). | [`hecate_runner.indicator_sweep`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/indicator_sweep.py) |
| **Generation** | LOCK Pattern Hunting | Structures threat investigations into four disciplined stages: Learn → Observe → Check → Keep. | [`hecate_agent.core.hunt_parser`](file:///home/chemch/betas/Hecate-Core/hecate_agent/core/hunt_parser.py) |
| **Generation** | Agentic Threat Research | Autonomous deep technical research extracting behavior, telemetry footprints, and attack flow from CTI. | [`hecate_agent.agents.hunt_researcher`](file:///home/chemch/betas/Hecate-Core/hecate_agent/agents/hunt_researcher.py) |
| **Quality** | Grounding Claim Audit | Verifies extracted artifacts verbatim against source intelligence, explicitly distinguishing observed facts from model inferences. | [`hecate_agent.core.grounding`](file:///home/chemch/betas/Hecate-Core/hecate_agent/core/grounding.py) |
| **Quality** | Dual-Use Tool Protection | Heuristically filters administrative tools (`whoami.exe`, `net.exe`, `curl`) lacking malicious context to suppress noisy rules. | [`hecate_agent.core.command_rules`](file:///home/chemch/betas/Hecate-Core/hecate_agent/core/command_rules.py) |
| **Detection** | Sigma Rule Synthesis | Synthesizes standard Sigma detection rules with precise logsource categorization and selection filters. | [`hecate_agent.agents.llm.sigma_generator`](file:///home/chemch/betas/Hecate-Core/hecate_agent/agents/llm/sigma_generator.py) |
| **Detection** | Reviewer Self-Remediation | AST validation and automated remediation feedback loop that corrects logsource and field discrepancies in real time. | [`hecate_runner.rule_tuner`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/rule_tuner.py) |
| **Validation** | Purple Team Emulation | Executes synthetic attack replay (Sysmon, WAF, Linux auditd, Zeek) using Atomic Red Team mappings to evaluate true positives. | [`hecate_runner.purple_team`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/purple_team.py) |
| **Transpilation** | Multi-Backend Export | Compiles Sigma rules to 5+ production SIEM/EDR query languages via pySigma (Splunk, Sentinel, CrowdStrike, Elastic, QRadar). | [`hecate_agent.core.sigma_transpiler`](file:///home/chemch/betas/Hecate-Core/hecate_agent/core/sigma_transpiler.py) |
| **Lifecycle** | Promotion Gate Enforcement | Validates formatting, grounding confidence, credential safety, and tests against promotion policies before merge. | [`promotion_gate.py`](file:///home/chemch/betas/Hecate-Workspace/scripts/promotion_gate.py) |
| **Operations** | Terminal Monitor TUI | Live terminal dashboard displaying active cycles, queue depths, quota usage, and decision trails. | [`hecate_agent.commands.monitor`](file:///home/chemch/betas/Hecate-Core/hecate_agent/commands/monitor.py) |
| **Operations** | Interactive Slack Bot | Real-time Slack notifications with rich Block Kit cards, interactive review buttons, and slash command controls. | [`hecate_runner.slack_bot`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/slack_bot.py) |

---

## 2. In-Depth Subsystem Capabilities

### 2.1 CTI Ingestion & Multi-Feed Triage
Hecate integrates with more than 20 external intelligence sources without requiring third-party aggregation middleware:
- **Commercial & Community Feeds:** AlienVault OTX, MISP instances, OpenCTI, and CISA Known Exploited Vulnerabilities (KEV).
- **Specialized Threat Trackers:** Abuse.ch (ThreatFox, URLhaus), MalwareBazaar, VX-Underground, Shadowserver, VulnCheck, DFIR Report, and MSRC security advisories.
- **Infrastructure & C2 Telemetry:** Censys C2 scans, Certstream TLS certificate transparency logs, and Cloud Threat monitoring.
- **Local Feeds:** Manual file drops via `cti_queue/` for instant ad-hoc investigation.

### 2.2 Dual-Track Queue & Deterministic Bypass
To solve the dual challenges of high threat volume and LLM rate/quota limitations:
- **Fast Track (Sweeps):** Pure indicator feeds (e.g. malware hash lists, IP blocklists) are routed to the deterministic sweep engine. This generates valid, high-fidelity Sigma rules without calling external LLM APIs, operating with near-zero latency and zero token cost.
- **Deep Track (Research):** Complex narrative reports (e.g. DFIR incident analyses, Microsoft advisories) are allocated dedicated LLM context, conducting structured web research, MITRE ATT&CK mapping, and multi-stage hypothesis generation.

### 2.3 Grounding Audit & Hallucination Mitigation
Detection rules in production cannot tolerate hallucinated command-line flags or fabricated IoCs:
- **Source Artifact Auditing:** Every extracted IP, domain, hash, filename, and registry path is verified against the raw intelligence document.
- **Strict Evidence Boundaries:** If a technique is inferred from general context rather than explicitly named, it is tagged as `grounding: inferred`, alerting human reviewers to verify telemetry availability.
- **Noise Suppression:** Built-in heuristics identify benign testing artifacts (e.g. loopback probes, mock lab scripts) and ensure dual-use utilities have required malicious flags before rules are approved.

### 2.4 Purple-Team Telemetry Replay & Emulation
Rather than assuming a generated detection rule works, Hecate tests it against synthetic telemetry:
- **Telemetry Replay:** Simulates attack telemetry corresponding to the hunt's MITRE ATT&CK techniques.
- **Multi-Source Event Modeling:** Synthesizes realistic events for Windows Process Creation (Sysmon 1 / 4688), File Events (Sysmon 11), Network Connections (Sysmon 3 / Zeek), and Web/WAF events (Nginx / ModSecurity).
- **Rule Verification:** Evaluates candidate Sigma rules against the synthetic event log to verify that the query fires on malicious patterns and rejects normal baseline activity.

### 2.5 Multi-Engine Query Transpilation
Hecate translates generic Sigma detection rules into native, optimized query languages:
- **Splunk:** Search Processing Language (SPL).
- **Microsoft Sentinel:** Kusto Query Language (KQL).
- **CrowdStrike Falcon:** Falcon LogScale Query Language.
- **Elasticsearch:** Event Query Language (EQL) and Lucene queries.
- **IBM QRadar:** Ariel Query Language (AQL).

### 2.6 Human-in-the-Loop ChatOps & Operations
- **Interactive Slack Cards:** When a hunt is drafted, Hecate posts an interactive Slack card displaying the hypothesis, confidence score, MITRE techniques, and candidate rules.
- **Thread Actions:** Security engineers can trigger queries, request rule tuning, or approve promotions directly from Slack threads.
- **Live Terminal Monitor:** Run `hecate-agent monitor` in any terminal to see a real-time curses-based view of daemon activity, queue status, and active research cycles.
