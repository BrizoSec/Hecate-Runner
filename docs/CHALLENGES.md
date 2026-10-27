# Engineering Challenges & Technical Solutions

A deep-dive into the architectural, algorithmic, and operational challenges solved during the engineering of the Hecate platform.

---

## Challenge 1: Hallucination Mitigation in High-Stakes Threat Detection

### The Problem
Generative language models frequently invent plausible-sounding command-line arguments, file paths, registry keys, or IP addresses. In threat hunting, an invented parameter in a Sigma rule yields a brittle detection that generates zero alerts or causes severe alert fatigue from false positives.

### The Solution
We adopted the architectural principle: **The LLM proposes, deterministic code disposes.**
1. **Verbatim Source Claim Audit:** All indicators of compromise (IoCs) and forensic artifacts extracted by agents undergo regex-based substring verification against the original CTI text and fetched primary vendor advisories.
2. **Explicit Grounding Taxonomy:** Every claim in a generated hunt document is tagged with its empirical provenance:
   - `grounding: verified`: Directly observed in the primary source document.
   - `grounding: inferred`: Synthesized by model reasoning based on technique behavior.
3. **Dual-Use Tool Suppression:** Benign administrative utilities (e.g. `whoami.exe`, `net.exe`, `curl`) often trigger false positives. The grounding engine requires specific malicious context (unusual parent process, obfuscated arguments, or external download flags) before allowing an artifact into a detection rule.
4. **PoC Lab Artifact Filtering:** The engine automatically detects and filters loopback IP addresses (`127.0.0.1`, `localhost`), test ports, and lab harness scripts (`exploit.py`, `poc.py`) that appear in vulnerability advisories but must not be embedded into enterprise production rules.

---

## Challenge 2: Token Economics, Web Search Rate Limits, and Quota Conservation

### The Problem
Continuous 24/7 autonomous operation across 20+ feeds ingests hundreds of threat intelligence items per day. Routing every item through multi-stage LLM chains (context analysis, web search via Tavily, hypothesis drafting, and Sigma generation) would quickly exceed monthly API rate limits and create prohibitive token costs.

### The Solution
1. **Dual-Track Scheduling Queue:** Feeds are segregated into two distinct operating tracks:
   - *Fast Sweep Track:* Pure indicator feeds (MalwareBazaar, ThreatFox, abuse.ch) are routed directly to the deterministic sweep engine.
   - *Deep Research Track:* Narrative reports (DFIR Report, MSRC, vendor security blogs) enter the agentic LLM research pipeline with conservative rate limits and dedicated cooldowns.
2. **Deterministic Sweep Bypass:** For indicator feeds, Hecate synthesizes valid, fully tested Sigma detection rules using deterministic AST generation, bypassing LLM generation completely. This operates with near-zero latency and zero token cost.
3. **Cursor-Based Deduplication:** Feeds maintain persistent cursor states and content fingerprints. Duplicate items or previously processed CVEs are parked immediately without invoking external search APIs.
4. **Local / Remote Hybrid Model Architecture:** Operators can route background drafting to local open-weights models (e.g., Ollama running `qwen2.5:32b` or `llama3.3:70b`) with zero marginal token cost, reserving frontier commercial APIs (Claude, OpenAI) for complex evaluation passes.

---

## Challenge 3: Generating Realistic Synthetic Telemetry for Non-Process Data (Web/WAF/Network)

### The Problem
Standard purple-teaming frameworks (such as Atomic Red Team) heavily focus on endpoint process execution (`cmd.exe`, `powershell.exe`, `sh`). However, modern threats frequently target web applications, edge appliances, and APIs (CVE exploitation, SSRF, path traversal, SQL injection). Candidate detection rules for web servers or WAFs cannot be validated using process creation logs alone.

### The Solution
We implemented a multi-source synthetic telemetry replay pipeline in [`purple_team.py`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/purple_team.py):
1. **Protocol-Aware Telemetry Generation:** The engine parses HTTP methods, URI paths, query strings, headers, and WAF action states from CTI advisories.
2. **Log Emulation:** Generates standards-compliant synthetic event records for:
   - **Web Servers:** Apache, Nginx access and error logs.
   - **Web Application Firewalls:** ModSecurity, Cloudflare, and AWS WAF event formats.
   - **Network Devices:** Zeek `conn.log` and `http.log`, firewall traffic logs.
3. **Automated Rule Evaluation:** Candidate Sigma rules with `logsource.category: webserver` or `logsource.service: waf` are executed against these synthetic streams, ensuring that path traversals (`../..`), suspicious user agents, and exploit payloads fire reliably before the rule is approved.

---

## Challenge 4: Logsource & Schema Discrepancies Across SIEM/EDR Platforms

### The Problem
Sigma rules require strict schema conformity. An LLM drafting a detection for a Linux technique might mistakenly populate Windows Sysmon fields (`CommandLine`, `ParentImage`), or mix network connection attributes into a process creation rule. When exported, these rules fail validation or compile into broken SIEM queries.

### The Solution
1. **Strict AST & Schema Validation:** Every candidate rule is parsed into an abstract syntax tree and checked against the Open Cybersecurity Schema Framework (OCSF) and Sigma standard logsource schemas.
2. **Reviewer Self-Remediation Feedback Loop:** When a schema violation or invalid field combination is detected:
   - The validation error is captured into structured diagnostic feedback.
   - The diagnostic is passed back to the LLM generator in an automated retry loop.
   - The generator self-remediates the logsource category, fixes the field mapping, and returns a conformant rule.
3. **Cross-Backend Transpilation Checks:** The rule is test-compiled across all 5 target SIEM engines (Splunk, Sentinel, CrowdStrike, Elastic, QRadar). If any dialect rejects a condition modifier, the rule is flagged and adjusted before writing to the workspace.

---

## Challenge 5: Multi-Backend Transpilation Semantics

### The Problem
Different SIEM and EDR query engines have conflicting semantics:
- Splunk SPL requires explicit `table`, `eval`, and specific wildcards.
- Microsoft Sentinel KQL enforces strict case sensitivity and type casting (`where CommandLine has_cs "..."`).
- CrowdStrike Falcon LogScale uses distinct event streaming filters and CIDR notation.
- Elastic EQL requires event-sequence formatting.

### The Solution
1. **pySigma Backend Pipelines:** Hecate integrates official pySigma backends with custom target pipeline transformations.
2. **Dialect-Specific Escaping & Normalization:** Special characters, backslashes, and quote escaping are normalized per backend.
3. **Query Literal Integrity:** Bounded search terms and exact IoC hashes are preserved without unwanted truncation or unescaped regex characters.

---

## Challenge 6: Process Concurrency, File Locking, and Daemon Resiliency

### The Problem
In an autonomous 24/7 daemon environment, multiple components access the shared workspace simultaneously (the perpetual daemon, the interactive Slack bot, manual operator CLI commands, and automated CI/CD runners). A premature process termination (e.g. `SIGTERM` during system shutdown) could leave corrupted files, broken JSON cursors, or duplicate hunt IDs.

### The Solution
1. **POSIX File Locking:** Hunt and research ID allocations utilize operating-system-level `flock` guards (`.hunt_id.lock`, `.research_id.lock`) to eliminate race conditions between concurrent threads or processes.
2. **Atomic Write-and-Rename Operations:** All state files, cursor updates, hunt markdown files, and Sigma YAML files use atomic file writing (`atomic_write_text`): data is written to a temporary sibling file and atomically replaced via `os.replace()`.
3. **State Checkpointing Before Heavy Compute:** CTI items are acknowledged and state cursors are persisted *before* launching multi-minute LLM generation tasks. If a timeout or server reboot occurs during drafting, the cycle will not leak quota or re-draft duplicate hunts on restart.
4. **systemd Lifecycle Integration:** The runner daemon is wrapped in a native systemd service with `Restart=always`, `RestartSec=10s`, and clean signal handling, ensuring continuous operation and automatic recovery across system reboots.
