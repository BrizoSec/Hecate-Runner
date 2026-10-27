# Hecate Platform Architecture

An architectural blueprint of the Hecate autonomous detection engineering and threat hunting platform.

---

## 1. Executive Summary

**Hecate** is an autonomous, agentic detection engineering ecosystem. It bridges the gap between raw Cyber Threat Intelligence (CTI) and production-grade detection content across modern Security Information and Event Management (SIEM) and Endpoint Detection and Response (EDR) platforms.

Hecate is designed around a core tenet: **The LLM proposes, deterministic code disposes.** Generative AI models propose hypotheses, extract threat behaviors, and draft candidate detection logic; deterministic static analysis engines, AST validators, MITRE ATT&CK grounders, and telemetry emulators verify, tune, and test every generated artifact before it reaches human review or production promotion.

---

## 2. The Three-Repository Topology

The platform is partitioned into three distinct repositories with decoupled responsibilities:

```mermaid
flowchart TD
    subgraph Repo1["Hecate-Core (BrizoSec/Hecate-Core)"]
        direction TB
        C_API["API Layer (hecate_agent.api)"]
        C_AGENTS["Agentic Reasoning Engine<br/>Hypothesis & Research Agents"]
        C_SIGMA["Sigma Rule Generator & AST Validator"]
        C_ATTACK["MITRE ATT&CK STIX Grounder"]
        C_TRANSPILER["pySigma Multi-Backend Transpiler"]
        C_CLI["hecate-agent CLI & TUI Monitor"]
    end

    subgraph Repo2["Hecate-Runner (BrizoSec/Hecate-Runner)"]
        direction TB
        R_DAEMON["Perpetual Daemon Service<br/>(hecate-runner-daemon.service)"]
        R_CTI["20+ Multi-Feed CTI Ingestion Engine"]
        R_QUEUE["Dual-Track Priority Queue Scheduler"]
        R_PURPLE["Purple Team Emulation Harness"]
        R_REVIEW["Automated Reviewer & Self-Remediation"]
        R_PUB["GitHub Outbox PR Publisher"]
        R_SLACK["Interactive Slack Bot & ChatOps"]
    end

    subgraph Repo3["Hecate-Workspace (BrizoSec/Hecate-Content)"]
        direction TB
        W_HUNTS["hunts/ (LOCK Pattern Documents)"]
        W_QUERIES["queries/ (Transpiled SIEM Queries)"]
        W_RESEARCH["research/ (CTI Research Dossiers)"]
        W_PLAYBOOKS["playbooks/ (Cross-Campaign Guides)"]
        W_POLICY["promotion-policy.yaml & Promotion Gates"]
    end

    Repo2 -- "imports in-process as library" --> Repo1
    Repo2 -- "reads & writes content / publishes PRs" --> Repo3
    Repo1 -- "references schemas & validates format" --> Repo3
```

### 2.1 Repository Summary

| Repository | Python Package | Primary Role | Key Artifacts |
|---|---|---|---|
| **[`Hecate-Core`](file:///home/chemch/betas/Hecate-Core)** | `hecate_agent` | Core detection reasoning library, prompt engine, MITRE ATT&CK grounding, Sigma generator, and pySigma transpiler. | `hecate-agent` CLI, agent modules, prompt templates, evaluation harness. |
| **[`Hecate-Runner`](file:///home/chemch/betas/Hecate-Runner)** | `hecate_runner` | Autonomous orchestrator, perpetual daemon, 20+ CTI intake feeds, purple-team adversary emulation, reviewer auto-remediation, GitHub publisher, Slack bot. | `hecate-runner` CLI, daemon service, CTI pollers, emulation runners, PR publisher. |
| **[`Hecate-Workspace`](file:///home/chemch/betas/Hecate-Workspace)** | *(Content Repo)* | Central version-controlled detection engineering repository (`BrizoSec/Hecate-Content`). | `hunts/` (LOCK markdown), `queries/` (Sigma & SIEM queries), `research/` dossiers, `promotion-policy.yaml`. |

---

## 3. End-to-End Lifecycle & Data Flow

From the arrival of an external intelligence pulse to a verified SIEM detection query in production, Hecate runs a multi-stage deterministic pipeline:

```mermaid
sequenceDiagram
    autonumber
    participant Feeds as Threat Feeds (20+ Sources)
    participant Runner as Hecate-Runner Daemon
    participant Core as Hecate-Core Agent API
    participant Purple as Purple Team Emulation
    participant Reviewer as Sigma Reviewer Engine
    participant GitHub as GitHub (BrizoSec/Hecate-Content)
    participant Slack as Slack Alert & ChatOps

    Feeds->>Runner: Raw CTI Item (RSS, OTX, MISP, KEV, etc.)
    Runner->>Runner: Triage & Deduplication (Park uninteresting/duplicate)
    alt Fast Indicator Sweep
        Runner->>Runner: Deterministic Sweep (0-cost rule generation)
    else Deep Narrative Threat
        Runner->>Core: Research Agent Context Extraction
        Core-->>Runner: Grounded Research Dossier (R-XXXX)
        Runner->>Core: Hypothesis Generation Agent
        Core-->>Runner: Structured Hypothesis (H-XXXX)
    end
    Runner->>Core: Sigma Rule Drafting
    Core-->>Runner: Candidate Sigma Rules (YAML)
    Runner->>Purple: Adversary Telemetry Emulation (Atomic Red Team Replay)
    Purple-->>Runner: Generated & Correlated Synthetic Events
    Runner->>Reviewer: Automated Syntax & Semantic Review
    alt Review Errors Found
        Reviewer->>Core: Self-Remediation Feedback Loop
        Core-->>Reviewer: Corrected Logsource / Field Mappings
    end
    Runner->>Core: pySigma Transpilation (Splunk, Sentinel, CrowdStrike, Elastic, QRadar)
    Core-->>Runner: Multi-Engine Query Targets
    Runner->>GitHub: Open Atomic PR with Hunt, Queries, and Digest
    Runner->>Slack: Broadcast Block Kit Hunt Card with Interactive Actions
```

---

## 4. Key Subsystem Architectures

### 4.1 Autonomous Daemon & Dual-Track Queue

The perpetual daemon ([`hecate_runner.orchestrator`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/orchestrator.py)) runs as a resilient systemd background service (`hecate-runner-daemon.service`).

```mermaid
flowchart TD
    POLL["Poll Active CTI Feeds"] --> DUAL{"Classify Feed Type"}
    DUAL -- "Pure Indicators / High-Velocity" --> SWEEP["Fast Sweep Track<br/>Short Cooldown (30s)<br/>Deterministic Generator"]
    DUAL -- "Narrative Threat Intel / Reports" --> DEEP["Deep Research Track<br/>Standard Cooldown (180s)<br/>Agentic Research & Hypothesis"]
    SWEEP --> EMULATE["Purple Team Emulation & Review"]
    DEEP --> EMULATE
    EMULATE --> DRAFT["Write Draft Hunt & Queries"]
    DRAFT --> SYNC["Outbox PR Dispatch & Slack Notice"]
```

- **Dual-Track Priority:** High-volume indicator feeds (e.g. ThreatFox, MalwareBazaar) bypass heavy LLM research and invoke fast deterministic sweeps, preserving LLM token budgets and Tavily search credits for complex narrative advisories.
- **State Persistence:** Feed cursor positions, processed pulse IDs, and daily quotas are atomically committed to `.cursors/` and `.orchestrator_state.json`.

### 4.2 Grounding & Anti-Hallucination Framework

To guarantee detection fidelity, Hecate enforces strict verification boundaries in [`hecate_agent.core.grounding`](file:///home/chemch/betas/Hecate-Core/hecate_agent/core/grounding.py) and [`hecate_runner.claim_provenance`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/claim_provenance.py):

1. **Source Evidence Extraction:** CTI text and primary web sources are parsed for exact regex matches against processes, command lines, hashes, IPs, domains, and registry keys.
2. **Verbatim Claim Auditing:** Any rule or hypothesis asserting that an attacker executed a specific artifact must have that artifact present in the verified source text; inferred techniques are explicitly labeled `grounding: inferred`.
3. **Platform Protects Heuristic:** Dual-use administrative tools (e.g. `whoami.exe`, `net.exe`, `curl`) require specific malicious context or command-line parameters to avoid generating noisy, un-tunable detection rules.

### 4.3 Automated Reviewer & Self-Remediation Loop

In [`hecate_agent.agents.llm.sigma_generator`](file:///home/chemch/betas/Hecate-Core/hecate_agent/agents/llm/sigma_generator.py) and [`hecate_runner.rule_tuner`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/rule_tuner.py):

1. **Syntactic Validation:** Every generated Sigma YAML rule is loaded into a strict AST parser to prevent invalid syntax or malformed YAML keys.
2. **Platform & Logsource Correction:** When a rule specifies an ambiguous platform or mismatched logsource (e.g. Linux auditd fields on a Windows process creation rule), the reviewer engine passes remediation error messages back to the LLM generator to regenerate corrected definitions.
3. **pySigma Backend Compatibility:** The rule is test-transpiled across all 5 target SIEM dialects. If a backend fails due to an unsupported condition modifier or wildcard placement, the rule is automatically tuned.

### 4.4 Purple-Team Telemetry Replay

In [`hecate_runner.purple_team`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/purple_team.py):
- For every generated hunt, Hecate simulates the adversary technique using Atomic Red Team definitions and synthetic telemetry generators.
- Synthesizes realistic events for:
  - **Process Creation:** Sysmon Event ID 1, Windows 4688, Linux auditd `execve`.
  - **File Operations:** Sysmon Event ID 11, auditd file write.
  - **Network Connections:** Sysmon Event ID 3, Zeek `conn.log`, Firewall logs.
  - **Web Application / WAF:** Apache/Nginx access logs and Cloudflare/ModSecurity WAF events.
- Evaluates candidate Sigma rules against the synthetic telemetry to verify true-positive detection prior to human submission.

### 4.5 Breach & Attack Simulation (BAS) & Live Adversary Emulation

In [`hecate_runner.bas`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/bas), Hecate implements automated **Level 4 Purple Teaming** by integrating with real-world adversary emulation frameworks:

```mermaid
flowchart TD
    subgraph Trigger ["Detonation Trigger"]
        CLI["CLI: bas-detonate / bas-verify"]
        ORCH["Orchestrator Pipeline<br/>(_emulate_and_validate_adversary)"]
    end

    subgraph Factory ["Provider Factory & Safety Boundary"]
        PROV["get_bas_provider(name)"]
        SAFETY{"check_safety(target)<br/>Prod Rejection & Allowlists"}
    end

    subgraph Providers ["BAS Providers"]
        MOCK["MockBASProvider<br/>In-memory Synthetic Telemetry"]
        CALDERA["CalderaConnector<br/>REST API v2 / Classic<br/>Dual API & Link Polling"]
        STRATUS["StratusConnector<br/>CLI Cloud API Detonation<br/>AWS / GCP / Azure"]
    end

    subgraph HardenedTarget ["Live Endpoint Execution (CALDERA)"]
        C2["CALDERA Server<br/>(127.0.0.1:8888 Docker)"]
        AGENT["Sandcat Agent<br/>(caldera-sandcat.service)<br/>NoNewPrivileges, PrivateTmp"]
    end

    subgraph Verification ["Closed-Loop Detection Verification"]
        VERIFIER["DetectionVerifier<br/>Correlate Detonation & Telemetry"]
        SIGMA["In-Process Sigma Evaluator<br/>Rule Query Matching"]
        RESULT["Verification Classification<br/>TRUE_POSITIVE / DETECTION_MISS / TELEMETRY_MISS"]
    end

    subgraph Policy ["Promotion & Persistence"]
        FRONTMATTER["Write-back Hunt Frontmatter<br/>purple_team_validated: true<br/>bas_verified: true"]
        GATE["Promotion Policy<br/>bas_failed: review / block"]
    end

    Trigger --> PROV --> SAFETY
    SAFETY -- "mock" --> MOCK
    SAFETY -- "caldera" --> CALDERA
    SAFETY -- "stratus" --> STRATUS
    CALDERA -. "Missing Platform / Offline" .-> MOCK
    CALDERA --> C2 --> AGENT
    MOCK --> VERIFIER
    CALDERA --> VERIFIER
    STRATUS --> VERIFIER
    VERIFIER --> SIGMA --> RESULT
    RESULT --> FRONTMATTER
    RESULT --> GATE
```

#### Core Components & Code Organization
- **Base Models & Safety Boundary ([`base.py`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/bas/base.py)):** Defines immutable Pydantic models (`DetonationRequest`, `DetonationResult`, `DetonationTarget`, `DetonationStage`, `VerificationStatus`, `DetectionVerificationResult`). Enforces non-negotiable safety guardrails: immediately raises `SafetyViolationError` if the target environment matches `production`, `prod`, or `live`, and verifies host and account allowlists.
- **MITRE CALDERA Connector ([`caldera.py`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/bas/caldera.py)):** Communicates with CALDERA servers via dual-API REST interaction (REST API v2 with automatic fallback to classic `/api/abilities`, `/api/agents`, and `/api/rest`). Resolves MITRE technique IDs to abilities, schedules autonomous ad-hoc operations, decodes base64 commands and output streams, detects early link completion, and cleans up adversaries and operations upon finish.
- **Platform-Aware Mock Fallback:** Disabled by default. Explicitly enabled fallbacks report `provider=mock` and carry fallback metadata; they are not live CALDERA execution evidence.
- **Stratus Red Team Connector ([`stratus.py`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/bas/stratus.py)):** Orchestrates cloud adversary emulation across AWS, GCP, and Azure using the `stratus-red-team` binary. Manages warm-up, detonation, telemetry event collection (CloudTrail, GCP Audit, Azure Activity), and mandatory resource destruction/cleanup.
- **Mock Provider ([`mock.py`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/bas/mock.py)):** Zero-dependency in-process provider generating deterministic, high-fidelity security telemetry (Sysmon process creation, network connections, file modifications, cloud audit events) for fast unit testing and offline CI/CD pipelines.
- **Detection Verifier ([`verifier.py`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/bas/verifier.py)):** Executes closed-loop verification by evaluating candidate Sigma detection rules directly against the telemetry generated during detonation. Evaluates true-positive coverage, reports rule hit counts, and updates hunt markdown documents with verification metadata and frontmatter flags.
- **Hardened Agent Deployment:** The user service supervises an isolated nonroot Docker agent with no host mounts, read-only root, dropped capabilities, no new privileges, resource limits, and an internal network. CALDERA publishes its API only on loopback. User service mount settings alone were insufficient on the audited host; see [the BAS audit](BAS_SAFETY_AUDIT.md).


---

## 5. Security & Isolation Model

- **Zero-Unattended Execution:** The pipeline generates `status: planning` hunts and candidate queries. No query or remediation command is executed against production SIEMs without authenticated human confirmation.
- **Atomic Operations:** All file updates utilize atomic temporary-write-and-rename patterns (`atomic_write_text`) with flock guards to eliminate corruption risks during system interruptions.
- **Secret Isolation:** API tokens, GitHub App private keys, and SIEM credentials reside in secure `.env` files or `/run/secrets/` and are never committed to version control.
