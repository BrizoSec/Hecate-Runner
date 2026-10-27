# Hecate Developer How-To Guide

A practical handbook of step-by-step developer recipes for setting up, extending, and operating Hecate.

---

## Table of Contents
1. [Recipe 1: Local Developer Environment Setup](#recipe-1-local-developer-environment-setup)
2. [Recipe 2: Running a Manual Threat Hunt](#recipe-2-running-a-manual-threat-hunt)
3. [Recipe 3: Adding a New CTI Feed Provider](#recipe-3-adding-a-new-cti-feed-provider)
4. [Recipe 4: Adding or Customizing a SIEM/EDR Backend](#recipe-4-adding-or-customizing-a-siemedr-backend)
5. [Recipe 5: Running Local Evals and Telemetry Replays](#recipe-5-running-local-evals-and-telemetry-replays)
6. [Recipe 6: Operating the Autonomous Perpetual Daemon](#recipe-6-operating-the-autonomous-perpetual-daemon)
7. [Recipe 7: Configuring ChatOps & The Slack Bot](#recipe-7-configuring-chatops--the-slack-bot)

---

## Recipe 1: Local Developer Environment Setup

Hecate uses [uv](https://docs.astral.sh/uv/) for lightning-fast, reproducible dependency management. Python 3.11 or newer is required.

### 1.1 Clone the Three Repositories Side-by-Side
```bash
mkdir -p ~/betas && cd ~/betas

git clone https://github.com/BrizoSec/Hecate-Core.git
git clone https://github.com/BrizoSec/Hecate-Runner.git
git clone https://github.com/BrizoSec/Hecate-Content.git Hecate-Workspace
```

### 1.2 Initialize Virtual Environments & Install Dependencies
```bash
# Setup Hecate-Core
cd ~/betas/Hecate-Core
uv sync --all-extras

# Setup Hecate-Runner (automatically links Hecate-Core in-process)
cd ~/betas/Hecate-Runner
uv sync --all-extras
```

### 1.3 Configure Environment Variables
Copy `.env.example` into `Hecate-Workspace/.env` (which Runner symlinks to):
```bash
cd ~/betas/Hecate-Workspace
cp .env.example .env
```
Edit `.env` to configure your preferred LLM provider:
```dotenv
# Choose your model provider
HECATE_AI_PROVIDER=anthropic      # options: anthropic, openai, bedrock, ollama
ANTHROPIC_API_KEY=sk-ant-...

# Web Grounding & Search (Required for deep research)
TAVILY_API_KEY=tvly-...

# Workspace Root
HECATE_WORKSPACE=/home/chemch/betas/Hecate-Workspace
```

### 1.4 Verify Installation & Run Tests
```bash
# Run Core tests
cd ~/betas/Hecate-Core
uv run pytest -q

# Run Runner tests
cd ~/betas/Hecate-Runner
uv run pytest -q
```

---

## Recipe 2: Running a Manual Threat Hunt

You do not need to wait for autonomous feeds to draft a hunt. You can trigger on-demand analysis from any text snippet, URL, or CVE.

### Option A: From Raw Intelligence Text
```bash
cd ~/betas/Hecate-Runner
uv run hecate-runner draft \
  --title "Salt Typhoon Cisco Router Compromise" \
  --content "Adversaries deployed a custom backdoor named GhostHook via CVE-2026-1934 into /tmp/gh.elf..." \
  --source-url "https://threatintel.example.com/reports/salt-typhoon"
```

### Option B: Dropping Intelligence into the Intake Queue
```bash
cat << 'EOF' > ~/betas/Hecate-Workspace/cti_queue/urgent_cve.txt
Title: CVE-2026-44321 Apache Struts OGNL RCE
Adversaries are actively exploiting CVE-2026-44321 using crafted Content-Type headers
containing multipart boundaries with OGNL expressions to execute /bin/sh commands.
EOF

# Process queued items immediately
cd ~/betas/Hecate-Runner
uv run hecate-runner run --source file
```

### Option C: Transpiling Sigma to SIEM Dialects
Once a hunt is drafted (e.g. `H-0885`), export it to all supported query targets:
```bash
cd ~/betas/Hecate-Core
uv run hecate-agent hunt promote --hunt H-0885 --output splunk
uv run hecate-agent hunt promote --hunt H-0885 --output sentinel
uv run hecate-agent hunt promote --hunt H-0885 --output crowdstrike
```

---

## Recipe 3: Adding a New CTI Feed Provider

All intelligence ingestors implement the `CTIProvider` interface in [`hecate_runner.cti.base`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/cti/base.py).

### Step 1: Create the Provider Class
Create `src/hecate_runner/cti/my_feed.py`:
```python
from typing import List
from hecate_runner.cti.base import CTIItem, CTIProvider

class MyFeedProvider(CTIProvider):
    name = "my_feed"

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key
        self.base_url = base_url or "https://api.myfeed.example.com/v1"

    def poll(self, max_items: int = 10) -> List[CTIItem]:
        # 1. Fetch raw data from API
        raw_entries = self._fetch_api(max_items)
        items = []

        for entry in raw_entries:
            # 2. Normalize into standard CTIItem
            item = CTIItem(
                source_id=f"my_feed:{entry['id']}",
                title=entry["title"],
                content=entry["description"],
                source_url=entry["url"],
                published=entry["timestamp"],
                entry_tags=entry.get("tags", []),
                raw_indicators=entry.get("iocs", []),
            )
            items.append(item)

        return items
```

### Step 2: Register the Provider
1. Add the provider class to `src/hecate_runner/cti/__init__.py`.
2. Add provider configuration settings in `src/hecate_runner/config.py`.
3. Add a CLI source flag in `src/hecate_runner/cli.py`.

### Step 3: Add Unit Tests
Create `tests/test_cti_my_feed.py` and mock external HTTP requests using `unittest.mock`.

---

## Recipe 4: Adding or Customizing a SIEM/EDR Backend

Query generation is governed by pySigma transpilation in [`hecate_agent.core.sigma_transpiler`](file:///home/chemch/betas/Hecate-Core/hecate_agent/core/sigma_transpiler.py).

### Step 1: Install the pySigma Backend Plugin
Add the target pySigma plugin to `pyproject.toml` in both `Hecate-Core` and `Hecate-Runner`:
```toml
# Example: Adding pySigma-backend-qradar
dependencies = [
    "pysigma>=0.11.0",
    "pysigma-backend-splunk>=1.0.0",
    "pysigma-backend-kusto>=1.0.0",
    "pysigma-backend-qradar>=1.0.0",
]
```

### Step 2: Register the Dialect in `sigma_transpiler.py`
In `hecate_agent/core/sigma_transpiler.py`:
```python
SUPPORTED_TARGETS = {
    "splunk": "Splunk SPL",
    "sentinel": "Microsoft Sentinel KQL",
    "crowdstrike": "CrowdStrike Falcon LogScale",
    "elastic": "Elasticsearch EQL",
    "qradar": "IBM QRadar AQL",
}
```
Define the backend initialization and pipeline options inside `transpile_rule()`.

---

## Recipe 5: Running Local Evals and Telemetry Replays

Hecate includes a deterministic evaluation harness to verify that detection logic catches adversary behaviors without false positives.

### 5.1 Run Replay Against Golden Eval Pulses
```bash
cd ~/betas/Hecate-Core
uv run python evals/replay.py --pulse evals/pulses/vshell-fake-resume.json
```

### 5.2 Test Synthetic Purple Team Replay
Test how synthetic telemetry generation validates a Sigma rule:
```bash
cd ~/betas/Hecate-Runner
uv run python -c "
from hecate_runner.purple_team import emulate_technique_telemetry
events = emulate_technique_telemetry('T1059.001', 'powershell.exe -enc AAAA...')
print(f'Generated {len(events)} synthetic telemetry events')
"
```

### 5.3 Live Adversary Emulation & Breach Simulation (BAS)
Execute on-demand adversary emulation or run closed-loop detection verification against any hunt:

```bash
cd ~/betas/Hecate-Runner

# 1. On-demand adversary detonation via Mock, CALDERA, or Stratus
uv run hecate-runner bas-detonate T1059.001 --provider mock --env lab
uv run hecate-runner bas-detonate T1562.008 --provider stratus --platform aws --env staging --account-id 123456789012

# 2. Closed-loop detection verification against a hunt draft
uv run hecate-runner bas-verify H-0886 --provider mock --write-back

# 3. Environment safety enforcement: production targets are strictly rejected
uv run hecate-runner bas-detonate T1059.001 --env production  # Rejection error exit 1
```

---

## Recipe 6: Operating the Autonomous Perpetual Daemon

The autonomous runner runs as a resident Linux systemd service.

### 6.1 Daemon Commands
```bash
# Check daemon status
systemctl --user status hecate-runner-daemon.service

# View live daemon logs
journalctl --user -u hecate-runner-daemon.service -f

# Restart daemon after updating code
systemctl --user restart hecate-runner-daemon.service

# Stop daemon
systemctl --user stop hecate-runner-daemon.service
```

### 6.2 Running the Daemon Interactively in Foreground
For debugging or testing without systemd:
```bash
cd ~/betas/Hecate-Runner
uv run hecate-runner daemon --interval 60 --max-cycles 0
```

### 6.3 Checking Pipeline Health & Metrics
```bash
# Inspect current queue status and quotas
cd ~/betas/Hecate-Runner
uv run hecate-runner status

# Launch the live curses TUI dashboard
cd ~/betas/Hecate-Core
uv run hecate-agent monitor
```

---

## Recipe 7: Configuring ChatOps & The Slack Bot

The Hecate Slack Bot provides real-time notifications with interactive human-in-the-loop review cards.

### 7.1 Setup App Credentials
In `.env`:
```dotenv
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
SLACK_CHANNEL_ID=C0123456789
```

### 7.2 Run the Bot Service
```bash
# Run standalone
cd ~/betas/Hecate-Runner
uv run hecate-runner slack-bot

# Or manage via systemd
systemctl --user start hecate-runner-slack-bot.service
```

### 7.3 Available Slash Commands in Slack
- `/hecate status`: Returns active queue depth, recent hunts, and daily quota consumption.
- `/hecate hunt H-0882`: Returns the summary, hypothesis, and candidate Sigma rules for hunt `H-0882`.
- `/hecate promote H-0882`: Triggers the CI promotion check and generates a pull request.
