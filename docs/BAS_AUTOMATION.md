# Approved Linux lab automation

Unattended BAS is restricted to ten reviewed non-destructive procedures. It never
executes commands from CTI, generated rules, or an arbitrary technique lookup.

| Technique | Pinned CALDERA ability | Exact Linux command |
| --- | --- | --- |
| T1033 | bd527b63-9f9e-46e0-9816-b8434d2b8989 | `whoami` |
| T1057 | 335cea7b-bec0-48c6-adfb-6066070f5f68 | `ps` |
| T1083 | 52177cc1-b9ab-4411-ac21-2eadc4b5d3b8 | `ls` |
| T1082 | Hecate-managed, pinned in code | `uname -a` |
| T1016 | Hecate-managed, pinned in code | `ip address show` |
| T1087.001 | Hecate-managed, pinned in code | `cut -d: -f1 /etc/passwd` (container accounts only) |
| T1069.001 | 5c4dd985-89e3-4590-9b57-71fed66ff4e2 | `groups` |
| T1124 | Hecate-managed, pinned in code | `date -u +"%Y-%m-%dT%H:%M:%SZ"` |
| T1059.004 | Hecate-managed, pinned in code | `sh -c 'printf hecate-bas-shell-probe'` |
| T1140 | Hecate-managed, pinned in code | `printf 'aGVjYXRlLWJhcy1wcm9iZQ==' \| base64 -d` (inert text only) |

Run `hecate-runner bas-install-procedures` once to install missing Hecate-managed
definitions. This command validates existing definitions before writing and
refuses to overwrite changed commands or executable metadata. Managed IDs are
deterministically pinned to the technique, exact command, and catalog version.

The ability's current contents are checked before scheduling. Changed commands,
payloads, cleanup commands, uploads, variations, requirements, or unexpected
executors cause refusal. New procedures require a code change and review.

A hunt must have Linux scope and a Linux `process_creation` Sigma rule tagged
with the exact approved technique. A compatibility check must also show that the
fixed procedure can exercise the rule predicates; an ATT&CK tag alone is
insufficient. This eligibility check never counts as validation. The first
eligible rule is evaluated using actual observed events. Other
hunts record a skip reason; skipping does not claim a failed or successful
detonation. Windows and cloud automation remain unsupported.

## Real process observation

The agent image runs Sandcat under `strace`, tracing successful `execve` calls
from its descendants. The tracer works as UID/GID 65534 without added
capabilities, privileged mode, host mounts, host PID access, or a relaxed
seccomp profile. The existing internal network and resource limits remain.
The temporary filesystem is `noexec`, core dumps are disabled, open descriptors
are capped at 256, and file sizes are bounded at 16 MiB. Preflight refuses a lab
that loses these controls. CALDERA server resource limits are configured
separately; the installed server has a 1 GiB memory limit, one CPU, and 128 PIDs.

Before scheduling, Hecate checks the exact container identity, hostname, agent
arguments, tracer entrypoint, read-only root, nonroot user, dropped capabilities,
security options, lack of mounts and published ports, resource limits, and
internal network. Missing sensor readiness prevents execution. A lock prevents
overlapping approved validation runs in the workspace.

Only successful observed executions of the exact approved command inside the
detonation's time window are evaluated. CALDERA link receipts are excluded from
sensor evidence. The actual hunt rule is evaluated against these events using
the Sigma evaluator. A rule miss remains a miss; no synthetic events are added
to make it pass.

This verifies **local sensor observation and Sigma matching**. It does not claim
that a SIEM ingested an event or fired an alert. No organizational SIEM/EDR
connection is required or implied.

## Configuration and checks

Keep configuration and credentials in the workspace's ignored `.env`:

```dotenv
HECATE_BAS_ENABLED=true
HECATE_BAS_MODE=caldera
HECATE_BAS_AUTO_EXECUTE_LIVE=true
HECATE_BAS_AUTO_TECHNIQUES=T1033,T1057,T1083,T1082,T1016,T1087.001,T1069.001,T1124,T1059.004,T1140
HECATE_BAS_TELEMETRY=lab_process
HECATE_BAS_SENSOR_CONTAINER=hecate-bas-agent
HECATE_BAS_ALLOWED_HOSTS=hecate-bas-lab
HECATE_BAS_LINUX_HOST=hecate-bas-lab
HECATE_BAS_FALLBACK_TO_MOCK=false
CALDERA_URL=http://127.0.0.1:8888
CALDERA_AGENT_GROUP=hecate-local-lab
```

The CALDERA group must contain exactly one trusted agent matching the lab host.
Automation accepts only a loopback CALDERA endpoint and this dedicated group.
Build the sensor-equipped image using `scripts/setup-bas-lab.sh` for a new lab;
that installer refuses to replace an existing container. Existing deployments
must retain their previous stopped container while replacing the agent with the
same isolation settings and agent arguments.

Run `scripts/check-bas-isolation.sh`, then:

```bash
.venv/bin/hecate-runner bas-check
```

This executes the configured approved procedures against a dedicated sensor
control rule and saves results locally. Sensor controls are explicitly separated
from hunt rule checks in the monitor. They do not modify or publish hunts.

Every automation result is saved with mode 0600 beneath
`<workspace>/.hecate/bas/runs/`. The monitor reads these records, deduplicates any
matching hunt frontmatter result by run ID, and shows automation mode, scope,
observed events, failures, and skips. The `.hecate` directory must remain ignored
by Git. Halt unattended execution by setting
`HECATE_BAS_AUTO_EXECUTE_LIVE=false` and restarting the Runner daemon.
