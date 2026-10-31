# BAS capability and host safety audit — 2026-10-27

**2026-10-31 update:** The workspace owner authorized automatic execution limited
to reviewed read-only procedures in the isolated Linux lab, with independent
process observation. See [approved lab automation](BAS_AUTOMATION.md). The
original recommendation below continues to apply to unrestricted technique
execution, Windows/cloud procedures, and execution on the shared host.

## Result

Isolated Linux CALDERA execution is working. The general host is **not yet fully hardened**: UFW is disabled and several host services listen on all interfaces. Administrator authentication and a decision about required LAN/Tailscale access are needed to complete firewall work.

## Verified behavior

- Authenticated CALDERA health is healthy; its published port is `127.0.0.1:8888`.
- Live T1033 identity discovery executed `whoami` inside the lab as `nobody`, exit 0. An additional run through `hecate-runner bas-detonate` completed successfully.
- The endpoint is `hecate-bas-lab`, agent `hecate-local-sandbox`, group `hecate-local-lab`. The physical host `k3s-core` is no longer an allowed live target; a CLI request against it failed before execution.
- No active Hecate operations remained after testing. One previously abandoned operation was stopped.
- 86 focused tests passed: BAS providers, target safety, orchestration BAS flow, configuration, and purple team pipeline. Ruff, shell syntax checks, and `git diff --check` passed.

## Isolation installed and checked at runtime

The old host-native Sandcat service was replaced by a Docker client service supervising `hecate-bas-agent`. The old unit is backed up at `~/.config/systemd/user/caldera-sandcat.service.pre-audit`.

The agent container uses UID/GID 65534, has a read-only root filesystem, no mounted host directories or volumes, all capabilities dropped, `no-new-privileges`, Docker seccomp, a 64 MiB temporary filesystem, a 128-process limit, 256 MiB memory limit, and half a CPU. It shares an internal Docker network with CALDERA and has no default route. The host home directory, Docker socket, and user session bus are absent. Runtime write probes confirmed that `/etc` is read-only and `/tmp` is writable.

The earlier systemd user unit reported filesystem sandbox settings without actually hiding host files on this machine. Those settings were not accepted as evidence of isolation. The replacement was checked inside the running container.

The service is enabled and user lingering is enabled. Docker must be running for the container service to operate.

## Application fixes

- Live targets require an explicit identity in a nonempty allowlist; wildcards and environments other than lab/staging/sandbox are rejected. Unknown platforms fail rather than silently selecting Linux.
- CALDERA checks the exact host, platform, trust flag, and optional agent ID. Its group must contain exactly one agent, preventing an initial group-wide operation against unrelated endpoints.
- Disabled live BAS is enforced by the provider factory. Unattended live execution requires a separate `HECATE_BAS_AUTO_EXECUTE_LIVE` opt-in; the installed setting is false.
- Mock fallback defaults to false. Explicit mock fallbacks retain `provider=mock` and fallback metadata instead of claiming CALDERA execution.
- Failed links prevent operation success. Timeouts attempt to stop remote scheduling and report cleanup as unconfirmed. CALDERA's explicit cleanup method no longer reports success without proof.
- The detonation CLI exits unsuccessfully on execution or cleanup failure.
- The active CALDERA API key was found in a tracked guide, removed from that guide, and rotated in CALDERA and the workspace environment. The old key now returns HTTP 401; the replacement authenticates. No replacement key was written into repository documentation.
- `Hecate-Workspace/.env` permissions changed from 0664 to 0600. Its BAS target/group settings point at the isolated endpoint.

## Host controls and unfinished administrator work

Observed controls: AppArmor active, unattended upgrades active with daily configuration, and kernel ptrace restriction set to 1. These checks do not constitute a complete host security assessment.

`/etc/ufw/ufw.conf` has `ENABLED=no`. Listeners on wildcard addresses included:

| Service | Ports observed |
| --- | --- |
| SSH | TCP 22 |
| GNOME remote desktop | TCP 3389 and 3390 |
| Neo4j | TCP 7473, 7474, 7687 |
| Kubernetes API and kubelet | TCP 6443, 10250 |
| Flannel VXLAN | UDP 8472 |

Wildcard listening does not prove Internet reachability; upstream routing/firewalls and other packet filters were not fully inspected. Do not infer that the host is protected from the disabled UFW service status alone.

Administrator work:

1. Review effective IPv4/IPv6 firewall rules and identify the required management networks and Kubernetes peers. Preserve current SSH/Tailscale access before enabling a default-deny inbound policy.
2. Restrict Neo4j and remote desktop to loopback or explicitly trusted management interfaces/networks. Restrict Kubernetes API/kubelet/VXLAN traffic to the required cluster peers and management clients.
3. Inspect effective SSH authentication settings and privileged service configurations. The session could not inspect root-only SSH drop-ins or change system firewall rules: `sudo -n` requires interactive authentication.
4. Recheck required access and blocked traffic from a separate host after applying the policy.

## Practical limits

Only harmless Linux identity discovery was executed live. Windows agents and cloud/Stratus execution were not validated. Cloud account allowlisting is not proof that a CLI's ambient credentials belong to the requested account; confirm actual cloud identity in an isolated test account before enabling cloud procedures. Live SIEM ingestion and detection triggering were not demonstrated; CALDERA command completion alone is not proof that a production detection fired.

The sandbox intentionally limits realistic host simulation: payloads cannot inspect the physical host's files or processes, and internet downloads are unavailable. It can reach the CALDERA service on the internal network. Containers share a kernel and are not a replacement for disposable VMs when testing hostile payloads or kernel exploits. Keep unattended live execution disabled on this shared development/Kubernetes host.

## Repeatable checks

From Hecate-Runner:

```bash
scripts/check-bas-isolation.sh
.venv/bin/hecate-runner bas-detonate T1033 --provider caldera \
  --host hecate-bas-lab --platform linux --env lab --timeout 120
.venv/bin/python -m pytest tests/test_bas* tests/test_orchestrator_bas_flow.py \
  tests/test_config.py tests/test_purple_team_pipeline.py -q --no-cov
```

For a fresh deployment with an existing loopback-bound CALDERA container, `scripts/setup-bas-lab.sh ../sandcat` builds the minimal agent image from a context containing only the Dockerfile and binary, creates the internal network, attaches CALDERA, and creates the restricted agent container. It refuses to replace an existing container or accept a non-internal network. Install the accompanying user service after preparing the container. Configure the private workspace environment as documented in HOW_TO.md.
