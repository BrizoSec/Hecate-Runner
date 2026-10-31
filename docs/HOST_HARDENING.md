# Host protections for the Linux BAS lab

Keep lab procedures fixed, non-destructive, and independent of CTI command
strings. The current catalog covers discovery, inert shell execution, and
decoding an inert marker. It does not authorize payload downloads, credential
access, persistence, lateral movement, or kernel exploits.

## Applied lab controls

- Nonroot agent, read-only root, all capabilities dropped, no privilege
  escalation, default seccomp, and no host directories or Docker socket.
- Internal Docker network; exact agent/group/host checks before execution.
- `noexec,nosuid,nodev` temporary filesystem, disabled core dumps, 256 open-file
  limit, 16 MiB file-size limit, 128 PIDs, 256 MiB RAM, and half a CPU.
- Independent process tracing and private result files. A missing control or
  unavailable sensor prevents approved automation.
- CALDERA runs as UID/GID 10001, with a read-only root, all capabilities dropped,
  no privilege escalation, default seccomp, and no host directory/socket mounts.
  Explicit private named volumes hold configuration, data, reports, and build/
  documentation caches. Limits remain 1 GiB RAM, one CPU, and 128 PIDs; the API
  is published only on loopback. Approved automation checks this profile too.

The installed Docker Desktop lab runs inside its Linux VM. Containers share
that VM kernel. These controls do not establish that arbitrary hostile code or
kernel attacks are safe to execute. Use a disposable, separately isolated VM
when procedures need stronger isolation or realistic persistence/credential
artifacts.

## Applied host baseline

The host baseline uses root-owned sysctl and SSH drop-in files, with root-only
backups and automatic restoration on application failure. The applied controls
restrict kernel address visibility, disable privileged core dumps, disable
IPv4/IPv6 redirect acceptance and source routing, and disable IPv4 redirect
sending. Existing interfaces are checked individually as well as global/default
values. Forwarding, router advertisements, reverse-path filtering, and user
namespaces remain configured for the existing workloads.

SSH disallows root and empty-password logins, enforces strict file permissions,
and bounds authentication attempts and login grace time. After a fresh client
key login is verified, the installed host requires public-key authentication;
password and keyboard-interactive authentication are disabled. Existing sessions
and forwarding remain available. Generate and retain private keys on the client,
authorize only their public keys, and verify a fresh login before disabling
password authentication.

The Kubernetes client directory is owner-only. Existing credential files stay
outside Git with owner-only permissions. Avoid copying private host evidence or
firewall addresses into the public hunt workspace.

## Persistent host firewall

The installed host uses Tailscale-only management access through an enabled
boot service. The profiles use a dedicated nftables INPUT table, preserve
existing connections and required control-plane traffic, and leave existing
K3s/Tailscale/Docker tables and forwarding intact. Profiles require validation
against the actual interfaces, LAN ranges, and native K3s nodes before use.

Apply with a timed rollback armed first. Confirm fresh SSH/remote desktop
connections from an authorized second device and native K3s health before
cancelling rollback and making the rule persistent. A successful local
connection does not verify external access. The profiles are not activated
merely by creating or syntax-checking them. The selected profile was committed
after an authenticated fresh connection from the separate client was observed.

## Nonroot controller migration

Build `deploy/caldera/Dockerfile` against the installed local controller image,
then run `.venv/bin/python scripts/migrate-caldera-controller.py`. The migration
refuses unexpected source mounts or a controller that is already migrated. It
holds the workspace BAS lock, stops the agent, gracefully saves controller state,
and takes an owner-only backup before creating private named volumes.

A candidate on a separate loopback port must preserve all API-visible ability,
agent, and operation IDs and the approved procedure contents before promotion.
Production retains the existing API credentials and loopback endpoint. Failure
restores the prior controller; the previous stopped container remains available.
Configuration/data volumes are writable because this CALDERA version saves them
on graceful shutdown. Application Python code remains read-only. Documentation
templates stay root-owned while generated documentation is writable by the
controller. Sandcat build/output caches are writable for existing functionality.

The Dockerfile derives from the locally installed image and does not upgrade
its application or operating-system packages. A version/CVE review and supported
base-image upgrade remain separate maintenance work. No active credentials or
runtime snapshots are copied into a newly built image or committed to Git.

Changing Docker network attachments may break host port publishing. The
internal-only CALDERA test on this host did so; the previous attachment was
restored and authenticated API access verified. CALDERA's external network
attachment remains a documented limitation.

References: [Linux networking sysctls](https://docs.kernel.org/networking/ip-sysctl.html),
[K3s network requirements](https://docs.k3s.io/installation/requirements),
[Tailscale with UFW](https://tailscale.com/docs/how-to/secure-ubuntu-server-with-ufw),
[Docker Engine security](https://docs.docker.com/engine/security/).
