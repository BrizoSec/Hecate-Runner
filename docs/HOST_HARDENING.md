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
- Separate CALDERA server limits: 1 GiB RAM, one CPU, 128 PIDs. The server API
  remains published only on loopback.

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
and bounds authentication attempts and login grace time. Existing password/key
authentication methods and forwarding remain available. Disabling password
authentication requires first verifying fresh key-based logins from the devices
that need access.

The Kubernetes client directory is owner-only. Existing credential files stay
outside Git with owner-only permissions. Avoid copying private host evidence or
firewall addresses into the public hunt workspace.

## Firewall activation needs an access decision

Prepared profiles provide either Tailscale management access or LAN plus
Tailscale management access. They use a dedicated nftables INPUT table, preserve
existing connections and required control-plane traffic, and leave existing
K3s/Tailscale/Docker tables and forwarding intact. Profiles require validation
against the actual interfaces, LAN ranges, and native K3s nodes before use.

Apply with a timed rollback armed first. Confirm fresh SSH/remote desktop
connections from an authorized second device and native K3s health before
cancelling rollback and making the rule persistent. A successful local
connection does not verify external access. The profiles are not activated
merely by creating or syntax-checking them.

Changing Docker network attachments may break host port publishing. The
internal-only CALDERA test on this host did so; the previous attachment was
restored and authenticated API access verified. CALDERA's external network
attachment remains a documented limitation.

References: [Linux networking sysctls](https://docs.kernel.org/networking/ip-sysctl.html),
[K3s network requirements](https://docs.k3s.io/installation/requirements),
[Tailscale with UFW](https://tailscale.com/docs/how-to/secure-ubuntu-server-with-ufw),
[Docker Engine security](https://docs.docker.com/engine/security/).
