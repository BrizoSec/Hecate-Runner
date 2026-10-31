#!/usr/bin/env bash
# Read-only inspection plus a temporary write probe inside the disposable lab.
set -euo pipefail
docker inspect hecate-bas-agent | python3 -c '
import json,sys
c=json.load(sys.stdin)[0]; h=c["HostConfig"]
assert c["State"]["Running"], "Agent is not running"
assert h["ReadonlyRootfs"], "Writable root filesystem"
assert c["Config"]["User"] == "65534:65534", "Unexpected agent identity"
assert "ALL" in h["CapDrop"], "Capabilities not dropped"
assert "no-new-privileges=true" in h["SecurityOpt"], "Privilege escalation permitted"
assert not c["Mounts"], "Unexpected mounted host data or volumes"
assert set(c["NetworkSettings"]["Networks"]) == {"hecate-bas-lab"}, "Unexpected network attachment"
assert h["PidsLimit"] == 128 and h["Memory"] == 268435456, "Resource limits differ"
assert "noexec" in h.get("Tmpfs", {}).get("/tmp", "").split(","), "Temporary filesystem permits native executables"
limits={item["Name"]: item for item in h.get("Ulimits", [])}
assert limits["core"]["Hard"] == 0 and limits["nofile"]["Hard"] <= 256, "Missing process limits"
assert 0 < limits["fsize"]["Hard"] <= 16777216, "Unbounded file size"
print("PASS: container configuration")
'
[[ $(docker network inspect -f '{{.Internal}}' hecate-bas-lab) == true ]]
docker exec hecate-bas-agent sh -ec '
[ "$(id -u)" = 65534 ]
[ ! -e /home/chemch ]
[ ! -S /var/run/docker.sock ]
[ ! -S /run/user/1000/bus ]
if touch /etc/hecate-write-probe 2>/dev/null; then exit 1; fi
touch /tmp/hecate-write-probe && rm /tmp/hecate-write-probe
! ip route | grep -q default
grep -q "^CapEff:[[:space:]]*0000000000000000$" /proc/self/status
grep -q "^NoNewPrivs:[[:space:]]*1$" /proc/self/status
grep -q "^Seccomp:[[:space:]]*2$" /proc/self/status
printf "PASS: runtime identity, filesystem, sockets, privileges, seccomp, and routing\n"
'
