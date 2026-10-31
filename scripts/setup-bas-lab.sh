#!/usr/bin/env bash
# Prepare an isolated, manually invoked CALDERA endpoint. No host directories mounted.
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
agent_binary=${1:-"$repo_dir/../sandcat"}
context_dir=$(mktemp -d)
trap 'rm -rf -- "$context_dir"' EXIT
cp -- "$repo_dir/deploy/bas/Dockerfile" "$context_dir/Dockerfile"
cp -- "$agent_binary" "$context_dir/sandcat"
docker build --pull=false -t hecate-bas-agent:local "$context_dir"
if ! docker network inspect hecate-bas-lab >/dev/null 2>&1; then
    docker network create --internal hecate-bas-lab
fi
if [[ $(docker network inspect -f '{{.Internal}}' hecate-bas-lab) != true ]]; then
    echo 'Refusing existing BAS network without internal isolation.' >&2
    exit 1
fi
if ! docker inspect -f '{{json .NetworkSettings.Networks}}' caldera | python3 -c 'import json,sys; sys.exit(0 if "hecate-bas-lab" in json.load(sys.stdin) else 1)'; then
    docker network connect hecate-bas-lab caldera
fi
if docker container inspect hecate-bas-agent >/dev/null 2>&1; then
    echo 'Agent container already exists; inspect it before replacing it.' >&2
    exit 1
fi
docker create --name hecate-bas-agent --hostname hecate-bas-lab \
    --network hecate-bas-lab --read-only --user 65534:65534 \
    --cap-drop ALL --security-opt no-new-privileges=true \
    --pids-limit 128 --memory 256m --cpus 0.5 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
    --ulimit core=0:0 --ulimit nofile=256:256 --ulimit fsize=16777216:16777216 \
    --log-opt max-size=10m --log-opt max-file=3 \
    hecate-bas-agent:local -server http://caldera:8888 \
    -group hecate-local-lab -paw hecate-local-sandbox
