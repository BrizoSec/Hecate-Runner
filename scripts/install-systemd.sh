#!/usr/bin/env bash
# Install hecate-runner systemd units.
#
# Usage: sudo ./scripts/install-systemd.sh
#
# Idempotent — safe to re-run after editing the units.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="/etc/systemd/system"

echo "==> Installing hecate-runner systemd units from $REPO_ROOT/systemd"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

install -m 0644 "$REPO_ROOT/systemd/hecate-runner-orchestrator.service" "$UNIT_DIR/hecate-runner-orchestrator.service"
install -m 0644 "$REPO_ROOT/systemd/hecate-runner-orchestrator.timer" "$UNIT_DIR/hecate-runner-orchestrator.timer"

echo "==> Reloading systemd"
systemctl daemon-reload

echo
echo "==> Installed. Next steps:"
echo "   sudo systemctl enable --now hecate-runner-orchestrator.timer"
echo "   sudo systemctl list-timers hecate-runner-orchestrator.timer"
echo "   sudo systemctl start hecate-runner-orchestrator.service   # force one run"
echo "   sudo journalctl -u hecate-runner-orchestrator.service -f  # follow logs"
echo
echo "   CTI polling needs no units of its own: with HECATE_RUNNER_CTI_PROVIDER=multi"
echo "   (or otx/rss/misp) the orchestrator pulls from each source inline every cycle."
echo "   To stage CTI into the file queue by hand instead, run one of:"
echo "   uv run hecate-runner otx-poll | rss-poll | misp-poll"
