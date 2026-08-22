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
install -m 0644 "$REPO_ROOT/systemd/hecate-runner-otx-poller.service" "$UNIT_DIR/hecate-runner-otx-poller.service"
install -m 0644 "$REPO_ROOT/systemd/hecate-runner-otx-poller.timer" "$UNIT_DIR/hecate-runner-otx-poller.timer"
install -m 0644 "$REPO_ROOT/systemd/hecate-runner-rss-poller.service" "$UNIT_DIR/hecate-runner-rss-poller.service"
install -m 0644 "$REPO_ROOT/systemd/hecate-runner-rss-poller.timer" "$UNIT_DIR/hecate-runner-rss-poller.timer"
install -m 0644 "$REPO_ROOT/systemd/hecate-runner-misp-poller.service" "$UNIT_DIR/hecate-runner-misp-poller.service"
install -m 0644 "$REPO_ROOT/systemd/hecate-runner-misp-poller.timer" "$UNIT_DIR/hecate-runner-misp-poller.timer"

echo "==> Reloading systemd"
systemctl daemon-reload

echo
echo "==> Installed. Next steps:"
echo "   sudo systemctl enable --now hecate-runner-orchestrator.timer"
echo "   sudo systemctl list-timers hecate-runner-orchestrator.timer"
echo "   sudo systemctl start hecate-runner-orchestrator.service   # force one run"
echo "   sudo journalctl -u hecate-runner-orchestrator.service -f  # follow logs"
echo
echo "   If SEC7669_CTI_PROVIDER=file and OTX_API_KEY is set, also enable the poller:"
echo "   sudo systemctl enable --now hecate-runner-otx-poller.timer"
echo "   sudo systemctl start hecate-runner-otx-poller.service     # force one poll"
echo
echo "   RSS feed polling has sensible defaults out of the box (no API key needed):"
echo "   sudo systemctl enable --now hecate-runner-rss-poller.timer"
echo "   sudo systemctl start hecate-runner-rss-poller.service     # force one poll"
echo
echo "   If MISP_BASE_URL and MISP_API_KEY are set, also enable the MISP poller:"
echo "   sudo systemctl enable --now hecate-runner-misp-poller.timer"
echo "   sudo systemctl start hecate-runner-misp-poller.service    # force one poll"
