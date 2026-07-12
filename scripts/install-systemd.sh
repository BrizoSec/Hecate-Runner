#!/usr/bin/env bash
# Install sec7669 systemd units.
#
# Usage: sudo ./scripts/install-systemd.sh
#
# Idempotent — safe to re-run after editing the units.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="/etc/systemd/system"

echo "==> Installing sec7669 systemd units from $REPO_ROOT/systemd"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

install -m 0644 "$REPO_ROOT/systemd/sec7669-orchestrator.service" "$UNIT_DIR/sec7669-orchestrator.service"
install -m 0644 "$REPO_ROOT/systemd/sec7669-orchestrator.timer" "$UNIT_DIR/sec7669-orchestrator.timer"
install -m 0644 "$REPO_ROOT/systemd/sec7669-otx-poller.service" "$UNIT_DIR/sec7669-otx-poller.service"
install -m 0644 "$REPO_ROOT/systemd/sec7669-otx-poller.timer" "$UNIT_DIR/sec7669-otx-poller.timer"
install -m 0644 "$REPO_ROOT/systemd/sec7669-rss-poller.service" "$UNIT_DIR/sec7669-rss-poller.service"
install -m 0644 "$REPO_ROOT/systemd/sec7669-rss-poller.timer" "$UNIT_DIR/sec7669-rss-poller.timer"
install -m 0644 "$REPO_ROOT/systemd/sec7669-misp-poller.service" "$UNIT_DIR/sec7669-misp-poller.service"
install -m 0644 "$REPO_ROOT/systemd/sec7669-misp-poller.timer" "$UNIT_DIR/sec7669-misp-poller.timer"

echo "==> Reloading systemd"
systemctl daemon-reload

echo
echo "==> Installed. Next steps:"
echo "   sudo systemctl enable --now sec7669-orchestrator.timer"
echo "   sudo systemctl list-timers sec7669-orchestrator.timer"
echo "   sudo systemctl start sec7669-orchestrator.service   # force one run"
echo "   sudo journalctl -u sec7669-orchestrator.service -f  # follow logs"
echo
echo "   If SEC7669_CTI_PROVIDER=file and OTX_API_KEY is set, also enable the poller:"
echo "   sudo systemctl enable --now sec7669-otx-poller.timer"
echo "   sudo systemctl start sec7669-otx-poller.service     # force one poll"
echo
echo "   RSS feed polling has sensible defaults out of the box (no API key needed):"
echo "   sudo systemctl enable --now sec7669-rss-poller.timer"
echo "   sudo systemctl start sec7669-rss-poller.service     # force one poll"
echo
echo "   If MISP_BASE_URL and MISP_API_KEY are set, also enable the MISP poller:"
echo "   sudo systemctl enable --now sec7669-misp-poller.timer"
echo "   sudo systemctl start sec7669-misp-poller.service    # force one poll"
