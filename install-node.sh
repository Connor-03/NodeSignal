#!/usr/bin/env bash
# install-node.sh — install/upgrade NodeSignal on the Bitcoin node box
# ===========================================================================
# Installs the daemon AND its web interface to /opt/nodesignal, registers a
# systemd service, and serves the app on port 8789.
#
#   Fresh install or upgrade, run from the folder holding
#   nodesignald.js + nodesignal.html (the operator console):
#
#       chmod +x install-node.sh
#       ./install-node.sh                      # nick = hostname, no web token
#       ./install-node.sh Bama-Knots-Node      # explicit nick
#       ./install-node.sh Bama-Knots-Node s3cret   # nick + web login token
#
# Your saved contacts and messages live in  ~/.nodesignal/state.json  and are
# never touched by this script.
#
# After install:
#     http://<tailscale-ip>:8789        the app
#     http://<tailscale-ip>:8789/health JSON health check
#     journalctl -u nodesignal -f       live log
#     sudo systemctl restart nodesignal
#
# Ports (reachable over Tailscale; no router forwarding needed):
#     8789/tcp  web app + WebSocket API
#     8788/tcp  daemon <-> daemon messaging
# If ufw is enabled, restrict them to the tailnet:
#     sudo ufw allow in on tailscale0 to any port 8789 proto tcp
#     sudo ufw allow in on tailscale0 to any port 8788 proto tcp
# ===========================================================================
set -euo pipefail

NICK="${1:-$(hostname)}"
WEB_TOKEN="${2:-}"
USER_NAME="$(id -un)"
DEST=/opt/nodesignal
WEB_PORT=8789
PEER_PORT=8788

echo "NodeSignal installer"
echo "  user      : ${USER_NAME}"
echo "  nick      : ${NICK}"
echo "  target    : ${DEST}"
echo "  web port  : ${WEB_PORT}"
echo "  peer port : ${PEER_PORT}"
echo ""

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js not found. Install it, then re-run:"
  echo "  sudo apt update && sudo apt install -y nodejs npm"
  exit 1
fi
echo "Node.js $(node --version) found."

for f in nodesignald.js nodesignal.html; do
  if [ ! -f "$f" ]; then
    echo "ERROR: $f not found in $(pwd)."
    echo "Copy nodesignald.js and nodesignal.html here, then re-run."
    echo "(nodesignal.html is the operator console — do NOT use nodesignal-demo.html"
    echo " on the node; that build is the Windows demo and needs a secure context.)"
    exit 1
  fi
done

# a stale demo build in /opt would be served in preference by older layouts
if [ -f /opt/nodesignal/nodesignal-demo.html ]; then
  echo "Removing an old demo build from /opt/nodesignal..."
  sudo rm -f /opt/nodesignal/nodesignal-demo.html
fi

# stop the old service if this is an upgrade (state.json is untouched)
if systemctl list-unit-files 2>/dev/null | grep -q '^nodesignal.service'; then
  echo "Existing service found — stopping for upgrade..."
  sudo systemctl stop nodesignal || true
fi

echo "Installing files to ${DEST}..."
sudo mkdir -p "$DEST"
sudo cp nodesignald.js nodesignal.html "$DEST/"
sudo chown -R "${USER_NAME}:${USER_NAME}" "$DEST"

echo "Installing dependencies (express, ws)..."
cd "$DEST"
npm install express ws --no-audit --no-fund --loglevel=error

EXEC="$(command -v node) ${DEST}/nodesignald.js --nick ${NICK} --web-port ${WEB_PORT} --peer-port ${PEER_PORT}"
if [ -n "$WEB_TOKEN" ]; then
  EXEC="${EXEC} --web-token ${WEB_TOKEN}"
  echo "Web login token ENABLED."
else
  echo "Web login token disabled (open on the tailnet). Pass a 2nd argument to enable."
fi

echo "Writing systemd unit..."
sudo tee /etc/systemd/system/nodesignal.service >/dev/null <<UNIT
[Unit]
Description=NodeSignal daemon and web app (operator chat beside the Bitcoin node)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USER_NAME}
WorkingDirectory=${DEST}
ExecStart=${EXEC}
Restart=on-failure
RestartSec=5
# state lives in ~/.nodesignal and survives upgrades

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now nodesignal
sleep 2

echo ""
echo "---------------------------------------------------------------"
sudo systemctl --no-pager --full status nodesignal | head -14 || true
echo "---------------------------------------------------------------"

TS_IP="$(ip -4 addr show tailscale0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1 || true)"
[ -z "$TS_IP" ] && TS_IP="<tailscale-ip>"

echo ""
echo "Health check:"
curl -fsS "http://127.0.0.1:${WEB_PORT}/health" && echo "" || echo "  (not answering yet — check: journalctl -u nodesignal -n 40)"
echo ""
echo "Done. Open:  http://${TS_IP}:${WEB_PORT}"
echo "Peers message this node on tcp ${PEER_PORT}."
