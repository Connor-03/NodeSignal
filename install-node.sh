#!/usr/bin/env bash
# install-node.sh: install or upgrade NodeSignal FROM SOURCE on a Linux node box
# ===========================================================================
# Most people should install the .deb instead (it brings its own Node.js):
# see LinuxInstallGuide.txt. This script is for running from a git checkout
# with the system's Node.js (18 or newer).
#
# Runs on: Linux, on the machine that runs bitcoind, from the repository
# folder, as a normal user with sudo rights:
#
#     ./install-node.sh                       display name = hostname
#     ./install-node.sh MyNodeName            explicit display name
#     ./install-node.sh MyNodeName --token    also require a web login token
#                                             (generated and printed once)
#     --advertise      add uacomment=nodesignal to bitcoin.conf (public)
#     --port-mapping   ask the router to forward the peer port (exposes your IP)
#     --yes            ask nothing; opt-ins stay off unless given as flags
#
# NodeSignal requires a Bitcoin node (Core or Knots) on this machine and
# refuses to install without one.
#
# What it does: copies the program to /opt/nodesignal, writes
# /etc/nodesignal/config.json (settings live there, never on a command line),
# a systemd unit running as the dedicated `nodesignal` system user (never
# root), NodeSignal's own RPC login (an rpcauth line plus an rpcwhitelist of
# the three methods it calls) in bitcoin.conf, and a `nodesignal` command in
# /usr/local/bin. The node's cookie file is never used. Restart bitcoind
# afterwards so it reads the new rpcauth line; this script does not.
#
# Your contacts and messages live in /var/lib/nodesignal/state.json. An older
# install's ~/.nodesignal is copied there once and never touched.
# ===========================================================================
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
SRC="$(pwd)"
DEST=/opt/nodesignal
UNIT=/etc/systemd/system/nodesignal.service

NICK=""
TOKEN=0
ADVERTISE=""
PORTMAP=""
ASK=1
[ -t 0 ] || ASK=0
for a in "$@"; do
  case "$a" in
    --token) TOKEN=1 ;;
    --advertise) ADVERTISE=1 ;;
    --port-mapping) PORTMAP=1 ;;
    --yes) ASK=0 ;;
    --*) echo "Unknown option: $a" >&2; exit 2 ;;
    *) NICK="$a" ;;
  esac
done

echo "NodeSignal installer (from source)"
echo ""

# --- prerequisites -------------------------------------------------------------
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js not found. Install Node.js 18 or newer, then re-run:"
  echo "  sudo apt update && sudo apt install -y nodejs"
  echo "Or use the .deb, which includes its own Node.js (see LinuxInstallGuide.txt)."
  exit 1
fi
NODE_BIN="$(command -v node)"
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "Node.js $(node --version) is too old; NodeSignal needs 18 or newer."
  exit 1
fi
echo "Node.js $(node --version) found at $NODE_BIN."
NODE_COPY=0
case "$(readlink -f "$NODE_BIN")" in
  /home/*|/root/*)
    # nvm and friends: the nodesignal user cannot reach home folders
    # (the unit sets ProtectHome=yes), so the service gets its own copy
    NODE_COPY=1
    echo "That is inside a home folder, which the nodesignal service user cannot reach;"
    echo "a copy of it goes to $DEST/node." ;;
esac

if ! MISSING="$(node setup-core.js --check-files "$SRC")"; then
  echo "ERROR: missing from $SRC: $MISSING"
  echo "Run this from a complete copy of the repository."
  exit 1
fi
FILES="$(node setup-core.js --list-files)"

if dpkg-query -W -f='${Status}' nodesignal 2>/dev/null | grep -q 'install ok installed'; then
  echo "NodeSignal is installed from the .deb package on this machine."
  echo "Upgrade it by installing the newer .deb instead of running this script."
  exit 1
fi

# --- the Bitcoin node ------------------------------------------------------------
DETECT="$(node setup-core.js --detect)"
jget() { printf '%s' "$DETECT" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{const j=JSON.parse(d);const v=process.argv[1].split(".").reduce((o,k)=>o==null?o:o[k],j);console.log(v==null?"":Array.isArray(v)?v.join("; "):v)})' "$1"; }
if [ "$(jget installed)" != "true" ]; then
  cat <<'MSG'
NodeSignal needs a Bitcoin node on this machine, and none was found.

It looked for a running bitcoind or bitcoin-qt, a bitcoind program and a
data directory (~/.bitcoin, /var/lib/bitcoind, /var/lib/bitcoin, /etc/bitcoin).

Install Bitcoin Core (https://bitcoincore.org/en/download/) or Bitcoin Knots
(https://bitcoinknots.org/) first, start it once, then run this again.
Pruned nodes are fine. Nothing was installed.
MSG
  exit 1
fi
echo "Bitcoin node found: $(jget how)"

# --- opt-ins, both off unless chosen ------------------------------------------------
ask_yn() {  # ask_yn "question"  -> 0 for yes; default No
  local a
  read -r -p "$1 [y/N]: " a || true
  case "$a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}
if [ "$ASK" = "1" ]; then
  if [ -z "$ADVERTISE" ]; then
    echo ""
    node -e 'for (const l of require("./setup-core.js").OPT_IN_TEXT.advertise.slice(1)) console.log("  " + l)'
    if ask_yn "Advertise NodeSignal in your node's user agent?"; then ADVERTISE=1; fi
  fi
  if [ -z "$PORTMAP" ]; then
    echo ""
    node -e 'for (const l of require("./setup-core.js").OPT_IN_TEXT.portMapping.slice(1)) console.log("  " + l)'
    if ask_yn "Ask your router to open the NodeSignal peer port (UPnP / NAT-PMP)?"; then PORTMAP=1; fi
  fi
  if [ "$TOKEN" = "0" ]; then
    echo ""
    echo "  A web login token is recommended unless the interface is only on"
    echo "  localhost or a private tailnet."
    if ask_yn "Require a web login token?"; then TOKEN=1; fi
  fi
fi
echo ""

# --- files ---------------------------------------------------------------------------
if [ -f "$UNIT" ]; then
  echo "Existing service found: stopping it for the upgrade..."
  sudo systemctl stop nodesignal 2>/dev/null || true
fi
echo "Installing files to $DEST..."
sudo mkdir -p "$DEST"
for f in $FILES; do sudo install -m 0644 "$SRC/$f" "$DEST/$f"; done
sudo rm -f "$DEST/nodesignal-demo.html"                       # retired demo build
sudo rm -rf "$DEST/node_modules" "$DEST/package-lock.json"    # no dependencies any more
if [ "$NODE_COPY" = "1" ]; then
  sudo install -m 0755 "$(readlink -f "$NODE_BIN")" "$DEST/node"
  NODE_BIN="$DEST/node"
fi

# --- systemd unit (same hardening as the .deb, with the system node) -------------------
MIGRATE=()
if [ -f "$UNIT" ] && ! grep -q 'install-node.sh 1.3' "$UNIT"; then
  # pre-1.3 unit: settings (and maybe a web token) sat on ExecStart; carry them over
  sudo cp "$UNIT" "$UNIT.pre-1.3-backup"
  sudo chmod 600 "$UNIT.pre-1.3-backup"
  MIGRATE=(--migrate-unit "$UNIT.pre-1.3-backup")
fi
sed -e "s#^ExecStart=/opt/nodesignal/node #ExecStart=$NODE_BIN #" \
    -e "1i # Written by install-node.sh 1.3 (from source)." \
    "$SRC/packaging/deb/nodesignal.service" | sudo tee "$UNIT" >/dev/null

SETUP=(setup)
[ -n "$NICK" ] && SETUP+=(--nick "$NICK")
[ "$TOKEN" = "1" ] && SETUP+=(--generate-token)
sudo "$NODE_BIN" "$DEST/cli.js" "${SETUP[@]}" ${MIGRATE[@]+"${MIGRATE[@]}"}

sudo tee /usr/local/bin/nodesignal >/dev/null <<WRAP
#!/bin/sh
# NodeSignal from-source wrapper (written by install-node.sh)
exec "$NODE_BIN" $DEST/cli.js "\$@"
WRAP
sudo chmod 0755 /usr/local/bin/nodesignal

HAVE_SYSTEMD=0
if [ -d /run/systemd/system ]; then
  HAVE_SYSTEMD=1
  sudo systemctl daemon-reload
  sudo systemctl enable nodesignal >/dev/null 2>&1
fi
if [ "$ADVERTISE" = "1" ]; then sudo "$NODE_BIN" "$DEST/cli.js" advertise on; fi
if [ "$PORTMAP" = "1" ]; then sudo "$NODE_BIN" "$DEST/cli.js" port-mapping on >/dev/null; fi

if [ "$HAVE_SYSTEMD" = "1" ]; then
  sudo systemctl restart nodesignal
  echo ""
  "$NODE_BIN" "$DEST/cli.js" status --wait 20 || echo "Not answering yet. Check: journalctl -u nodesignal -n 40"
else
  echo "systemd is not running here, so the service was not started."
fi

echo ""
echo "Commands: nodesignal status | nodesignal open | nodesignal logs"
echo "          sudo nodesignal advertise on|off | sudo nodesignal port-mapping on|off"
echo "          sudo nodesignal rpc-access show|add|remove"
echo "Live log: journalctl -u nodesignal -f"
