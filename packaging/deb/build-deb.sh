#!/usr/bin/env bash
# build-deb.sh: build the NodeSignal .deb with its own Node.js runtime.
# ===========================================================================
# Runs on: a Linux build machine (the GitHub Actions Ubuntu runner, or any
# Debian/Ubuntu box) with bash, curl, tar, xz, sha256sum, dpkg-deb and node
# (node only reads packaging/files.json; it is not what gets shipped).
#
#   packaging/deb/build-deb.sh <version> <amd64|arm64>
#
# Produces, in dist/ (or $DIST_DIR):
#   nodesignal-linux-<arch>.deb          stable name for releases/latest/download
#   nodesignal_<version>_<arch>.deb      versioned copy
#
# The Node.js runtime is the official linux tarball from nodejs.org for the
# target arch, verified against that release's SHASUMS256.txt before use.
#   NODE_VERSION   e.g. v22.22.0 (default: latest-v22.x, the newest 22 LTS)
#   NODE_CACHE_DIR reuse downloaded tarballs from this folder (still verified)
#   SRC_DIR        repository to package (default: this checkout)
#   DIST_DIR       output folder (default: <repo>/dist)
#   MAINTAINER     Maintainer field for DEBIAN/control
# ===========================================================================
set -euo pipefail

die() { echo "build-deb: $*" >&2; exit 1; }

VERSION="${1:-}"
ARCH="${2:-}"
[ -n "$VERSION" ] && [ -n "$ARCH" ] || die "usage: $0 <version> <amd64|arm64>"
VERSION="${VERSION#v}"
[[ "$VERSION" =~ ^[0-9][0-9A-Za-z.+~-]*$ ]] || die "version must start with a digit (got '$VERSION')"
case "$ARCH" in
  amd64) NODE_ARCH=x64 ;;
  arm64) NODE_ARCH=arm64 ;;
  *) die "arch must be amd64 or arm64 (got '$ARCH')" ;;
esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "${SRC_DIR:-$HERE/../..}" && pwd)"
DIST="${DIST_DIR:-$SRC/dist}"
NODE_LINE="${NODE_VERSION:-latest-v22.x}"
MAINTAINER="${MAINTAINER:-NodeSignal project <https://github.com/Connor-03/NodeSignal/issues>}"

for tool in curl tar xz sha256sum dpkg-deb node; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

# --- the one file list -------------------------------------------------------
FILES="$(node -e '
  const f = require(process.argv[1]);
  console.log([...f.daemon, ...f.tools].join("\n"));
' "$SRC/packaging/files.json")"
missing=""
for f in $FILES; do [ -f "$SRC/$f" ] || missing="$missing $f"; done
[ -z "$missing" ] || die "missing file(s) listed in packaging/files.json:$missing"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- Node.js runtime, verified ----------------------------------------------
case "$NODE_LINE" in
  latest-*) BASE="https://nodejs.org/dist/$NODE_LINE" ;;
  *)        BASE="https://nodejs.org/dist/v${NODE_LINE#v}" ;;
esac
DL="$WORK/download"          # downloads go in their own empty folder
mkdir "$DL"
curl -fsSL --retry 3 -o "$DL/SHASUMS256.txt" "$BASE/SHASUMS256.txt"
TARBALL="$(awk -v want="linux-$NODE_ARCH.tar.xz" '$2 ~ ("^node-v[0-9.]+-" want "$") { print $2; exit }' "$DL/SHASUMS256.txt")"
[ -n "$TARBALL" ] || die "no linux-$NODE_ARCH tarball listed in $BASE/SHASUMS256.txt"
NODE_DIR="${TARBALL%.tar.xz}"

if [ -n "${NODE_CACHE_DIR:-}" ] && [ -f "$NODE_CACHE_DIR/$TARBALL" ]; then
  cp "$NODE_CACHE_DIR/$TARBALL" "$DL/$TARBALL"
else
  curl -fsSL --retry 3 -o "$DL/$TARBALL" "$BASE/$TARBALL"
fi
( cd "$DL" && grep -E "  $TARBALL\$" SHASUMS256.txt | sha256sum -c --status - ) \
  || die "SHA256 of $TARBALL does not match SHASUMS256.txt"
echo "build-deb: $TARBALL verified against SHASUMS256.txt"
if [ -n "${NODE_CACHE_DIR:-}" ]; then mkdir -p "$NODE_CACHE_DIR"; cp -n "$DL/$TARBALL" "$NODE_CACHE_DIR/" 2>/dev/null || true; fi

mkdir "$WORK/node"
tar -xJf "$DL/$TARBALL" -C "$WORK/node" --strip-components=1 "$NODE_DIR/bin/node" "$NODE_DIR/LICENSE"

# --- package tree -------------------------------------------------------------
PKG="$WORK/pkg"
OPT="$PKG/opt/nodesignal"
install -d "$PKG/DEBIAN" "$OPT" "$PKG/usr/bin" "$PKG/lib/systemd/system" "$PKG/usr/share/doc/nodesignal"
install -m 0755 "$WORK/node/bin/node" "$OPT/node"
install -m 0644 "$WORK/node/LICENSE" "$OPT/node-LICENSE"
for f in $FILES; do install -m 0644 "$SRC/$f" "$OPT/$f"; done
printf '%s\n' "$VERSION" > "$OPT/VERSION"
chmod 0644 "$OPT/VERSION"

cat > "$PKG/usr/bin/nodesignal" <<'WRAP'
#!/bin/sh
# nodesignal: command-line helper for the NodeSignal daemon. See: nodesignal help
exec /opt/nodesignal/node /opt/nodesignal/cli.js "$@"
WRAP
chmod 0755 "$PKG/usr/bin/nodesignal"

install -m 0644 "$HERE/nodesignal.service" "$PKG/lib/systemd/system/nodesignal.service"
{
  echo "NodeSignal"
  echo "Source: https://github.com/Connor-03/NodeSignal"
  echo ""
  cat "$SRC/LICENSE"
  echo ""
  echo "The bundled Node.js runtime (/opt/nodesignal/node) is distributed under"
  echo "its own license, included as /opt/nodesignal/node-LICENSE."
} > "$PKG/usr/share/doc/nodesignal/copyright"
chmod 0644 "$PKG/usr/share/doc/nodesignal/copyright"

for s in preinst postinst prerm postrm; do install -m 0755 "$HERE/$s" "$PKG/DEBIAN/$s"; done

INSTALLED_KB="$(du -sk --exclude=DEBIAN "$PKG" | cut -f1)"
cat > "$PKG/DEBIAN/control" <<CTRL
Package: nodesignal
Version: $VERSION
Architecture: $ARCH
Maintainer: $MAINTAINER
Installed-Size: $INSTALLED_KB
Depends: libc6 (>= 2.28), libstdc++6, libgcc-s1 | libgcc1
Recommends: tor
Section: net
Priority: optional
Homepage: https://github.com/Connor-03/NodeSignal
Description: encrypted chat between Bitcoin node operators
 NodeSignal runs beside Bitcoin Core or Bitcoin Knots on the same machine
 and refuses to install without one. It reads the node's peer list over
 read-only RPC, identifies peers with a read-only version handshake on port
 8333, and carries messages on its own Noise-encrypted channel (TCP 8788),
 never over the Bitcoin P2P network. Message history is stored in the clear
 unless a history passphrase is set.
 Includes its own Node.js runtime (${NODE_DIR}).
CTRL

mkdir -p "$DIST"
OUT_VER="$DIST/nodesignal_${VERSION}_${ARCH}.deb"
OUT="$DIST/nodesignal-linux-${ARCH}.deb"
# xz rather than the zstd default, so older dpkg (Debian 11, Raspberry Pi OS
# bullseye) can still read the package.
dpkg-deb -Zxz --root-owner-group --build "$PKG" "$OUT_VER" >/dev/null
cp "$OUT_VER" "$OUT"
echo "build-deb: built $OUT ($(du -h "$OUT" | cut -f1))"
echo "build-deb: built $OUT_VER"
sha256sum "$OUT" "$OUT_VER"
