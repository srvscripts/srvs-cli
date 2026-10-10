#!/bin/sh
# Install srvs (https://github.com/srvscripts/srvs-cli) from the GitHub releases, checking the SHA-256 checksum.
#   curl -fsSL https://raw.githubusercontent.com/srvscripts/srvs-cli/main/scripts/install.sh | sh
# Options (environment): SRVS_VERSION=v0.1.0 (default: latest)   BINDIR=/usr/local/bin (default: /usr/local/bin if
# writable, otherwise ~/.local/bin)
set -eu

REPO=srvscripts/srvs-cli
VERSION=${SRVS_VERSION:-latest}

err() { echo "srvs install: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "needs $1"; }
need curl; need tar; need uname

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) err "unsupported system $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) err "unsupported CPU $(uname -m)" ;;
esac

if [ "$VERSION" = latest ]; then
  url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") || err "cannot reach GitHub"
  VERSION=${url##*/}
fi
case "$VERSION" in v*) ;; *) err "could not find the latest release (got '$VERSION')" ;; esac

name="srvs_${VERSION#v}_${os}_${arch}"
base="https://github.com/$REPO/releases/download/$VERSION"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading srvs $VERSION for $os/$arch..."
curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz" || err "download failed: $base/$name.tar.gz"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || err "checksum file download failed"

want=$(grep " $name.tar.gz\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
[ -n "$want" ] || err "no checksum for $name.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then got=$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)
else err "needs sha256sum or shasum to verify the download"; fi
[ "$want" = "$got" ] || err "checksum mismatch: expected $want, got $got"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"

if [ -z "${BINDIR:-}" ]; then
  if [ -w /usr/local/bin ] || [ "$(id -u)" = 0 ]; then BINDIR=/usr/local/bin; else BINDIR="$HOME/.local/bin"; fi
fi
mkdir -p "$BINDIR"
install -m 0755 "$tmp/$name/srvs" "$BINDIR/srvs" 2>/dev/null || { cp "$tmp/$name/srvs" "$BINDIR/srvs" && chmod 0755 "$BINDIR/srvs"; }

echo "Installed $("$BINDIR/srvs" version) to $BINDIR/srvs"
case ":$PATH:" in *":$BINDIR:"*) ;; *) echo "Note: $BINDIR is not in your PATH. Add it, or run $BINDIR/srvs" ;; esac
echo "Try: srvs check example.com"
