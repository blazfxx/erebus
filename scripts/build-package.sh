#!/bin/bash
# Builds the package the Blobby Launcher downloads: the engine, the welcome page and the MCP server in one .tar.gz.
#   scripts/build-package.sh                       -> dist/erebus-<version>-darwin-arm64.tar.gz (builds the engine, macOS)
#   scripts/build-package.sh --engine build/erebus --platform linux-x64   (use an engine you already built)
set -euo pipefail
cd "$(dirname "$0")/.."

ENGINE=""; PLATFORM="darwin-arm64"
while [ $# -gt 0 ]; do case "$1" in
  --engine) ENGINE="$2"; shift 2;;
  --platform) PLATFORM="$2"; shift 2;;
  *) echo "unknown option $1"; exit 2;;
esac; done

VERSION=$(sed -n 's/^project(erebus VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
if [ -z "$ENGINE" ]; then
  echo "==> engine (static Capstone, release)"
  cmake -S . -B build-app -G Ninja -DCMAKE_BUILD_TYPE=Release -DEREBUS_STATIC_CAPSTONE=ON >/dev/null
  cmake --build build-app --target erebus
  ENGINE=build-app/erebus
fi

NAME="erebus-$VERSION-$PLATFORM"
STAGE=$(mktemp -d)/pkg
mkdir -p "$STAGE/bin" "$STAGE/welcome" "$STAGE/mcp" dist
cp "$ENGINE" "$STAGE/bin/erebus"
cp app/welcome/index.html app/welcome/icon.png "$STAGE/welcome/"
cp mcp/erebus-mcp.mjs "$STAGE/mcp/"
cp LICENSE THIRD_PARTY_NOTICES.md "$STAGE/"
cat > "$STAGE/erebus.json" <<J
{ "name": "erebus", "version": "$VERSION", "platform": "$PLATFORM", "engine": "bin/erebus", "welcome": "welcome/index.html", "mcp": "mcp/erebus-mcp.mjs" }
J
if [ "$(uname)" = "Darwin" ]; then
  xattr -cr "$STAGE"
  codesign --force --sign - "$STAGE/bin/erebus"
fi
rm -f "dist/$NAME.tar.gz"
tar -czf "dist/$NAME.tar.gz" -C "$STAGE" .
echo "==> dist/$NAME.tar.gz ($(du -h "dist/$NAME.tar.gz" | cut -f1))"
