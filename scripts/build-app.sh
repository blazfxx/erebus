#!/bin/bash
# Builds a self-contained Erebus.app (arm64) into dist/.
#   scripts/build-app.sh            -> dist/Erebus.app
#   scripts/build-app.sh --zip      -> also dist/Erebus-<version>-macos-arm64.zip
#   scripts/build-app.sh --dmg      -> also dist/Erebus-<version>-macos-arm64.dmg
# Requires: Xcode command line tools, CMake, Ninja, and `brew install capstone cpp-httplib nlohmann-json`.
set -euo pipefail
cd "$(dirname "$0")/.."

ZIP=0; DMG=0
for a in "$@"; do case "$a" in --zip) ZIP=1;; --dmg) DMG=1;; *) echo "unknown option $a"; exit 2;; esac; done

VERSION=$(sed -n 's/^project(erebus VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
DIST=dist
APP="$DIST/Erebus.app"
echo "==> Erebus $VERSION"

echo "==> engine (static Capstone, release)"
cmake -S . -B build-app -G Ninja -DCMAKE_BUILD_TYPE=Release -DEREBUS_STATIC_CAPSTONE=ON >/dev/null
cmake --build build-app --target erebus

echo "==> app shell"
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/bin"
swiftc -O app/main.swift -o "$APP/Contents/MacOS/Erebus" -framework Cocoa -framework WebKit
cp build-app/erebus "$APP/Contents/Resources/bin/erebus"
mkdir -p "$APP/Contents/Resources/welcome"
cp app/welcome/index.html app/welcome/icon.png "$APP/Contents/Resources/welcome/"
cp LICENSE "$APP/Contents/Resources/LICENSE"
cp THIRD_PARTY_NOTICES.md "$APP/Contents/Resources/THIRD_PARTY_NOTICES.md"
sed "s/@VERSION@/$VERSION/g" app/Info.plist.in > "$APP/Contents/Info.plist"

echo "==> icon"
# The icon is drawn in app/AppIcon.svg and rendered into app/AppIcon.iconset.
iconutil -c icns app/AppIcon.iconset -o "$APP/Contents/Resources/AppIcon.icns"

echo "==> ad-hoc sign"
xattr -cr "$APP"
codesign --force --sign - "$APP/Contents/Resources/bin/erebus"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP" && echo "signature ok"

NAME="Erebus-$VERSION-macos-arm64"
if [ $ZIP = 1 ]; then
  rm -f "$DIST/$NAME.zip"; ditto -c -k --keepParent "$APP" "$DIST/$NAME.zip"; echo "==> $DIST/$NAME.zip"
fi
if [ $DMG = 1 ]; then
  STAGE=$(mktemp -d); cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
  rm -f "$DIST/$NAME.dmg"; hdiutil create -quiet -volname "Erebus" -srcfolder "$STAGE" -ov -format UDZO "$DIST/$NAME.dmg"; echo "==> $DIST/$NAME.dmg"
fi
echo "==> done: $APP"
