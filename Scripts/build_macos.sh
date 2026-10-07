#!/bin/bash
# Developer-only research build. This script is not a consumer installer.
set -euo pipefail
if [[ "$(/usr/bin/uname -s)" != "Darwin" ]]; then
    echo "Requires an authorized macOS build host; no changes made." >&2
    exit 1
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TASK_GO="${LEGACYWG_GO:-}"
if [[ -z "$TASK_GO" || ! -x "$TASK_GO" ]]; then
    echo "Set LEGACYWG_GO to the verified project-local Go 1.24.13 binary." >&2
    exit 1
fi
if [[ "$("$TASK_GO" version)" != "go version go1.24.13 darwin/amd64" ]]; then
    echo "Research target requires pinned Go 1.24.13 darwin/amd64." >&2
    exit 1
fi
export GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 GOAMD64=v1
export GOCACHE="$ROOT/.cache/macos-build" GOMODCACHE="$ROOT/.cache/gomod"
mkdir -p "$ROOT/Build/Research" "$ROOT/Docs/Evidence/Mac"
for label in baseline candidate; do
    (
        cd "$ROOT/Vendor/wireguard-$label"
        "$TASK_GO" mod verify
        "$TASK_GO" build -trimpath -buildvcs=false -o "$ROOT/Build/Research/wireguard-go-$label-darwin-amd64" .
    )
done
cd "$ROOT"
"$TASK_GO" test -count=1 ./ConfigCore ./NetworkCore
"$TASK_GO" build -trimpath -buildvcs=false -o "$ROOT/Build/Research/legacywg-native-smoke-darwin-amd64" ./Engine/smoke
/usr/bin/sw_vers > "$ROOT/Docs/Evidence/Mac/os.txt"
/usr/bin/uname -m > "$ROOT/Docs/Evidence/Mac/architecture.txt"
if /usr/bin/xcrun --find clang >/dev/null 2>&1; then
    /usr/bin/xcrun clang --version > "$ROOT/Docs/Evidence/Mac/clang.txt"
    /usr/bin/xcrun --sdk macosx --show-sdk-version > "$ROOT/Docs/Evidence/Mac/sdk.txt"
fi
for target in "$ROOT"/Build/Research/*-darwin-amd64; do
    /usr/bin/otool -L "$target" > "$ROOT/Docs/Evidence/Mac/$(basename "$target")-libraries.txt"
    /usr/bin/otool -l "$target" > "$ROOT/Docs/Evidence/Mac/$(basename "$target")-commands.txt"
    /usr/bin/shasum -a 256 "$target"
done
echo "Research binaries built. No app, helper, signing, installation or VPN session has been produced."
