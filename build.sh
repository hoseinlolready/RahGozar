#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p dist

# A unique version per build so `rahgozar update` can show before -> after.
VERSION="${RAHGOZAR_VERSION:-$(date -u +%Y.%m.%d-%H%M%S)}"
LDFLAGS="-s -w -X main.version=$VERSION -extldflags \"-static\""
TAGS='sqlite_omit_load_extension netgo'

echo "Version: $VERSION"

echo "Building linux/amd64..."
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "$LDFLAGS" -tags "$TAGS" -o dist/rahgozar-linux-amd64 .

echo "Building linux/arm64..."
CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc \
  go build -trimpath -ldflags "$LDFLAGS" -tags "$TAGS" -o dist/rahgozar-linux-arm64 .

echo "Done:"
ls -lh dist/
