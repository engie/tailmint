#!/usr/bin/env bash
set -euo pipefail

VERSION=${1:?Usage: release.sh <version>}

echo "Building tailpod-mint-key-linux-arm64..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags='-s -w' -o tailpod-mint-key-linux-arm64 .

echo "SHA256:"
sha256sum tailpod-mint-key-linux-arm64

echo "Creating release v${VERSION}..."
gh release create "v${VERSION}" tailpod-mint-key-linux-arm64 --title "v${VERSION}"
