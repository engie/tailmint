#!/usr/bin/env bash
set -euo pipefail

echo "Building tailmint-linux-arm64..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags='-s -w' -o tailmint-linux-arm64 .

echo "Building tailmint-linux-amd64..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' -o tailmint-linux-amd64 .

echo "SHA256:"
sha256sum tailmint-linux-arm64 tailmint-linux-amd64
