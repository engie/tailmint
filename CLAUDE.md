# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A single-binary Go CLI tool that mints short-lived Tailscale auth keys via the Tailscale OAuth API. It reads OAuth credentials from an env file, exchanges them for an access token, then creates a device auth key and writes it to an output file. Designed to run as a systemd/Quadlet pre-start step for containerized Tailscale sidecars.

## Build & Test Commands

```bash
# Build (static binary, linux/arm64)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags='-s -w' -o tailmint-linux-arm64 .

# Run all tests
go test ./...

# Run a single test
go test -run TestMintKeySuccess ./...

# Release (requires gh CLI, creates GitHub release)
./release.sh <version>
```

## Architecture

Single-file `main.go` with no external dependencies (stdlib only). The flow is:

1. `loadConfig` — reads an env file (default `/etc/tailscale/oauth.env`) with `TS_API_CLIENT_ID`, `TS_API_CLIENT_SECRET`, and optional config vars
2. `getAccessToken` — POST to Tailscale OAuth token endpoint
3. `mintKey` — POST to Tailscale create-key API using the access token
4. `writeOutput` — atomic write (temp file + rename) of `TS_AUTHKEY=...` env file with 0600 permissions; chowns to `SUDO_UID`/`SUDO_GID` if running under sudo

Tests use `httptest` servers and override the package-level `oauthTokenURL` and `createKeyURL` vars to mock the Tailscale API.
