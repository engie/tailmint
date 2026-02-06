# tailmint

A small CLI tool that mints short-lived [Tailscale](https://tailscale.com) auth keys using the OAuth API. Designed to run as a systemd/Quadlet pre-start step so containers can join your tailnet without long-lived keys.

## How it works

1. Reads OAuth credentials from an env file (default `/etc/tailscale/oauth.env`)
2. Exchanges them for an access token via the Tailscale OAuth endpoint
3. Creates a device auth key with the specified tag and capabilities
4. Writes `TS_AUTHKEY=...` (and optionally `TS_HOSTNAME=...`) to an output file with `0600` permissions

The output file can then be passed to `tailscale up --authkey` or loaded as a container environment file.

## Install

Download a pre-built binary from [Releases](../../releases), or build from source:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags='-s -w' -o tailmint .
```

## Usage

```bash
tailmint -tag tag:tailpod -output /run/tailscale/authkey.env
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | `/etc/tailscale/oauth.env` | Path to OAuth credentials env file |
| `-tag` | *(required)* | ACL tag to apply (e.g. `tag:tailpod`) |
| `-output` | *(required)* | Path to write the `TS_AUTHKEY=...` env file |
| `-hostname` | | If set, also writes `TS_HOSTNAME=...` to the output |

### Config file

Create `/etc/tailscale/oauth.env` (or wherever `-config` points):

```env
TS_API_CLIENT_ID=your-oauth-client-id
TS_API_CLIENT_SECRET=your-oauth-client-secret

# Optional:
TS_TAILNET=example.com          # default: "-" (auto-detect)
TS_KEY_EXPIRY_SECONDS=3600      # default: 3600
TS_KEY_EPHEMERAL=true           # default: true
TS_KEY_REUSABLE=false           # default: false
TS_KEY_PREAUTHORIZED=true       # default: true
```

### Example: Quadlet container

Run tailmint before your Tailscale sidecar starts:

```ini
# /etc/containers/systemd/myapp-ts.container
[Unit]
Requires=tailmint@myapp.service
After=tailmint@myapp.service

[Container]
Image=ghcr.io/tailscale/tailscale:latest
EnvironmentFile=/run/tailscale/myapp.env
```

## License

MIT
