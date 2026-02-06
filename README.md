# tailmint

A small Go CLI that mints short-lived [Tailscale](https://tailscale.com) auth keys using the OAuth API. Run it as an `ExecStartPre` in a systemd unit so each container gets a fresh, ephemeral key at startup.

## How it works

1. Reads OAuth client credentials from an env file (default `/etc/tailscale/oauth.env`)
2. Exchanges them for a short-lived access token via the Tailscale OAuth endpoint
3. Creates an ephemeral device auth key scoped to a tag
4. Writes an env file containing `TS_AUTHKEY` and (optionally) `TS_HOSTNAME`

The output env file is loaded by the container runtime. The container's network tool (e.g. [ts4nsnet](https://github.com/engie/ts4nsnet)) reads `TS_AUTHKEY` to authenticate with Tailscale and `TS_HOSTNAME` to register the node name on the tailnet.

## Build

No external dependencies — stdlib only.

```bash
# arm64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags='-s -w' -o tailmint-linux-arm64 .

# x86_64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' -o tailmint-linux-amd64 .
```

Pre-built arm64 binaries are available on the [Releases](../../releases) page.

## Usage

```bash
sudo tailmint \
  -config /etc/tailscale/oauth.env \
  -tag tag:tailpod \
  -output /run/user/1000/ts-authkeys/myapp.env \
  -hostname myapp
```

This writes:

```env
TS_AUTHKEY=tskey-auth-...
TS_HOSTNAME=myapp
```

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | `/etc/tailscale/oauth.env` | Path to OAuth credentials env file |
| `-tag` | *(required)* | Tailscale ACL tag (must match the OAuth client's allowed tags) |
| `-output` | *(required)* | Path to write the output env file |
| `-hostname` | | Node name on the tailnet; also written as `TS_HOSTNAME` |

### Output variables

| Variable | Description |
|----------|-------------|
| `TS_AUTHKEY` | Ephemeral Tailscale auth key. Consumed by `tailscale up --authkey` or a tsnet-based tool like [ts4nsnet](https://github.com/engie/ts4nsnet) to join the tailnet. Single-use by default. |
| `TS_HOSTNAME` | The hostname the device registers under on the tailnet (e.g. `myapp` becomes `myapp.tailnet-name.ts.net`). Only written when `-hostname` is provided. |

### Config file

Create `/etc/tailscale/oauth.env` with your [Tailscale OAuth client](https://tailscale.com/kb/1215/oauth-clients) credentials:

```env
TS_API_CLIENT_ID=your-oauth-client-id
TS_API_CLIENT_SECRET=tskey-client-...

# Optional overrides:
TS_TAILNET=example.com          # default: "-" (auto-detect)
TS_KEY_EXPIRY_SECONDS=3600      # default: 3600
TS_KEY_EPHEMERAL=true           # default: true
TS_KEY_REUSABLE=false           # default: false
TS_KEY_PREAUTHORIZED=true       # default: true
```

### Example: Quadlet ExecStartPre

tailmint is designed to run as an `ExecStartPre` step in a container's systemd unit. Each container startup mints a fresh key:

```ini
[Service]
ExecStartPre=mkdir -p %t/ts-authkeys
ExecStartPre=sudo tailmint -config /etc/tailscale/oauth.env -tag tag:tailpod -output %t/ts-authkeys/%N.env -hostname %N
EnvironmentFile=-%t/ts-authkeys/%N.env
```

The container then starts with `TS_AUTHKEY` and `TS_HOSTNAME` in its environment. If using rootless Podman, you'll need a sudoers rule:

```
%cusers ALL=(root) NOPASSWD: /usr/local/bin/tailmint
```

## License

MIT
