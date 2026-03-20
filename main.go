package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Hostname is a validated DNS-label hostname. Construct only via parseHostname.
type Hostname string

// OutputPath is a validated output file path. Construct only via parseOutputPath.
type OutputPath string

type config struct {
	ClientID     string
	ClientSecret string
	Tailnet      string
	Expiry       int
	Ephemeral    bool
	Reusable     bool
	Preauthorized bool
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

type createKeyRequest struct {
	Capabilities capabilities `json:"capabilities"`
	ExpirySeconds int         `json:"expirySeconds"`
	Description   string      `json:"description,omitempty"`
}

type capabilities struct {
	Devices deviceCaps `json:"devices"`
}

type deviceCaps struct {
	Create createCaps `json:"create"`
}

type createCaps struct {
	Reusable      bool     `json:"reusable"`
	Ephemeral     bool     `json:"ephemeral"`
	Preauthorized bool     `json:"preauthorized"`
	Tags          []string `json:"tags"`
}

type keyResponse struct {
	Key string `json:"key"`
}

// Overridable for testing
var (
	oauthTokenURL = "https://api.tailscale.com/api/v2/oauth/token"
	createKeyURL  = func(tailnet string) string {
		return fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/keys", tailnet)
	}
	httpClient   = &http.Client{Timeout: 30 * time.Second}
	sysSetuid    = syscall.Setuid
	sysSetgid    = syscall.Setgid
	sysSetgroups = syscall.Setgroups
	osGetuid     = os.Getuid
	userLookupId = user.LookupId
)

func main() {
	configFile := flag.String("config", "/etc/tailscale/oauth.env", "Path to OAuth config env file")
	tag := flag.String("tag", "", "Tag to apply (e.g. tag:tailpod)")
	output := flag.String("output", "", "Output file for TS_AUTHKEY=... env file")
	hostname := flag.String("hostname", "", "Hostname to include as TS_HOSTNAME=...")
	flag.Parse()

	if *tag == "" {
		fmt.Fprintln(os.Stderr, "error: -tag is required")
		os.Exit(2)
	}
	if *output == "" {
		fmt.Fprintln(os.Stderr, "error: -output is required")
		os.Exit(2)
	}

	host, err := parseHostname(*hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	outPath, err := parseOutputPath(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	cfg, err := loadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := dropPrivileges(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	authKey, err := mintKey(cfg, *tag, host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := writeOutput(outPath, authKey, host); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("reading config %s: %w", path, err)
	}

	env := parseEnvFile(string(data))
	c := config{
		ClientID:      env["TS_API_CLIENT_ID"],
		ClientSecret:  env["TS_API_CLIENT_SECRET"],
		Tailnet:       env["TS_TAILNET"],
		Expiry:        3600,
		Ephemeral:     true,
		Reusable:      false,
		Preauthorized: true,
	}

	if c.ClientID == "" {
		return config{}, fmt.Errorf("TS_API_CLIENT_ID not set in %s", path)
	}
	if c.ClientSecret == "" {
		return config{}, fmt.Errorf("TS_API_CLIENT_SECRET not set in %s", path)
	}
	if c.Tailnet == "" {
		c.Tailnet = "-"
	}
	if v, ok := env["TS_KEY_EXPIRY_SECONDS"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			c.Expiry = n
		}
	}
	if v, ok := env["TS_KEY_EPHEMERAL"]; ok {
		c.Ephemeral = v == "true"
	}
	if v, ok := env["TS_KEY_REUSABLE"]; ok {
		c.Reusable = v == "true"
	}
	if v, ok := env["TS_KEY_PREAUTHORIZED"]; ok {
		c.Preauthorized = v == "true"
	}

	return c, nil
}

func parseEnvFile(data string) map[string]string {
	env := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "="); idx >= 0 {
			val := strings.TrimSpace(line[idx+1:])
			val = unquote(val)
			env[strings.TrimSpace(line[:idx])] = val
		}
	}
	return env
}

// unquote strips matching single or double quotes from a value.
func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

func dropPrivileges() error {
	if osGetuid() != 0 {
		return nil // not root, nothing to do
	}

	uidStr := os.Getenv("SUDO_UID")
	gidStr := os.Getenv("SUDO_GID")
	if uidStr == "" || gidStr == "" {
		return fmt.Errorf("running as root without SUDO_UID/SUDO_GID; refusing to continue as bare root")
	}

	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return fmt.Errorf("invalid SUDO_UID %q: %w", uidStr, err)
	}
	gid, err := strconv.Atoi(gidStr)
	if err != nil {
		return fmt.Errorf("invalid SUDO_GID %q: %w", gidStr, err)
	}

	// Look up supplementary groups for the user
	var gids []int
	u, err := userLookupId(uidStr)
	if err == nil {
		groupIDs, err := u.GroupIds()
		if err == nil {
			for _, g := range groupIDs {
				if id, err := strconv.Atoi(g); err == nil {
					gids = append(gids, id)
				}
			}
		}
	}
	// If lookup failed, fall back to just the primary GID
	if len(gids) == 0 {
		gids = []int{gid}
	}

	// Order matters: setgroups before setgid before setuid
	if err := sysSetgroups(gids); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := sysSetgid(gid); err != nil {
		return fmt.Errorf("setgid(%d): %w", gid, err)
	}
	if err := sysSetuid(uid); err != nil {
		return fmt.Errorf("setuid(%d): %w", uid, err)
	}

	return nil
}

func mintKey(cfg config, tag string, hostname Hostname) (string, error) {
	// Step 1: Get OAuth access token
	accessToken, err := getAccessToken(cfg)
	if err != nil {
		return "", fmt.Errorf("getting access token: %w", err)
	}

	// Step 2: Create auth key
	desc := "minted-by-quadlet-deploy"
	if hostname != "" {
		desc = string(hostname)
	}

	reqBody := createKeyRequest{
		Capabilities: capabilities{
			Devices: deviceCaps{
				Create: createCaps{
					Reusable:      cfg.Reusable,
					Ephemeral:     cfg.Ephemeral,
					Preauthorized: cfg.Preauthorized,
					Tags:          []string{tag},
				},
			},
		},
		ExpirySeconds: cfg.Expiry,
		Description:   desc,
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", createKeyURL(cfg.Tailnet), strings.NewReader(string(bodyJSON)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("creating auth key: %w", err)
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("create key API returned %d: %s", resp.StatusCode, body)
	}
	if readErr != nil {
		return "", fmt.Errorf("reading create key response: %w", readErr)
	}

	var keyResp keyResponse
	if err := json.Unmarshal(body, &keyResp); err != nil {
		return "", fmt.Errorf("parsing key response: %w", err)
	}
	if keyResp.Key == "" {
		return "", fmt.Errorf("empty key in response: %s", body)
	}

	return keyResp.Key, nil
}

func getAccessToken(cfg config) (string, error) {
	data := url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
	}

	resp, err := httpClient.PostForm(oauthTokenURL, data)
	if err != nil {
		return "", fmt.Errorf("OAuth token request: %w", err)
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OAuth token API returned %d: %s", resp.StatusCode, body)
	}
	if readErr != nil {
		return "", fmt.Errorf("reading OAuth token response: %w", readErr)
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access_token in response: %s", body)
	}

	return tokenResp.AccessToken, nil
}

// parseHostname validates and returns a Hostname. Rejects values that could
// inject extra lines into the output env file or abuse the sudoers wildcard
// on -hostname *. Only allows characters valid in DNS labels: alphanumeric
// plus hyphens. Empty is allowed (hostname is optional).
func parseHostname(h string) (Hostname, error) {
	if h == "" {
		return "", nil
	}
	for _, c := range h {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return "", fmt.Errorf("hostname contains invalid character %q: %s", c, h)
		}
	}
	if h[0] == '-' || h[len(h)-1] == '-' {
		return "", fmt.Errorf("hostname must not start or end with a hyphen: %s", h)
	}
	return Hostname(h), nil
}

// parseOutputPath validates and returns an OutputPath. sudoers glob wildcards
// match "/" so they can't prevent path traversal on their own (e.g.
// /run/user/../../etc/shadow.env would match the sudoers pattern). This
// function is the precise inner check; the sudoers rule is the coarse outer fence.
func parseOutputPath(path string) (OutputPath, error) {
	// Check for ".." before Clean, since Clean resolves traversals away
	// in absolute paths, which would hide the attack.
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("output path must not contain '..': %s", path)
		}
	}

	cleaned := filepath.Clean(path)

	// Must be absolute
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("output path must be absolute: %s", path)
	}

	// Must live under /run/user/<numeric-uid>/ts-authkeys/ and end in .env
	parts := strings.Split(cleaned, string(filepath.Separator))
	// cleaned absolute path splits as: ["", "run", "user", "<uid>", "ts-authkeys", "<name>.env"]
	if len(parts) != 6 ||
		parts[1] != "run" ||
		parts[2] != "user" ||
		parts[4] != "ts-authkeys" {
		return "", fmt.Errorf("output path must match /run/user/<uid>/ts-authkeys/<name>.env: %s", path)
	}

	// UID component must be numeric
	if _, err := strconv.Atoi(parts[3]); err != nil {
		return "", fmt.Errorf("output path UID component must be numeric: %s", parts[3])
	}

	// Filename must end in .env and contain no further path separators (Clean already handled that)
	if !strings.HasSuffix(parts[5], ".env") {
		return "", fmt.Errorf("output path must end in .env: %s", path)
	}

	return OutputPath(cleaned), nil
}

func writeOutput(path OutputPath, authKey string, hostname Hostname) error {
	dir := filepath.Dir(string(path))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(string(path))+".tmp.*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()

	content := fmt.Sprintf("TS_AUTHKEY=%s\n", authKey)
	if hostname != "" {
		content += fmt.Sprintf("TS_HOSTNAME=%s\n", hostname)
	}

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("setting permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Rename(tmpPath, string(path)); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming temp file: %w", err)
	}

	return nil
}

