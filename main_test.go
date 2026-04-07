package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMintKeySuccess(t *testing.T) {
	// Mock OAuth token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		r.ParseForm()
		if r.Form.Get("client_id") != "test-id" {
			t.Errorf("unexpected client_id: %s", r.Form.Get("client_id"))
		}
		if r.Form.Get("client_secret") != "test-secret" {
			t.Errorf("unexpected client_secret: %s", r.Form.Get("client_secret"))
		}
		json.NewEncoder(w).Encode(tokenResponse{AccessToken: "test-token"})
	}))
	defer tokenServer.Close()

	// Mock create key endpoint
	keyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("unexpected auth header: %s", auth)
		}

		var req createKeyRequest
		json.NewDecoder(r.Body).Decode(&req)
		if !req.Capabilities.Devices.Create.Ephemeral {
			t.Error("expected ephemeral=true")
		}
		if len(req.Capabilities.Devices.Create.Tags) != 1 || req.Capabilities.Devices.Create.Tags[0] != "tag:tailpod" {
			t.Errorf("unexpected tags: %v", req.Capabilities.Devices.Create.Tags)
		}

		json.NewEncoder(w).Encode(keyResponse{Key: "tskey-auth-test123"})
	}))
	defer keyServer.Close()

	// Override URLs
	origTokenURL := oauthTokenURL
	origKeyURL := createKeyURL
	oauthTokenURL = tokenServer.URL
	createKeyURL = func(tailnet string) string { return keyServer.URL }
	defer func() {
		oauthTokenURL = origTokenURL
		createKeyURL = origKeyURL
	}()

	cfg := config{
		ClientID:      "test-id",
		ClientSecret:  "test-secret",
		Tailnet:       "-",
		Expiry:        3600,
		Ephemeral:     true,
		Preauthorized: true,
	}

	key, err := mintKey(cfg, "tag:tailpod", Hostname("nginx-demo"))
	if err != nil {
		t.Fatalf("mintKey error: %v", err)
	}
	if key != "tskey-auth-test123" {
		t.Errorf("unexpected key: %s", key)
	}
}

func TestMintKeyOAuthError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer tokenServer.Close()

	origTokenURL := oauthTokenURL
	oauthTokenURL = tokenServer.URL
	defer func() { oauthTokenURL = origTokenURL }()

	cfg := config{
		ClientID:     "bad-id",
		ClientSecret: "bad-secret",
		Tailnet:      "-",
	}

	_, err := mintKey(cfg, "tag:tailpod", Hostname("test"))
	if err == nil {
		t.Fatal("expected error for OAuth failure")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should mention 400: %v", err)
	}
}

func TestMintKeyAPIError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(tokenResponse{AccessToken: "test-token"})
	}))
	defer tokenServer.Close()

	keyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message":"tag not allowed"}`))
	}))
	defer keyServer.Close()

	origTokenURL := oauthTokenURL
	origKeyURL := createKeyURL
	oauthTokenURL = tokenServer.URL
	createKeyURL = func(tailnet string) string { return keyServer.URL }
	defer func() {
		oauthTokenURL = origTokenURL
		createKeyURL = origKeyURL
	}()

	cfg := config{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		Tailnet:      "-",
	}

	_, err := mintKey(cfg, "tag:wrong", Hostname("test"))
	if err == nil {
		t.Fatal("expected error for API failure")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should mention 400: %v", err)
	}
}

func TestWriteOutput(t *testing.T) {
	outPath := OutputPath(fmt.Sprintf("/run/user/%d/ts-authkeys/nginx-demo.env", os.Getuid()))

	err := writeOutput(outPath, "tskey-test123", Hostname("nginx-demo"))
	if err != nil {
		t.Fatalf("writeOutput error: %v", err)
	}
	defer os.Remove(string(outPath))

	data, err := os.ReadFile(string(outPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "TS_AUTHKEY=tskey-test123") {
		t.Error("output should contain TS_AUTHKEY")
	}
	if !strings.Contains(content, "TS_HOSTNAME=nginx-demo") {
		t.Error("output should contain TS_HOSTNAME")
	}

	info, _ := os.Stat(string(outPath))
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %o", info.Mode().Perm())
	}
}

func TestWriteOutputNoHostname(t *testing.T) {
	outPath := OutputPath(fmt.Sprintf("/run/user/%d/ts-authkeys/test.env", os.Getuid()))

	err := writeOutput(outPath, "tskey-test123", "")
	if err != nil {
		t.Fatalf("writeOutput error: %v", err)
	}
	defer os.Remove(string(outPath))

	data, err := os.ReadFile(string(outPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "TS_AUTHKEY=tskey-test123") {
		t.Error("output should contain TS_AUTHKEY")
	}
	if strings.Contains(content, "TS_HOSTNAME") {
		t.Error("output should not contain TS_HOSTNAME when not provided")
	}
}

func TestParseHostname(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr string
	}{
		{name: "valid simple", host: "nginx-demo"},
		{name: "valid with numbers", host: "web01"},
		{name: "valid uppercase", host: "MyHost"},
		{name: "empty is ok", host: ""},
		{name: "newline injection", host: "foo\nTS_AUTHKEY=evil", wantErr: "invalid character"},
		{name: "space", host: "foo bar", wantErr: "invalid character"},
		{name: "slash", host: "foo/bar", wantErr: "invalid character"},
		{name: "equals", host: "foo=bar", wantErr: "invalid character"},
		{name: "starts with hyphen", host: "-foo", wantErr: "must not start or end with a hyphen"},
		{name: "ends with hyphen", host: "foo-", wantErr: "must not start or end with a hyphen"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHostname(tt.host)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if string(got) != tt.host {
					t.Errorf("got %q, want %q", got, tt.host)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseOutputPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{
			name: "valid path",
			path: "/run/user/1000/ts-authkeys/nginx-demo.env",
		},
		{
			name:    "path traversal in uid",
			path:    "/run/user/../../etc/shadow.env",
			wantErr: "must not contain '..'",
		},
		{
			name:    "path traversal in filename",
			path:    "/run/user/1000/ts-authkeys/../../../etc/shadow.env",
			wantErr: "must not contain '..'",
		},
		{
			name:    "relative path",
			path:    "run/user/1000/ts-authkeys/test.env",
			wantErr: "must be absolute",
		},
		{
			name:    "wrong prefix",
			path:    "/tmp/ts-authkeys/test.env",
			wantErr: "must match",
		},
		{
			name:    "non-numeric uid",
			path:    "/run/user/evil/ts-authkeys/test.env",
			wantErr: "must be numeric",
		},
		{
			name:    "wrong extension",
			path:    "/run/user/1000/ts-authkeys/test.sh",
			wantErr: "must end in .env",
		},
		{
			name:    "extra depth",
			path:    "/run/user/1000/ts-authkeys/sub/test.env",
			wantErr: "must match",
		},
		{
			name:    "missing ts-authkeys",
			path:    "/run/user/1000/other/test.env",
			wantErr: "must match",
		},
		{
			name:    "just /run/user",
			path:    "/run/user/test.env",
			wantErr: "must match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOutputPath(tt.path)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if string(got) != filepath.Clean(tt.path) {
					t.Errorf("got %q, want %q", got, filepath.Clean(tt.path))
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseEnvFileQuotedValues(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "double quoted",
			input: `KEY="hello world"`,
			want:  map[string]string{"KEY": "hello world"},
		},
		{
			name:  "single quoted",
			input: `KEY='hello world'`,
			want:  map[string]string{"KEY": "hello world"},
		},
		{
			name:  "unquoted",
			input: `KEY=hello`,
			want:  map[string]string{"KEY": "hello"},
		},
		{
			name:  "mismatched quotes left as-is",
			input: `KEY="hello'`,
			want:  map[string]string{"KEY": `"hello'`},
		},
		{
			name:  "empty quoted value",
			input: `KEY=""`,
			want:  map[string]string{"KEY": ""},
		},
		{
			name:  "quotes in middle not stripped",
			input: `KEY=he"ll"o`,
			want:  map[string]string{"KEY": `he"ll"o`},
		},
		{
			name:  "multiple keys with mixed quoting",
			input: "A=\"one\"\nB='two'\nC=three\n",
			want:  map[string]string{"A": "one", "B": "two", "C": "three"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseEnvFile(tt.input)
			for k, wantV := range tt.want {
				if gotV, ok := got[k]; !ok {
					t.Errorf("missing key %q", k)
				} else if gotV != wantV {
					t.Errorf("key %q: got %q, want %q", k, gotV, wantV)
				}
			}
		})
	}
}

func TestLoadConfigQuotedValues(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oauth.env")
	os.WriteFile(cfgPath, []byte(`TS_API_CLIENT_ID="myid"
TS_API_CLIENT_SECRET='mysecret'
TS_TAILNET="example.com"
`), 0600)

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig error: %v", err)
	}
	if cfg.ClientID != "myid" {
		t.Errorf("unexpected ClientID: %q", cfg.ClientID)
	}
	if cfg.ClientSecret != "mysecret" {
		t.Errorf("unexpected ClientSecret: %q", cfg.ClientSecret)
	}
	if cfg.Tailnet != "example.com" {
		t.Errorf("unexpected Tailnet: %q", cfg.Tailnet)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oauth.env")
	os.WriteFile(cfgPath, []byte(`TS_API_CLIENT_ID=myid
TS_API_CLIENT_SECRET=mysecret
TS_TAILNET=example.com
TS_KEY_EXPIRY_SECONDS=7200
`), 0600)

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig error: %v", err)
	}
	if cfg.ClientID != "myid" {
		t.Errorf("unexpected ClientID: %s", cfg.ClientID)
	}
	if cfg.ClientSecret != "mysecret" {
		t.Errorf("unexpected ClientSecret: %s", cfg.ClientSecret)
	}
	if cfg.Tailnet != "example.com" {
		t.Errorf("unexpected Tailnet: %s", cfg.Tailnet)
	}
	if cfg.Expiry != 7200 {
		t.Errorf("unexpected Expiry: %d", cfg.Expiry)
	}
}

func TestLoadConfigMissingID(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oauth.env")
	os.WriteFile(cfgPath, []byte("TS_API_CLIENT_SECRET=secret\n"), 0600)

	_, err := loadConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for missing client ID")
	}
}

func TestDropPrivilegesUnderSudo(t *testing.T) {
	// Save and restore all overridable vars
	origGetuid := osGetuid
	origSetuid := sysSetuid
	origSetgid := sysSetgid
	origSetgroups := sysSetgroups
	origLookupId := userLookupId
	defer func() {
		osGetuid = origGetuid
		sysSetuid = origSetuid
		sysSetgid = origSetgid
		sysSetgroups = origSetgroups
		userLookupId = origLookupId
	}()

	// Record syscall invocations in order
	type call struct {
		name string
		args interface{}
	}
	var calls []call

	osGetuid = func() int { return 0 }
	sysSetgroups = func(gids []int) error {
		calls = append(calls, call{"setgroups", gids})
		return nil
	}
	sysSetgid = func(gid int) error {
		calls = append(calls, call{"setgid", gid})
		return nil
	}
	sysSetuid = func(uid int) error {
		calls = append(calls, call{"setuid", uid})
		return nil
	}
	userLookupId = func(uid string) (*user.User, error) {
		return nil, fmt.Errorf("user not found") // force fallback to primary GID
	}

	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_GID", "1000")

	err := dropPrivileges()
	if err != nil {
		t.Fatalf("dropPrivileges error: %v", err)
	}

	if len(calls) != 3 {
		t.Fatalf("expected 3 syscalls, got %d: %v", len(calls), calls)
	}
	if calls[0].name != "setgroups" {
		t.Errorf("first call should be setgroups, got %s", calls[0].name)
	}
	if gids := calls[0].args.([]int); len(gids) != 1 || gids[0] != 1000 {
		t.Errorf("setgroups args: %v", gids)
	}
	if calls[1].name != "setgid" || calls[1].args.(int) != 1000 {
		t.Errorf("second call should be setgid(1000), got %s(%v)", calls[1].name, calls[1].args)
	}
	if calls[2].name != "setuid" || calls[2].args.(int) != 1000 {
		t.Errorf("third call should be setuid(1000), got %s(%v)", calls[2].name, calls[2].args)
	}
}

func TestDropPrivilegesWithSupplementaryGroups(t *testing.T) {
	origGetuid := osGetuid
	origSetuid := sysSetuid
	origSetgid := sysSetgid
	origSetgroups := sysSetgroups
	origLookupId := userLookupId
	defer func() {
		osGetuid = origGetuid
		sysSetuid = origSetuid
		sysSetgid = origSetgid
		sysSetgroups = origSetgroups
		userLookupId = origLookupId
	}()

	var gotGids []int

	osGetuid = func() int { return 0 }
	sysSetgroups = func(gids []int) error {
		gotGids = gids
		return nil
	}
	sysSetgid = func(gid int) error { return nil }
	sysSetuid = func(uid int) error { return nil }
	userLookupId = func(uid string) (*user.User, error) {
		return &user.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
		}, nil
	}

	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_GID", "1000")

	err := dropPrivileges()
	if err != nil {
		t.Fatalf("dropPrivileges error: %v", err)
	}

	// user.User.GroupIds() reads /etc/group; in test the mock user won't have
	// real group entries, so it will fall back to the primary GID
	if len(gotGids) == 0 {
		t.Fatal("setgroups was not called")
	}
}

func TestDropPrivilegesNotRoot(t *testing.T) {
	origGetuid := osGetuid
	origSetuid := sysSetuid
	origSetgid := sysSetgid
	origSetgroups := sysSetgroups
	defer func() {
		osGetuid = origGetuid
		sysSetuid = origSetuid
		sysSetgid = origSetgid
		sysSetgroups = origSetgroups
	}()

	called := false
	osGetuid = func() int { return 1000 } // not root
	sysSetgroups = func(gids []int) error { called = true; return nil }
	sysSetgid = func(gid int) error { called = true; return nil }
	sysSetuid = func(uid int) error { called = true; return nil }

	err := dropPrivileges()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Error("syscalls should not be made when not running as root")
	}
}

func TestDropPrivilegesRootWithoutSudo(t *testing.T) {
	origGetuid := osGetuid
	defer func() { osGetuid = origGetuid }()

	osGetuid = func() int { return 0 }

	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")

	err := dropPrivileges()
	if err == nil {
		t.Fatal("expected error when running as bare root")
	}
	if !strings.Contains(err.Error(), "bare root") {
		t.Errorf("error should mention bare root: %v", err)
	}
}

func TestCleanupStaleDevicesDeletesMatchingHostname(t *testing.T) {
	var deletedIDs []string
	devServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(devicesResponse{
				Devices: []deviceInfo{
					{ID: "dev-1", Hostname: "nginx-demo", Name: "nginx-demo.tail1234.ts.net"},
					{ID: "dev-2", Hostname: "other-host", Name: "other-host.tail1234.ts.net"},
					{ID: "dev-3", Hostname: "nginx-demo", Name: "nginx-demo-1.tail1234.ts.net"},
				},
			})
			return
		}
		if r.Method == "DELETE" {
			// Extract device ID from URL path
			parts := strings.Split(r.URL.Path, "/")
			deletedIDs = append(deletedIDs, parts[len(parts)-1])
			w.WriteHeader(http.StatusOK)
			return
		}
		t.Errorf("unexpected method: %s", r.Method)
	}))
	defer devServer.Close()

	origDevicesURL := devicesURL
	origDeleteURL := deleteDeviceURL
	devicesURL = func(tailnet string) string { return devServer.URL }
	deleteDeviceURL = func(id string) string { return devServer.URL + "/" + id }
	defer func() {
		devicesURL = origDevicesURL
		deleteDeviceURL = origDeleteURL
	}()

	err := cleanupStaleDevices("test-token", "-", "nginx-demo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deletedIDs) != 2 {
		t.Fatalf("expected 2 deletions, got %d: %v", len(deletedIDs), deletedIDs)
	}
	if deletedIDs[0] != "dev-1" || deletedIDs[1] != "dev-3" {
		t.Errorf("unexpected deleted IDs: %v", deletedIDs)
	}
}

func TestCleanupStaleDevicesNoMatches(t *testing.T) {
	devServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(devicesResponse{
			Devices: []deviceInfo{
				{ID: "dev-1", Hostname: "other-host", Name: "other-host.tail1234.ts.net"},
			},
		})
	}))
	defer devServer.Close()

	origDevicesURL := devicesURL
	devicesURL = func(tailnet string) string { return devServer.URL }
	defer func() { devicesURL = origDevicesURL }()

	err := cleanupStaleDevices("test-token", "-", "nginx-demo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCleanupStaleDevicesAPIError(t *testing.T) {
	devServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer devServer.Close()

	origDevicesURL := devicesURL
	devicesURL = func(tailnet string) string { return devServer.URL }
	defer func() { devicesURL = origDevicesURL }()

	err := cleanupStaleDevices("bad-token", "-", "nginx-demo")
	if err == nil {
		t.Fatal("expected error for API failure")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention 403: %v", err)
	}
}

func TestCleanupStaleDevicesDeleteError(t *testing.T) {
	devServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(devicesResponse{
				Devices: []deviceInfo{
					{ID: "dev-1", Hostname: "nginx-demo", Name: "nginx-demo.tail1234.ts.net"},
				},
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer devServer.Close()

	origDevicesURL := devicesURL
	origDeleteURL := deleteDeviceURL
	devicesURL = func(tailnet string) string { return devServer.URL }
	deleteDeviceURL = func(id string) string { return devServer.URL + "/" + id }
	defer func() {
		devicesURL = origDevicesURL
		deleteDeviceURL = origDeleteURL
	}()

	err := cleanupStaleDevices("test-token", "-", "nginx-demo")
	if err == nil {
		t.Fatal("expected error for delete failure")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention 500: %v", err)
	}
}

func TestGetAccessTokenReadError(t *testing.T) {
	// Server claims a large body via Content-Length but sends nothing, causing io.ReadAll to fail
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "9999")
		w.WriteHeader(http.StatusOK)
		// Close without writing the promised body
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer tokenServer.Close()

	origTokenURL := oauthTokenURL
	oauthTokenURL = tokenServer.URL
	defer func() { oauthTokenURL = origTokenURL }()

	cfg := config{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		Tailnet:      "-",
	}

	_, err := getAccessToken(cfg)
	if err == nil {
		t.Fatal("expected error from read failure")
	}
	if !strings.Contains(err.Error(), "reading OAuth token response") {
		t.Errorf("error should mention reading response, got: %v", err)
	}
}

func TestMintKeyCreateKeyReadError(t *testing.T) {
	// Token endpoint works fine
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(tokenResponse{AccessToken: "test-token"})
	}))
	defer tokenServer.Close()

	// Key endpoint claims large body but closes connection
	keyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "9999")
		w.WriteHeader(http.StatusOK)
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer keyServer.Close()

	origTokenURL := oauthTokenURL
	origKeyURL := createKeyURL
	oauthTokenURL = tokenServer.URL
	createKeyURL = func(tailnet string) string { return keyServer.URL }
	defer func() {
		oauthTokenURL = origTokenURL
		createKeyURL = origKeyURL
	}()

	cfg := config{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		Tailnet:      "-",
	}

	_, err := mintKey(cfg, "tag:test", Hostname("test"))
	if err == nil {
		t.Fatal("expected error from read failure")
	}
	if !strings.Contains(err.Error(), "reading create key response") {
		t.Errorf("error should mention reading response, got: %v", err)
	}
}

func TestOAuthTokenTimeout(t *testing.T) {
	// Server that hangs longer than the client timeout
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		json.NewEncoder(w).Encode(tokenResponse{AccessToken: "too-late"})
	}))
	defer tokenServer.Close()

	origTokenURL := oauthTokenURL
	origClient := httpClient
	oauthTokenURL = tokenServer.URL
	httpClient = &http.Client{Timeout: 100 * time.Millisecond}
	defer func() {
		oauthTokenURL = origTokenURL
		httpClient = origClient
	}()

	cfg := config{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		Tailnet:      "-",
	}

	_, err := mintKey(cfg, "tag:test", Hostname("test"))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	// net/http wraps timeout errors; check for context deadline or timeout indication
	errStr := err.Error()
	if !strings.Contains(errStr, "deadline exceeded") &&
		!strings.Contains(errStr, "Timeout") &&
		!strings.Contains(errStr, "timeout") {
		t.Errorf("error should indicate timeout, got: %v", err)
	}
}

func TestCreateKeyTimeout(t *testing.T) {
	// Token endpoint responds quickly
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(tokenResponse{AccessToken: "test-token"})
	}))
	defer tokenServer.Close()

	// Key endpoint hangs
	keyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		json.NewEncoder(w).Encode(keyResponse{Key: "too-late"})
	}))
	defer keyServer.Close()

	origTokenURL := oauthTokenURL
	origKeyURL := createKeyURL
	origClient := httpClient
	oauthTokenURL = tokenServer.URL
	createKeyURL = func(tailnet string) string { return keyServer.URL }
	httpClient = &http.Client{Timeout: 100 * time.Millisecond}
	defer func() {
		oauthTokenURL = origTokenURL
		createKeyURL = origKeyURL
		httpClient = origClient
	}()

	cfg := config{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		Tailnet:      "-",
	}

	_, err := mintKey(cfg, "tag:test", Hostname("test"))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "deadline exceeded") &&
		!strings.Contains(errStr, "Timeout") &&
		!strings.Contains(errStr, "timeout") {
		t.Errorf("error should indicate timeout, got: %v", err)
	}
}
