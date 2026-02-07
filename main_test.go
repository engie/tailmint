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

	key, err := mintKey(cfg, "tag:tailpod", "nginx-demo")
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

	_, err := mintKey(cfg, "tag:tailpod", "test")
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

	_, err := mintKey(cfg, "tag:wrong", "test")
	if err == nil {
		t.Fatal("expected error for API failure")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should mention 400: %v", err)
	}
}

func TestWriteOutput(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "sub", "test.env")

	err := writeOutput(outPath, "tskey-test123", "nginx-demo")
	if err != nil {
		t.Fatalf("writeOutput error: %v", err)
	}

	data, err := os.ReadFile(outPath)
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

	info, _ := os.Stat(outPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %o", info.Mode().Perm())
	}
}

func TestWriteOutputNoHostname(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "test.env")

	err := writeOutput(outPath, "tskey-test123", "")
	if err != nil {
		t.Fatalf("writeOutput error: %v", err)
	}

	data, err := os.ReadFile(outPath)
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

	_, err := mintKey(cfg, "tag:test", "test")
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

	_, err := mintKey(cfg, "tag:test", "test")
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
