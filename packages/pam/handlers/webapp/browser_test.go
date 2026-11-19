package webapp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSandboxDisabled(t *testing.T) {
	cases := []struct {
		euid    int
		env     string
		want    bool
		wantErr bool
	}{
		{euid: 0, env: "", wantErr: true},
		{euid: 0, env: "false", wantErr: true},
		{euid: 0, env: "1", wantErr: true},
		{euid: 0, env: "true", want: true},
		{euid: 1000, env: "", want: false},
		{euid: 1000, env: "true", want: true},
	}
	for _, tc := range cases {
		got, err := sandboxDisabled(tc.euid, tc.env)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("sandboxDisabled(%d, %q) = %v, %v", tc.euid, tc.env, got, err)
		}
	}
}

func TestMaxBrowserSessions(t *testing.T) {
	cases := map[string]int{"": 5, "abc": 5, "0": 5, "-2": 5, "1": 1, "12": 12}
	for in, want := range cases {
		if got := maxBrowserSessions(in); got != want {
			t.Errorf("maxBrowserSessions(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestSessionLimiter(t *testing.T) {
	var l sessionLimiter
	r1, ok1 := l.acquire(2)
	r2, ok2 := l.acquire(2)
	_, ok3 := l.acquire(2)
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("acquire results = %v %v %v", ok1, ok2, ok3)
	}
	r1()
	r1()
	if _, ok := l.acquire(2); !ok {
		t.Fatal("slot not freed")
	}
	if _, ok := l.acquire(2); ok {
		t.Fatal("double release freed two slots")
	}
	r2()
}

func TestFindBrowserPathFromEnv(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "browser")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	notExe := filepath.Join(dir, "plain")
	if err := os.WriteFile(notExe, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv(browserPathEnv, exe)
	if got := FindBrowserPath(); got != exe {
		t.Errorf("FindBrowserPath() = %q, want %q", got, exe)
	}
	for _, bad := range []string{notExe, dir, filepath.Join(dir, "missing")} {
		t.Setenv(browserPathEnv, bad)
		if got := FindBrowserPath(); got != "" {
			t.Errorf("FindBrowserPath() with %q = %q, want none", bad, got)
		}
	}
}

func TestFindBrowserPathSearchesPath(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "chromium")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(browserPathEnv, "")
	t.Setenv("PATH", dir)
	if got := FindBrowserPath(); got != exe {
		t.Errorf("FindBrowserPath() = %q, want %q", got, exe)
	}
	t.Setenv("PATH", t.TempDir())
	if got := FindBrowserPath(); got != "" {
		t.Errorf("FindBrowserPath() = %q, want none", got)
	}
}

func readServerJSON(t *testing.T, conn net.Conn) map[string]any {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		header := make([]byte, frameHeaderBytes)
		if _, err := io.ReadFull(conn, header); err != nil {
			t.Fatalf("read frame header: %v", err)
		}
		payload := make([]byte, binary.BigEndian.Uint32(header[:4])-1)
		if _, err := io.ReadFull(conn, payload); err != nil {
			t.Fatalf("read frame: %v", err)
		}
		if header[4] != frameTypeJSON {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal(payload, &msg); err != nil {
			t.Fatal(err)
		}
		return msg
	}
}

func runRefusedSession(t *testing.T, p *WebAppProxy) (map[string]any, error) {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- p.HandleConnection(context.Background(), server) }()
	msg := readServerJSON(t, client)
	select {
	case err := <-done:
		return msg, err
	case <-time.After(5 * time.Second):
		t.Fatal("HandleConnection did not return")
		return nil, nil
	}
}

func fakeBrowserEnv(t *testing.T) {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "browser")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(browserPathEnv, exe)
	t.Setenv(browserNoSandboxEnv, "true")
}

func TestHandleConnectionRefusesBlockedStartURL(t *testing.T) {
	fakeBrowserEnv(t)
	p := &WebAppProxy{
		config:   WebAppProxyConfig{SessionID: "s", StartURL: "https://metadata.internal/"},
		resolver: publicResolver(),
	}
	msg, err := runRefusedSession(t, p)
	if err == nil {
		t.Fatal("blocked start URL accepted")
	}
	if msg["type"] != "error" || !strings.Contains(msg["message"].(string), "always blocked") {
		t.Errorf("message = %v", msg)
	}
}

func TestHandleConnectionRefusesInvalidStartURL(t *testing.T) {
	fakeBrowserEnv(t)
	p := &WebAppProxy{config: WebAppProxyConfig{SessionID: "s", StartURL: "ftp://grafana.internal"}, resolver: publicResolver()}
	msg, err := runRefusedSession(t, p)
	if err == nil || msg["type"] != "error" {
		t.Errorf("msg = %v, err = %v", msg, err)
	}
}

func TestHandleConnectionRefusesRootWithSandbox(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	fakeBrowserEnv(t)
	t.Setenv(browserNoSandboxEnv, "")
	p := &WebAppProxy{config: WebAppProxyConfig{SessionID: "s", StartURL: "https://grafana.internal"}, resolver: publicResolver()}
	msg, err := runRefusedSession(t, p)
	if !errors.Is(err, errRootWithSandbox) || msg["type"] != "error" {
		t.Errorf("msg = %v, err = %v", msg, err)
	}
}

func TestHandleConnectionRefusesPastSessionCap(t *testing.T) {
	fakeBrowserEnv(t)
	t.Setenv(browserMaxSessionsEnv, "1")
	release, ok := browserSessions.acquire(1)
	if !ok {
		t.Fatal("could not take the only slot")
	}
	defer release()

	p := &WebAppProxy{config: WebAppProxyConfig{SessionID: "s", StartURL: "https://grafana.internal"}, resolver: publicResolver()}
	msg, err := runRefusedSession(t, p)
	if err == nil || msg["type"] != "error" || !strings.Contains(msg["message"].(string), "as many browser sessions") {
		t.Errorf("msg = %v, err = %v", msg, err)
	}
}

func TestPassthroughEnvDropsOtherVariables(t *testing.T) {
	t.Setenv("INFISICAL_TOKEN", "secret-value")
	t.Setenv("HOME", "/home/gateway")
	env := passthroughEnv()
	if !slices.Contains(env, "HOME=/home/gateway") {
		t.Errorf("HOME missing from %v", env)
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "INFISICAL_TOKEN=") {
			t.Fatal("gateway credentials passed to the browser")
		}
	}
}
