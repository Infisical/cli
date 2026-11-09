package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

func TestRunGivesTheAgentWhatConnectNeeds(t *testing.T) {
	parent := []string{
		agentVaultProxyAddressEnv + "=stale:1",
		agentVaultCaFileEnv + "=/old/ca.pem",
		"PATH=/usr/bin",
	}
	env := withAgentVaultConnectEnv(parent, "10.0.0.5:17323", "agv_new", "/data/ca-1.pem", "https://eu.infisical.com/api", false)

	for key, want := range map[string]string{
		agentVaultSessionTokenEnv:      "agv_new",
		agentVaultProxyAddressEnv:      "10.0.0.5:17323",
		agentVaultCaFileEnv:            "/data/ca-1.pem",
		util.INFISICAL_DOMAIN_ENV_NAME: "https://eu.infisical.com",
		"PATH":                         "/usr/bin",
	} {
		if got, _ := envValue(env, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if strings.Contains(strings.Join(env, "\n"), "stale:1") {
		t.Error("a stale proxy address from the parent reached the agent")
	}
}

func TestRunLeavesTheOperatorsDomainAndDropsAStaleCaFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("keys compare case-insensitively on Windows")
	}
	parent := []string{util.INFISICAL_DOMAIN_ENV_NAME + "=https://self.example.com", agentVaultCaFileEnv + "=/old/ca.pem"}
	env := withAgentVaultConnectEnv(parent, "p:1", "agv", "", "https://app.infisical.com/api", false)

	if got, _ := envValue(env, util.INFISICAL_DOMAIN_ENV_NAME); got != "https://self.example.com" {
		t.Errorf("domain = %q, want the operator's", got)
	}
	if _, ok := envValue(env, agentVaultCaFileEnv); ok {
		t.Error("a CA file from another run reached the agent under --no-ca-trust")
	}
}

func TestConnectPicksServicesByNameOrAll(t *testing.T) {
	available := []agentvault.NativeServiceInfo{{Name: "analytics", Type: "postgres"}, {Name: "bastion", Type: "ssh"}}

	picked, err := pickAgentVaultConnectServices(available, []string{"Bastion"}, false)
	if err != nil || len(picked) != 1 || picked[0].Name != "bastion" {
		t.Fatalf("picked %v, %v", picked, err)
	}
	if all, _ := pickAgentVaultConnectServices(available, nil, true); len(all) != 2 {
		t.Fatalf("--all picked %d services", len(all))
	}
	if _, err := pickAgentVaultConnectServices(available, []string{"nope"}, false); err == nil ||
		!strings.Contains(err.Error(), "analytics, bastion") {
		t.Fatalf("an unknown name gave %v, want the list of services", err)
	}
	if _, err := pickAgentVaultConnectServices(nil, nil, true); err == nil {
		t.Fatal("a session with no services wasn't refused")
	}
}

func TestRunsDomainFlagReplacesAnInheritedDomain(t *testing.T) {
	parent := []string{
		util.INFISICAL_DOMAIN_ENV_NAME + "=https://eu.infisical.com",
		util.LEGACY_INFISICAL_API_URL_ENV_NAME + "=https://eu.infisical.com/api",
	}
	env := withAgentVaultConnectEnv(parent, "p:1", "agv", "", "https://self.example.com/api", true)

	if got, _ := envValue(env, util.INFISICAL_DOMAIN_ENV_NAME); got != "https://self.example.com" {
		t.Errorf("domain = %q, want run's --domain", got)
	}
	if _, ok := envValue(env, util.LEGACY_INFISICAL_API_URL_ENV_NAME); ok {
		t.Error("the inherited legacy domain variable still reached the agent")
	}
}

func TestConnectPrintsALabelledBlockPerService(t *testing.T) {
	for _, tc := range []struct {
		service agentvault.NativeServiceInfo
		want    string
	}{
		{agentvault.NativeServiceInfo{Name: "analytics", Type: "postgres", Database: "app"},
			"analytics (PostgreSQL)\n  Address:  127.0.0.1:5000\n  Example:  psql \"postgres://agent@127.0.0.1:5000/?sslmode=disable\"\n"},
		{agentvault.NativeServiceInfo{Name: "orders", Type: "mysql", Database: "orders"},
			"orders (MySQL)\n  Address:  127.0.0.1:5000\n  Example:  mysql -h 127.0.0.1 -P 5000 -u agent\n"},
		{agentvault.NativeServiceInfo{Name: "bastion", Type: "ssh"},
			"bastion (SSH)\n  Address:  127.0.0.1:5000\n  Example:  ssh -p 5000 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null agent@127.0.0.1\n"},
		{agentvault.NativeServiceInfo{Name: "cache", Type: "redis"}, "cache\n  Address:  127.0.0.1:5000\n"},
	} {
		if got := agentVaultConnectBlock(tc.service, 5000); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.service.Type, got, tc.want)
		}
	}
}

// A database name is the admin's text, and the example is pasted into a shell.
func TestConnectLeavesTheDatabaseOutOfTheExample(t *testing.T) {
	for _, serviceType := range []string{"postgres", "mysql"} {
		block := agentVaultConnectBlock(agentvault.NativeServiceInfo{Name: "db", Type: serviceType, Database: "orders; echo PWNED"}, 5000)
		if strings.Contains(block, "PWNED") || strings.Contains(block, "orders") {
			t.Errorf("%s printed the database name: %q", serviceType, block)
		}
	}
}

func TestConnectAllSkipsOnlyAServiceRefusal(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		skip bool
	}{
		{"service refused", &agentvault.ProxyRefusedError{Status: http.StatusForbidden, Message: "personal values aren't set"}, true},
		{"session ended", &agentvault.ProxyRefusedError{Status: http.StatusForbidden,
			Message: "the session is no longer valid, or it belongs to a different Agent Vault project than this proxy"}, false},
		{"proxy can't reach Infisical", &agentvault.ProxyRefusedError{Status: http.StatusBadGateway, Message: "failed to resolve the session"}, false},
		{"network", errors.New("connection reset"), false},
	} {
		if got := isAgentVaultServiceRefusal(tc.err); got != tc.skip {
			t.Errorf("%s: skip = %v, want %v", tc.name, got, tc.skip)
		}
	}
}

func TestConnectGivesAnEndedSessionItsOwnCode(t *testing.T) {
	err := classifyAgentVaultConnectError(&agentvault.ProxyRefusedError{Status: http.StatusForbidden,
		Message: "the session is no longer valid, or it belongs to a different Agent Vault project than this proxy"}, "10.0.0.5:17323")
	if codeOf(err) != errCodeSessionInvalid {
		t.Fatalf("code %q, want %q", codeOf(err), errCodeSessionInvalid)
	}
	if err := classifyAgentVaultConnectError(&agentvault.ProxyRefusedError{Status: http.StatusForbidden, Message: "no"}, "p:1"); codeOf(err) != errCodeServiceRefused {
		t.Fatalf("a service refusal got code %q", codeOf(err))
	}
}

// runAgentVaultConnectForTest runs `connect <args>` on a fresh command with the connect variables cleared, then
// set by setup. It returns stderr and whether the command exited.
func runAgentVaultConnectForTest(t *testing.T, setup func(), args ...string) (stderr string, exited bool) {
	t.Helper()
	t.Setenv(agentVaultSessionTokenEnv, "")
	t.Setenv(agentVaultProxyAddressEnv, "")
	if setup != nil {
		setup()
	}
	errOut := captureStderr(t)
	oldExit, oldTelemetry := exitProcess, Telemetry
	exitProcess = func(int) { panic(exitCalled{}) }
	Telemetry = telemetry.NewTelemetry(false)
	t.Cleanup(func() { exitProcess, Telemetry = oldExit, oldTelemetry })

	cmd := &cobra.Command{Use: "connect", Run: runAgentVaultConnect}
	cmd.Flags().Bool("silent", false, "")
	cmd.Flags().StringP("output", "o", "", "")
	cmd.Flags().String("session-token", "", "")
	cmd.Flags().String("proxy", "", "")
	cmd.Flags().String("ca-fingerprint", "", "")
	cmd.Flags().Bool("all", false, "")
	cmd.Flags().Int("port", 0, "")
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(exitCalled); !ok {
					panic(r)
				}
				exited = true
			}
		}()
		cmd.Run(cmd, cmd.Flags().Args())
	}()
	return errOut.String(), exited
}

func TestConnectPortNeedsExactlyOneService(t *testing.T) {
	for _, args := range [][]string{
		{"--all", "--port", "5432"},
		{"analytics", "orders", "--port", "5432"},
	} {
		stderr, exited := runAgentVaultConnectForTest(t, nil, args...)
		if !exited || !strings.Contains(stderr, "--port works with one service") {
			t.Errorf("%v: exited %v, stderr %q", args, exited, stderr)
		}
	}
	stderr, exited := runAgentVaultConnectForTest(t, nil, "analytics", "--port", "70000")
	if !exited || !strings.Contains(stderr, "--port must be between 1 and 65535") {
		t.Errorf("an out-of-range port: exited %v, stderr %q", exited, stderr)
	}
}

func TestConnectNamesTheVariableABadProxyAddressCameFrom(t *testing.T) {
	stderr, exited := runAgentVaultConnectForTest(t, func() {
		t.Setenv(agentVaultSessionTokenEnv, "agv_x")
		t.Setenv(agentVaultProxyAddressEnv, "10.0.0.1")
	}, "analytics")
	if !exited || !strings.Contains(stderr, agentVaultProxyAddressEnv+" must be host:port") || strings.Contains(stderr, "--proxy must") {
		t.Fatalf("exited %v, stderr %q; want the variable named", exited, stderr)
	}
}

type agentVaultTrustCase struct {
	name        string
	caFile      string
	infisical   http.HandlerFunc
	unreachable bool
	pin         string
	wantSource  string
	wantCode    string
	wantText    string
	wantCalls   int32
}

// The proxy's CA is trusted only when the pin, the run's CA file or Infisical vouches for it, and the session token
// is never sent to the proxy on the way.
func TestConnectTrustsTheProxyOnlyWhenSomethingVouchesForIt(t *testing.T) {
	served := selfSignedPEM(t, "served")
	other := selfSignedPEM(t, "other")
	_, servedFP, _ := agentVaultCaFingerprint(served)
	_, otherFP, _ := agentVaultCaFingerprint(other)

	var tokenAtProxy atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, values := range r.Header {
			if strings.Contains(strings.Join(values, " "), "agv_test") {
				tokenAtProxy.Store(true)
			}
		}
		_ = json.NewEncoder(w).Encode(agentVaultProxyCa{Certificate: served})
	}))
	t.Cleanup(proxy.Close)
	proxyAddr := strings.TrimPrefix(proxy.URL, "http://")

	lists := func(fingerprints ...string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"fingerprints": fingerprints})
		}
	}
	answers := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}
	}

	for _, tc := range []agentVaultTrustCase{
		{name: "run's CA file matches", caFile: served, infisical: answers(500, "{}"), wantSource: agentVaultTrustRunCa},
		{name: "Infisical lists it", caFile: other, infisical: lists(otherFP, servedFP), wantSource: agentVaultTrustInfisical, wantCalls: 1},
		{name: "pin matches with Infisical down", unreachable: true, pin: servedFP, wantSource: agentVaultTrustPinned},
		{name: "pin mismatch overrules the CA file and Infisical", caFile: served, infisical: lists(servedFP), pin: otherFP,
			wantCode: errCodeProxyUntrusted, wantText: "not the one passed in --ca-fingerprint"},
		{name: "nothing matches", caFile: other, infisical: lists(otherFP), wantCode: errCodeProxyUntrusted,
			wantText: "wasn't sent to the proxy", wantCalls: 1},
		{name: "session no longer valid (401)", infisical: answers(401, `{"statusCode":401,"error":"UnauthorizedError","message":"x"}`),
			wantCode: errCodeSessionInvalid, wantCalls: 1},
		{name: "session no longer valid (403)", infisical: answers(403, `{"statusCode":403,"error":"PermissionDenied","message":"x"}`),
			wantCode: errCodeSessionInvalid, wantCalls: 1},
		{name: "Infisical predates the fingerprint route", infisical: answers(404, `{"statusCode":404,"error":"Not Found","message":"Route GET:/api/v1/agent-vault/session/proxy-ca-fingerprints not found"}`),
			wantCode: errCodeProxyUntrusted, wantText: "doesn't list proxy fingerprints yet", wantCalls: 1},
		{name: "Infisical unreachable", unreachable: true, wantCode: errCodeProxyUntrusted, wantText: "Couldn't reach Infisical at"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenAtProxy.Store(false)
			caFile := ""
			if tc.caFile != "" {
				caFile = filepath.Join(t.TempDir(), "ca.pem")
				if err := os.WriteFile(caFile, []byte(tc.caFile), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv(agentVaultCaFileEnv, caFile)

			var calls atomic.Int32
			infisicalURL := ""
			if tc.unreachable {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				infisicalURL = "http://" + ln.Addr().String()
				_ = ln.Close()
			} else {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					tc.infisical(w, r)
				}))
				t.Cleanup(srv.Close)
				infisicalURL = srv.URL
			}
			oldURL := config.INFISICAL_URL
			config.INFISICAL_URL = infisicalURL + "/api"
			t.Cleanup(func() { config.INFISICAL_URL = oldURL })
			useAgentVaultDomainExplicitlySet(t, true)

			pool, source, err := trustAgentVaultProxy(proxyAddr, "agv_test", tc.pin)
			if tc.wantCode == "" {
				if err != nil || pool == nil || source != tc.wantSource {
					t.Fatalf("source %q, err %v; want %q", source, err, tc.wantSource)
				}
			} else {
				if pool != nil || codeOf(err) != tc.wantCode || !strings.Contains(err.Error(), tc.wantText) {
					t.Fatalf("pool %v, err %v; want code %s with %q", pool != nil, err, tc.wantCode, tc.wantText)
				}
			}
			if calls.Load() != tc.wantCalls {
				t.Errorf("Infisical was asked %d times, want %d", calls.Load(), tc.wantCalls)
			}
			if tokenAtProxy.Load() {
				t.Error("the session token reached the proxy before it was trusted")
			}
		})
	}
}

func TestAConnectWarningIsCleanedBeforeItPrints(t *testing.T) {
	var buf strings.Builder
	old := util.GetStderrWriter
	util.GetStderrWriter = func() io.Writer { return &buf }
	t.Cleanup(func() { util.GetStderrWriter = old })

	token := "agv_" + strings.Repeat("a", 43)
	warnAgentVaultConnect("orders\x1b[2J", "refused \x1b[31mred\x1b[0m with "+token)

	got := buf.String()
	if strings.Contains(got, "\x1b") {
		t.Fatalf("warning %q kept an escape byte", got)
	}
	if strings.Contains(got, token) || !strings.Contains(got, "<redacted>") {
		t.Fatalf("warning %q, want the token redacted", got)
	}
	if !strings.HasPrefix(got, "orders") {
		t.Fatalf("warning %q, want it to start with the service name", got)
	}
}
