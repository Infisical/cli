//go:build darwin

package sandbox

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests actually spawn sandbox-exec on the host to prove the profile enforces what we claim.
// They are gated behind INFISICAL_SANDBOX_LIVE=1 so ordinary `go test` (and CI) skip them.
func requireLive(t *testing.T) {
	t.Helper()
	if os.Getenv("INFISICAL_SANDBOX_LIVE") != "1" {
		t.Skip("set INFISICAL_SANDBOX_LIVE=1 to run live sandbox-exec tests")
	}
	if _, err := os.Stat(sandboxExecPath); err != nil {
		t.Skipf("%s not present", sandboxExecPath)
	}
}

func liveSpec(t *testing.T, port int) SandboxSpec {
	t.Helper()
	home, _ := os.UserHomeDir()
	return SandboxSpec{
		Sandbox:      true,
		Cwd:          t.TempDir(),
		TempDir:      t.TempDir(),
		LoopbackPort: port,
		DenyPaths:    DefaultDenyPaths(home),
		Env:          os.Environ(),
		NetMode:      HardFence,
	}
}

func runInSandbox(t *testing.T, spec SandboxSpec, argv ...string) (string, error) {
	t.Helper()
	cmd, err := seatbeltBackend{}.Wrap(spec, argv)
	if err != nil {
		t.Fatal(err)
	}
	// Wrap sets stdio for interactive use; clear it so CombinedOutput can capture instead.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// The credential boundary: reading a credential file must fail inside the box.
func TestLiveDeniesCredentialFileRead(t *testing.T) {
	requireLive(t)
	home, _ := os.UserHomeDir()
	probe := home + "/.aws/credentials"
	if _, err := os.Stat(probe); err != nil {
		// Create a throwaway file under a denied path so the test is meaningful even without real creds.
		probe = home + "/.infisical/.sandbox-probe"
		_ = os.MkdirAll(home+"/.infisical", 0o700)
		if werr := os.WriteFile(probe, []byte("secret"), 0o600); werr != nil {
			t.Skipf("cannot stage a probe file: %v", werr)
		}
		defer os.Remove(probe)
	}
	out, err := runInSandbox(t, liveSpec(t, 51234), "/bin/cat", probe)
	if err == nil {
		t.Fatalf("expected reading %s to fail inside the sandbox; got output:\n%s", probe, out)
	}
	t.Logf("denied as expected: %v\n%s", err, out)
}

// The network fence: a raw outbound connection to a non-loopback host must fail.
func TestLiveDeniesExternalEgress(t *testing.T) {
	requireLive(t)
	// curl to a well-known host; expect a non-zero exit (connection denied by the sandbox).
	out, err := runInSandbox(t, liveSpec(t, 51234), "/usr/bin/curl", "-sS", "--max-time", "5", "https://example.com")
	if err == nil {
		t.Fatalf("expected external egress to be denied; got:\n%s", out)
	}
	t.Logf("egress denied as expected: %v\n%s", err, out)
}

// Loopback to the proxy port must be reachable: start a listener on that port and curl it.
func TestLiveAllowsLoopbackToProxy(t *testing.T) {
	requireLive(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "reached-proxy")
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/"
	out, err := runInSandbox(t, liveSpec(t, port), "/usr/bin/curl", "-sS", "--max-time", "5", url)
	if err != nil {
		t.Fatalf("expected loopback to the proxy port to succeed, got %v:\n%s", err, out)
	}
	if !strings.Contains(out, "reached-proxy") {
		t.Fatalf("did not reach the loopback listener; output:\n%s", out)
	}
}

// The sandbox must not stop an ordinary command from running (baseline: profile boots a process).
func TestLiveAllowsBasicExec(t *testing.T) {
	requireLive(t)
	out, err := runInSandbox(t, liveSpec(t, 51234), "/bin/echo", "hello")
	if err != nil {
		t.Fatalf("basic exec failed inside the sandbox: %v\n%s", err, out)
	}
	if !strings.Contains(out, "hello") {
		t.Fatalf("unexpected output: %q", out)
	}
	_ = exec.Command // keep import if trimmed
}

func TestLiveKeychainReadDenied(t *testing.T) {
	requireLive(t)
	// `security find-generic-password` talks to the keychain mach services we omit; it must fail.
	out, err := runInSandbox(t, liveSpec(t, 51234), "/usr/bin/security", "find-generic-password", "-s", "infisical")
	if err == nil {
		t.Fatalf("expected keychain access to be denied; got:\n%s", out)
	}
	t.Logf("keychain denied as expected: %v", err)
	_ = time.Second
}
