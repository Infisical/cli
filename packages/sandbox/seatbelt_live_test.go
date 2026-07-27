//go:build darwin

package sandbox

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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

func liveSpec(t *testing.T, port int) Spec {
	t.Helper()
	home, _ := os.UserHomeDir()
	return Spec{
		Enabled:      true,
		Cwd:          t.TempDir(),
		TempDir:      t.TempDir(),
		LoopbackPort: port,
		DenyPaths:    DefaultDenyPaths(home),
		Env:          os.Environ(),
		NetMode:      HardFence,
	}
}

func runInSandbox(t *testing.T, spec Spec, argv ...string) (string, error) {
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

// The central network invariant: the sandbox cannot resolve or reach anything itself, and a hostname
// only becomes reachable by being handed to the proxy. Covers the three ways out at once.
func TestLiveEgressOnlyViaProxy(t *testing.T) {
	requireLive(t)

	// A stand-in proxy that answers absolute-URI requests the way the real one does.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "PROXY-SAW %s", r.Host)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	home, _ := os.UserHomeDir()
	spec := liveSpec(t, port)
	proxyURL := "http://127.0.0.1:" + strconv.Itoa(port)
	bare := []string{"PATH=/usr/bin:/bin", "HOME=" + home}

	// 1. No resolver: a hostname can't be looked up, so a proxy-ignoring client fails closed.
	spec.Env = bare
	if out, err := runInSandbox(t, spec, "/usr/bin/curl", "-sS", "--max-time", "6", "http://example.com"); err == nil {
		t.Errorf("a hostname must not be resolvable without the proxy, got:\n%s", out)
	}

	// 2. No route: raw TCP straight to an external IP, no DNS involved, must still be refused. This is
	// what proves the fence is the egress rule and not merely the absence of DNS.
	if out, err := runInSandbox(t, spec, "/usr/bin/nc", "-w", "4", "-z", "1.1.1.1", "443"); err == nil {
		t.Errorf("raw TCP to an external IP must be denied, got:\n%s", out)
	}

	// 3. With the proxy env vars the same request succeeds, and the proxy is what saw the hostname:
	// resolution happened on the host, outside the sandbox. Lowercase included on purpose (curl reads
	// only lowercase http_proxy for plain-HTTP URLs).
	spec.Env = append(append([]string{}, bare...),
		"HTTP_PROXY="+proxyURL, "http_proxy="+proxyURL,
		"HTTPS_PROXY="+proxyURL, "https_proxy="+proxyURL,
		"NO_PROXY=localhost,127.0.0.1", "no_proxy=localhost,127.0.0.1")
	out, err := runInSandbox(t, spec, "/usr/bin/curl", "-sS", "--max-time", "6", "http://example.com")
	if err != nil {
		t.Fatalf("a request through the proxy must succeed, got %v:\n%s", err, out)
	}
	if !strings.Contains(out, "PROXY-SAW example.com") {
		t.Fatalf("the proxy should have received the hostname; got:\n%s", out)
	}
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
}

// A --allow-read exception must re-open exactly one path inside a denied directory: the excepted file
// becomes readable, its siblings stay denied, and it does not become writable.
func TestLiveReadExceptionIsPreciseAndReadOnly(t *testing.T) {
	requireLive(t)
	home, _ := os.UserHomeDir()
	denyDir := filepath.Join(home, ".infisical")
	excepted := filepath.Join(denyDir, ".sandbox-probe-excepted")
	sibling := filepath.Join(denyDir, ".sandbox-probe-sibling")

	if err := os.MkdirAll(denyDir, 0o700); err != nil {
		t.Skipf("cannot stage the probe dir: %v", err)
	}
	for _, p := range []string{excepted, sibling} {
		if err := os.WriteFile(p, []byte("PROBE_CONTENT\n"), 0o600); err != nil {
			t.Skipf("cannot stage %s: %v", p, err)
		}
		defer os.Remove(p)
	}

	spec := liveSpec(t, 51234)
	spec.DenyPaths = []string{denyDir}
	spec.ReadPaths = []string{excepted}

	if out, err := runInSandbox(t, spec, "/bin/cat", excepted); err != nil {
		t.Errorf("the excepted path must be readable, got %v:\n%s", err, out)
	} else if !strings.Contains(out, "PROBE_CONTENT") {
		t.Errorf("unexpected content from the excepted path: %q", out)
	}

	if out, err := runInSandbox(t, spec, "/bin/cat", sibling); err == nil {
		t.Errorf("a sibling in the denied dir must stay denied, but it read:\n%s", out)
	}

	if out, err := runInSandbox(t, spec, "/usr/bin/tee", excepted); err == nil {
		t.Errorf("a read exception must not grant write, but tee succeeded:\n%s", out)
	}
}

func TestLiveKeychainReadDenied(t *testing.T) {
	requireLive(t)
	// `security find-generic-password` talks to the keychain mach services we omit; it must fail.
	out, err := runInSandbox(t, liveSpec(t, 51234), "/usr/bin/security", "find-generic-password", "-s", "infisical")
	if err == nil {
		t.Fatalf("expected keychain access to be denied; got:\n%s", out)
	}
	t.Logf("keychain denied as expected: %v", err)
}
