package sandbox

import (
	"strings"
	"testing"
)

func testSpec() Spec {
	return Spec{
		Enabled:      true,
		Cwd:          "/Users/dev/project",
		TempDir:      "/private/tmp/infisical-run-abc",
		LoopbackPort: 51234,
		DenyPaths: []string{
			"/Users/dev/.aws",
			"/Users/dev/.infisical",
			"/Users/dev/.ssh",
		},
		WritePaths: []string{"/Users/dev/.cache"},
		NetMode:    HardFence,
	}
}

func TestSeatbeltProfileStructure(t *testing.T) {
	p := generateSeatbeltProfile(testSpec())

	mustContain := []string{
		"(version 1)",
		"(deny default)",
		"(allow pseudo-tty)",
		// Egress must be filtered on remote + the exact loopback port, never local.
		`(allow network-outbound (remote ip "localhost:51234"))`,
		// Credential deny paths (sorted).
		`(deny file-read* (subpath "/Users/dev/.aws"))`,
		`(deny file-read* (subpath "/Users/dev/.infisical"))`,
		`(deny file-read* (subpath "/Users/dev/.ssh"))`,
		// Writable cwd + tempdir + operator path.
		`(allow file-write* (subpath "/Users/dev/project"))`,
		`(allow file-write* (subpath "/private/tmp/infisical-run-abc"))`,
		`(allow file-write* (subpath "/Users/dev/.cache"))`,
	}
	for _, s := range mustContain {
		if !strings.Contains(p, s) {
			t.Errorf("profile missing expected line:\n  %s\n---\n%s", s, p)
		}
	}

	mustNotContain := []string{
		// The two keychain services must be omitted so (deny default) blocks the keyring.
		"com.apple.securityd.xpc",
		"com.apple.SecurityServer",
		// trustd omitted so the injected CA bundle is the trust path.
		"com.apple.trustd",
		// Never filter egress on local ip (silently admits all egress).
		"(allow network-outbound (local ip",
		// No blanket network allow.
		"(allow network*)",
	}
	for _, s := range mustNotContain {
		if strings.Contains(p, s) {
			t.Errorf("profile must NOT contain %q\n---\n%s", s, p)
		}
	}
}

func TestSeatbeltProfileTrustdToggle(t *testing.T) {
	spec := testSpec()

	// Default: trustd omitted so native-trust TLS falls back to the injected CA bundle.
	if strings.Contains(generateSeatbeltProfile(spec), "com.apple.trustd") {
		t.Error("trustd must be omitted when AllowTrustd is false")
	}

	// AllowTrustd: trustd allowed, but keychain secret services stay omitted (token stays unreadable).
	spec.AllowTrustd = true
	p := generateSeatbeltProfile(spec)
	if !strings.Contains(p, `(global-name "com.apple.trustd")`) {
		t.Errorf("expected trustd allowed when AllowTrustd is true\n%s", p)
	}
	for _, s := range []string{"com.apple.securityd.xpc", "com.apple.SecurityServer"} {
		if strings.Contains(p, s) {
			t.Errorf("keychain secret service %q must stay omitted even with AllowTrustd", s)
		}
	}
}

func TestSeatbeltProfileEscaping(t *testing.T) {
	spec := testSpec()
	spec.DenyPaths = []string{`/Users/dev/weird "dir"\path`}
	p := generateSeatbeltProfile(spec)
	if !strings.Contains(p, `(subpath "/Users/dev/weird \"dir\"\\path")`) {
		t.Errorf("path not escaped correctly:\n%s", p)
	}
}

func TestSeatbeltProfileDenyBeforeAllowWrite(t *testing.T) {
	// A denied read path that also appears as a write path: the write allow is emitted, but the read
	// deny must still be present (SBPL is last-match-wins, and this documents the ordering intent).
	p := generateSeatbeltProfile(testSpec())
	readAllow := strings.Index(p, "(allow file-read*)")
	firstDeny := strings.Index(p, "(deny file-read*")
	if readAllow == -1 || firstDeny == -1 || firstDeny < readAllow {
		t.Fatalf("expected broad read allow before the deny subtractions (allow=%d deny=%d)", readAllow, firstDeny)
	}
}

func TestSeatbeltProfileReadExceptions(t *testing.T) {
	spec := testSpec()
	spec.ReadPaths = []string{"/Users/dev/.aws/config"}
	p := generateSeatbeltProfile(spec)

	allowLine := `(allow file-read* (subpath "/Users/dev/.aws/config"))`
	if !strings.Contains(p, allowLine) {
		t.Fatalf("missing the read exception:\n%s", p)
	}
	// SBPL is last-match-wins, so the exception must come after the deny it overrides...
	denyRead := strings.Index(p, `(deny file-read* (subpath "/Users/dev/.aws"))`)
	exception := strings.Index(p, allowLine)
	if denyRead == -1 || exception < denyRead {
		t.Fatalf("read exception must follow the read deny (deny=%d exception=%d)", denyRead, exception)
	}
	// ...and before the trailing write denies, so re-opening a read never grants a write.
	writeDeny := strings.Index(p, `(deny file-write* (subpath "/Users/dev/.aws"))`)
	if writeDeny == -1 || writeDeny < exception {
		t.Fatalf("write denies must still come last (exception=%d writeDeny=%d)", exception, writeDeny)
	}
	if strings.Contains(p, `(allow file-write* (subpath "/Users/dev/.aws/config"))`) {
		t.Error("a read exception must never emit a write allow")
	}
}

func TestSeatbeltProfileNoReadExceptionSection(t *testing.T) {
	// With no --allow-read, the profile must not gain an empty exceptions section.
	if strings.Contains(generateSeatbeltProfile(testSpec()), "Read exceptions") {
		t.Error("no read exceptions should be emitted when ReadPaths is empty")
	}
}

func TestPassthroughBackendWrap(t *testing.T) {
	spec := Spec{Enabled: false, Env: []string{"FOO=bar"}}
	b := NewBackend(spec)
	if _, ok := b.(passthroughBackend); !ok {
		t.Fatalf("expected passthrough backend when Sandbox=false, got %T", b)
	}
	cmd, err := b.Wrap(spec, []string{"echo", "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Args[0] != "echo" || cmd.Args[1] != "hi" {
		t.Fatalf("unexpected argv: %v", cmd.Args)
	}
	if len(cmd.Env) != 1 || cmd.Env[0] != "FOO=bar" {
		t.Fatalf("env not set from spec: %v", cmd.Env)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestDefaultDenyPaths(t *testing.T) {
	got := DefaultDenyPaths("/Users/dev", "/run/user/1000")
	want := map[string]bool{
		"/Users/dev/.infisical": true,
		"/Users/dev/.aws":       true,
		"/Users/dev/.ssh":       true,
	}
	for _, p := range got {
		delete(want, p)
	}
	if len(want) != 0 {
		t.Fatalf("DefaultDenyPaths missing entries: %v", want)
	}
	if want := "/run/user/1000"; !contains(got, want) {
		t.Fatalf("DefaultDenyPaths must include the runtime dir %q", want)
	}
	if DefaultDenyPaths("", "") != nil {
		t.Fatal("DefaultDenyPaths(\"\") should be nil")
	}
}
