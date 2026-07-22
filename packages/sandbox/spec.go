// Package sandbox builds and applies an OS-level jail around the agent process spawned by
// `infisical secrets agent-proxy run`. It is the trust boundary for local coupled mode: the
// developer's real credentials exist on the same machine, so the sandbox is what stops the
// untrusted agent from reading them. macOS uses Seatbelt (sandbox-exec); Linux uses bubblewrap.
//
// The profile/argv generators are pure functions of a SandboxSpec (no OS calls), so they are
// unit-testable with golden files on any platform. Only the exec wiring is platform-specific.
package sandbox

import "runtime"

// NetMode selects how the child reaches the network.
type NetMode int

const (
	// HardFence is the default: no external egress. On macOS a (deny default) SBPL profile permits
	// only loopback to the proxy port; on Linux an empty network namespace is bridged to the proxy's
	// unix socket. The proxy is the child's only route out.
	HardFence NetMode = iota
	// SharedNet shares the host network. Used on macOS (loopback is already isolated by SBPL) and as
	// the Linux fallback when unprivileged user namespaces are restricted (Ubuntu 24.04). It weakens
	// only the network fence; the credential controls (env scrub, keyring block, fs deny) are
	// unaffected.
	SharedNet
)

// SandboxSpec is the complete, in-memory policy for one wrapped command. Nothing here is persisted.
type SandboxSpec struct {
	// Sandbox=false is the --no-sandbox path: run the child uncontained (proxy + scrubbed env still
	// apply). Backends return a plain exec.Cmd in that case.
	Sandbox bool

	// ReadPaths are extra readable paths beyond the always-included set (cwd, system libraries).
	ReadPaths []string
	// WritePaths are extra writable paths beyond the always-included set (cwd, tmp). Write implies read.
	WritePaths []string
	// DenyPaths are read-denied even though they fall under a broad read allow: the credential files
	// (~/.infisical, ~/.aws, ~/.ssh, ...). On Linux they are simply never bound into the namespace.
	DenyPaths []string

	// Cwd is the working directory, always readable and writable.
	Cwd string
	// TempDir is the per-run 0700 scratch dir (CA cert, unix socket, log). Readable inside the box.
	TempDir string

	// LoopbackPort is the TCP port the proxy listens on (macOS / Linux shared-net), and the port the
	// in-namespace bridge listens on (Linux hard fence). The only permitted egress port on macOS.
	LoopbackPort int
	// ProxySocket is the pathname unix socket the proxy listens on (Linux hard fence only). When set,
	// the bridge forwards LoopbackPort -> this socket.
	ProxySocket string

	// Env is the fully-prepared child environment (already scrubbed; proxy + CA + placeholders).
	Env []string

	// AllowHosts are extra hostnames the agent may reach; informational for the sandbox layer (host
	// policy is enforced by the proxy), carried here for completeness.
	AllowHosts []string

	NetMode NetMode
}

// DefaultDenyPaths returns the credential paths denied by default, resolved against the given home
// directory. Kept here (not in a backend) so both OS backends and the tests agree on the set.
func DefaultDenyPaths(home string) []string {
	if home == "" {
		return nil
	}
	rel := []string{
		".infisical",
		".aws",
		".ssh",
		".config/gcloud",
		".azure",
		".kube",
		".netrc",
		".docker/config.json",
		".config/infisical",
	}
	paths := make([]string, 0, len(rel))
	for _, r := range rel {
		paths = append(paths, home+"/"+r)
	}
	return paths
}

// CurrentOS reports the platform the process is running on. Split out so tests can reason about it.
func CurrentOS() string { return runtime.GOOS }
