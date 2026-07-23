// Package sandbox applies an OS-level jail (macOS Seatbelt, Linux bubblewrap) around the agent
// spawned by `agent-proxy run`. The profile/argv generators are pure functions of a SandboxSpec so
// they are golden-testable on any platform; only the exec wiring is platform-specific.
package sandbox

type NetMode int

const (
	// HardFence: no external egress, the proxy is the only route out (macOS (deny default) SBPL;
	// Linux empty netns bridged to the proxy socket).
	HardFence NetMode = iota
	// SharedNet: host network shared. macOS (SBPL still fences to loopback) and the Linux fallback
	// when unprivileged user namespaces are restricted. Only the network fence weakens, not the
	// credential controls.
	SharedNet
)

// SandboxSpec is the in-memory policy for one wrapped command. Nothing here is persisted.
type SandboxSpec struct {
	Sandbox bool // false => --no-sandbox: run uncontained

	ReadPaths  []string
	WritePaths []string
	DenyPaths  []string // read-denied credential paths, subtracted from the broad read allow

	Cwd     string
	TempDir string // per-run 0700 dir: CA cert, and the unix socket on the Linux hard fence

	// LoopbackPort is the proxy's TCP port (macOS / Linux shared-net) or the in-namespace bridge port
	// (Linux hard fence); ProxySocket is the proxy's unix socket, set only on the hard fence.
	LoopbackPort int
	ProxySocket  string

	Env     []string // fully-prepared, scrubbed child environment
	NetMode NetMode
}

// DefaultDenyPaths returns the credential paths denied by default, resolved against home.
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
