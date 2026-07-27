// Package sandbox applies an OS-level jail (macOS Seatbelt, Linux bubblewrap) around the agent
// spawned by `agent-proxy run`. The profile/argv generators are pure functions of a Spec so
// they are golden-testable on any platform; only the exec wiring is platform-specific.
package sandbox

import (
	"sort"
	"strings"
)

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

// Spec is the in-memory policy for one wrapped command. Nothing here is persisted.
type Spec struct {
	Enabled bool // false => --no-sandbox: run uncontained

	// ReadPaths re-open specific paths inside DenyPaths (--allow-read). Reads are allowed broadly by
	// default, so these only matter as exceptions carved out of the deny set; they never grant write.
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

	// AllowTrustd allows the macOS cert-trust evaluation service so native-trust tools (Go CLIs like
	// gh) can verify the proxy's leaves against a CA trusted in the keychain. securityd (keychain
	// secret reads) stays blocked regardless, so the login token remains unreadable. macOS only.
	AllowTrustd bool
}

// DefaultDenyPaths returns the credential paths denied by default, resolved against home.
func DefaultDenyPaths(home string) []string {
	if home == "" {
		return nil
	}
	rel := []string{
		".infisical",
		"infisical-keyring", // file-vault backend store (JWT + backup key); default on headless Linux
		".aws",
		".ssh",
		".config/gcloud",
		".azure",
		".kube",
		".netrc",
		".docker/config.json",
		".config/infisical",
		".config/gh",       // GitHub CLI token
		".git-credentials", // git stored credentials
		".npmrc",           // npm auth token
		".gnupg",           // GPG private keys
	}
	paths := make([]string, 0, len(rel))
	for _, r := range rel {
		paths = append(paths, home+"/"+r)
	}
	return paths
}

// containsString reports whether s is present in list.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// underAny reports whether path is equal to, or nested inside, any of the given roots.
func underAny(path string, roots []string) bool {
	for _, root := range roots {
		if root == "" {
			continue
		}
		if path == root || strings.HasPrefix(path, strings.TrimSuffix(root, "/")+"/") {
			return true
		}
	}
	return false
}

// dedupeSorted drops empty strings and duplicates, and sorts, so the profile/argv generators emit
// deterministic (golden-testable) output. Shared by the Seatbelt and bwrap generators.
func dedupeSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
