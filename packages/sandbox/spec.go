// Package sandbox applies an OS-level jail (macOS Seatbelt, Linux bubblewrap) around the agent
// spawned by `agent-proxy run`. The profile/argv generators are pure functions of a Spec so
// they are golden-testable on any platform; only the exec wiring is platform-specific.
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type NetMode int

const (
	// HardFence: no external egress, the proxy is the only route out (macOS (deny default) SBPL;
	// Linux empty netns bridged to the proxy socket).
	HardFence NetMode = iota
	// SharedNet shares the host network: the Linux fallback when a network namespace is unavailable,
	// and the deliberate choice for callers with no proxy to route through (PAM agentic access, whose
	// proxies are per-account TCP listeners rather than a forward proxy, so the agent still needs its
	// own egress). Only the network fence weakens; the credential controls are unchanged.
	SharedNet
)

// Spec is the in-memory policy for one wrapped command. Nothing here is persisted.
type Spec struct {
	Enabled bool // false => --no-sandbox: run uncontained

	// ReadPaths (--allow-read) re-open paths inside DenyPaths. Reads are broadly allowed by default,
	// so these only matter as exceptions to the deny set, and never grant write.
	ReadPaths  []string
	WritePaths []string
	DenyPaths  []string // read-denied credential paths, subtracted from the broad read allow

	// DenySockets are unix sockets the child must not be able to connect to, for callers that allow
	// unrestricted egress. A DenyPaths entry does not cover one: connecting to a unix socket is a
	// network-outbound operation on macOS, not a file read, so a path mask leaves it reachable. The
	// hard fence needs none of these, since its loopback-only egress rule already denies them.
	//
	// Entries must name the resolved path: seatbelt matches after symlink resolution, so denying a
	// symlink to a socket does nothing.
	DenySockets []string

	Cwd     string
	TempDir string // per-run 0700 dir: CA cert, and the unix socket on the Linux hard fence

	// LoopbackPort is the proxy's TCP port (macOS / Linux shared-net) or the in-namespace bridge port
	// (Linux hard fence); ProxySocket is the proxy's unix socket, set only on the hard fence.
	LoopbackPort int
	ProxySocket  string

	Env     []string // fully-prepared, scrubbed child environment
	NetMode NetMode

	// AllowTrustd lets macOS evaluate cert trust, so Go tools like gh accept the proxy's leaves.
	AllowTrustd bool
}

// DefaultDenyPaths returns the credential paths denied by default, resolved against home. runtimeDir
// is the per-user runtime directory (/run/user/<uid> on Linux, empty elsewhere): it holds the session
// bus and other host IPC sockets, which are not namespaced and would otherwise be reachable.
func DefaultDenyPaths(home, runtimeDir string) []string {
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
	paths := make([]string, 0, len(rel)+1)
	for _, r := range rel {
		paths = append(paths, home+"/"+r)
	}
	if runtimeDir != "" {
		paths = append(paths, runtimeDir)
	}
	return paths
}

// AgentStateWritePaths returns the state paths the supported agents need to write: sessions,
// transcripts, history and config. Without them an agent starts but cannot record anything, which
// surfaces as permission-denied writes rather than as a sandbox error.
//
// Only paths that already exist are returned, since bwrap --bind fails on a missing source.
//
// Shared by every caller that sandboxes an agent, so that adding support for one does not mean
// remembering to widen a second copy of this list somewhere else.
func AgentStateWritePaths(home string) []string {
	if home == "" {
		return nil
	}
	candidates := []string{
		filepath.Join(home, ".claude"),      // Claude Code state (sessions, history, cache)
		filepath.Join(home, ".claude.json"), // Claude Code top-level config
		filepath.Join(home, ".codex"),       // Codex state
		filepath.Join(home, ".gemini"),      // Gemini CLI state
	}

	var paths []string
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			paths = append(paths, path)
		}
	}
	return paths
}

// HostRuntimeDir is the per-user runtime directory holding host IPC sockets: the session bus and
// friends. Linux only, because those sockets are not namespaced there; empty elsewhere.
//
// Scrubbing XDG_RUNTIME_DIR from the child is not enough on its own, since the directory is still on
// disk and unix sockets ignore the network namespace, so callers pass this to DefaultDenyPaths to
// have it masked as well.
func HostRuntimeDir() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return dir
	}
	return fmt.Sprintf("/run/user/%d", os.Getuid())
}

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

// dedupeSorted drops empties and duplicates and sorts, so the generators emit deterministic output.
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
