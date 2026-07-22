package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

var errUnsupportedPlatform = errors.New("sandbox: unsupported platform")

// PreflightResult reports whether the OS sandbox can run here and, on Linux, whether the hard fence
// must fall back to shared networking.
type PreflightResult struct {
	// Supported is false when no OS sandbox is available (e.g. Windows, or bwrap missing). The caller
	// then either errors or, if the user passed --no-sandbox, runs uncontained.
	Supported bool
	// FallbackToSharedNet is set on Linux when the empty-netns hard fence cannot start (restricted
	// unprivileged user namespaces). The caller downgrades NetMode to SharedNet and warns once.
	FallbackToSharedNet bool
	// UsesBridge is true only on the Linux hard-fence path: the child runs in an empty network
	// namespace and reaches the proxy through the in-namespace bridge, so the proxy must listen on a
	// pathname unix socket (not TCP) and the child's HTTP(S)_PROXY targets the bridge's loopback port.
	// macOS, the Linux shared-net fallback, and --no-sandbox all leave this false (TCP loopback proxy).
	UsesBridge bool
	// Reason explains an unsupported result or a fallback, suitable for a user-facing message.
	Reason string
}

// Backend applies an OS sandbox to a command.
type Backend interface {
	// Preflight reports whether this backend can run the given spec here, and any required fallback.
	Preflight(spec SandboxSpec) (PreflightResult, error)
	// Wrap returns an *exec.Cmd ready to Start: the target command wrapped by the OS sandbox, with
	// stdio inherited and Env set from the spec. It does not Start the process.
	Wrap(spec SandboxSpec, argv []string) (*exec.Cmd, error)
}

// NewBackend returns the OS sandbox backend for the current platform. When spec.Sandbox is false it
// returns the passthrough backend regardless of platform.
func NewBackend(spec SandboxSpec) Backend {
	if !spec.Sandbox {
		return passthroughBackend{}
	}
	return osBackend()
}

// passthroughBackend runs the command uncontained (the --no-sandbox path). The ephemeral proxy and
// the scrubbed env still apply; only the OS controls are dropped.
type passthroughBackend struct{}

func (passthroughBackend) Preflight(SandboxSpec) (PreflightResult, error) {
	return PreflightResult{Supported: true}, nil
}

func (passthroughBackend) Wrap(spec SandboxSpec, argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("sandbox: empty command")
	}
	// #nosec G204 -- the command is provided directly by the operator running the CLI
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = spec.Env
	return cmd, nil
}
