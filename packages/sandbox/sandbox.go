package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

var errUnsupportedPlatform = errors.New("sandbox: unsupported platform")

type PreflightResult struct {
	Supported           bool   // false => no OS sandbox here (e.g. Windows, bwrap missing)
	FallbackToSharedNet bool   // Linux: empty-netns hard fence unavailable, downgrade to shared net
	UsesBridge          bool   // Linux hard fence only: proxy on a unix socket, reached via the bridge
	Reason              string // user-facing explanation for an unsupported result or a fallback
}

// Backend applies an OS sandbox to a command. Wrap returns an *exec.Cmd ready to Start (stdio
// inherited, Env from the spec) but does not start it.
type Backend interface {
	Preflight(spec SandboxSpec) (PreflightResult, error)
	Wrap(spec SandboxSpec, argv []string) (*exec.Cmd, error)
}

// NewBackend returns the platform backend, or the uncontained passthrough backend for --no-sandbox.
func NewBackend(spec SandboxSpec) Backend {
	if !spec.Sandbox {
		return passthroughBackend{}
	}
	return osBackend()
}

// passthroughBackend runs the command uncontained (--no-sandbox): proxy and scrubbed env still apply.
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
