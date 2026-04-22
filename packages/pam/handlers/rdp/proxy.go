package rdp

import (
	"github.com/Infisical/infisical-merge/packages/pam/session"
)

// RDPProxyConfig is what the gateway's PAM dispatcher passes to
// [NewRDPProxy] when routing a Windows/RDP session.
type RDPProxyConfig struct {
	TargetHost     string
	TargetPort     uint16
	InjectUsername string
	InjectPassword string
	SessionID      string

	// SessionLogger is retained on the config for API symmetry with the
	// other PAM handlers. The current bridge has no event tap (no RDP
	// session recording yet) so nothing is actually written through it,
	// but the dispatcher expects to hand one in per session and may start
	// shipping events through it in a later phase.
	SessionLogger session.SessionLogger
}

// RDPProxy is the gateway-side handler for a Windows/RDP PAM session.
// It wraps an [RDPProxyConfig] and implements the same HandleConnection
// shape as SSH / Postgres / Redis / etc.
type RDPProxy struct {
	config RDPProxyConfig
}

// NewRDPProxy constructs a proxy. The actual session work happens in
// HandleConnection (whose implementation is in a platform-specific file).
func NewRDPProxy(config RDPProxyConfig) *RDPProxy {
	return &RDPProxy{config: config}
}
