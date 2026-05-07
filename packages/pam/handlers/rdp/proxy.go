package rdp

import (
	"github.com/Infisical/infisical-merge/packages/pam/session"
)

type RDPProxyConfig struct {
	TargetHost     string
	TargetPort     uint16
	InjectUsername string
	InjectPassword string
	SessionID      string
	// Retained for API symmetry with other PAM handlers; not yet written
	// through (no RDP session recording in this MVP).
	SessionLogger session.SessionLogger
}

type RDPProxy struct {
	config RDPProxyConfig
}

func NewRDPProxy(config RDPProxyConfig) *RDPProxy {
	return &RDPProxy{config: config}
}
