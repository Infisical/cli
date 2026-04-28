package rdp

import (
	"github.com/Infisical/infisical-merge/packages/pam/session"
)

type RDPProxyConfig struct {
	TargetHost     string
	TargetPort     uint16
	InjectUsername string
	InjectPassword string
	// Empty for local accounts; AD domain name (e.g. "CORP.EXAMPLE.COM") for
	// domain-joined NTLM CredSSP. Backend session credentials populate this.
	InjectDomain string
	SessionID    string
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
