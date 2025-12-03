package kubernetes

import (
	"sync"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

type KubernetesProxyConfig struct {
	TargetUrl       string
	AuthMethod      string
	InjectAuthToken string
	SessionID       string
	SessionLogger   session.SessionLogger
}

type KubernetesProxy struct {
	config      KubernetesProxyConfig
	mutex       sync.Mutex
	sessionData []byte // Store session data for logging
	inputBuffer []byte // Buffer for input data to batch keystrokes
}
