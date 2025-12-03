package kubernetes

import (
	"context"
	"net"
	"sync"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

type KubernetesProxyConfig struct {
	TargetApiServer string
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

func NewKubernetesProxy(config KubernetesProxyConfig) *KubernetesProxy {
	return &KubernetesProxy{config: config}
}

func (p *KubernetesProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	// TODO:
	return nil
}
