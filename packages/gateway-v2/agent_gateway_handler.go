package gatewayv2

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"

	"github.com/Infisical/infisical-merge/packages/agentproxy"
	"github.com/Infisical/infisical-merge/packages/agentproxy/tunnel"
	"github.com/rs/zerolog/log"
)

// The protocol version the client and gateway agree on before any tunnel opens. Negotiating up front means a
// version mismatch is an actionable message rather than mis-framed bytes much later.
const agentGatewayProtocolVersion = 1

const (
	CapabilityAgentGateway         = "agentProxy"
	CapabilityAgentGatewayProtocol = "agentProxyProtocol"
)

type agentGatewayPreamble struct {
	ProtocolVersion int    `json:"protocolVersion"`
	ClientVersion   string `json:"clientVersion"`
}

type agentGatewayPreambleAck struct {
	ProtocolVersion int    `json:"protocolVersion"`
	Error           string `json:"error,omitempty"`
}

// The broker is created on first use and shared across sessions. Constructing it lazily means a gateway that
// never brokers never signs a CA intermediate and never holds a credential; the pieces it shares between
// sessions (CA manager, upstream transport, bundle cache) are all credential-free or session-keyed.
func (g *Gateway) agentBroker() (*agentproxy.Broker, error) {
	g.agentBrokerOnce.Do(func() {
		g.agentBrokerInstance, g.agentBrokerErr = agentproxy.NewBroker(agentproxy.BrokerOptions{
			Token: func() string {
				g.agentBrokerTokenMu.RLock()
				defer g.agentBrokerTokenMu.RUnlock()
				return g.agentBrokerToken
			},
		})
	})
	return g.agentBrokerInstance, g.agentBrokerErr
}

// registerAgentSession records a live transport so it can be dropped on request, and returns the deregister.
func (g *Gateway) registerAgentSession(sessionID string, drop func()) func() {
	g.agentSessionsMu.Lock()
	g.agentSessions[sessionID] = append(g.agentSessions[sessionID], drop)
	index := len(g.agentSessions[sessionID]) - 1
	g.agentSessionsMu.Unlock()

	return func() {
		g.agentSessionsMu.Lock()
		defer g.agentSessionsMu.Unlock()
		entries := g.agentSessions[sessionID]
		if index < len(entries) {
			// Nil rather than reslice: another transport's closure holds an index into this slice.
			entries[index] = nil
		}
		for _, entry := range entries {
			if entry != nil {
				return
			}
		}
		delete(g.agentSessions, sessionID)
	}
}

// cancelAgentGatewaySession drops every transport serving a session, so its credentials leave memory and its
// in-flight requests fail rather than completing after the session was ended.
func (g *Gateway) cancelAgentGatewaySession(sessionID string) {
	if sessionID == "" {
		return
	}

	g.agentSessionsMu.Lock()
	drops := g.agentSessions[sessionID]
	delete(g.agentSessions, sessionID)
	g.agentSessionsMu.Unlock()

	for _, drop := range drops {
		if drop != nil {
			drop()
		}
	}

	// Also drop the cached bundle: a session whose transport had already gone must not leave resolved
	// credentials behind for the idle sweep to find.
	if broker := g.agentBrokerInstance; broker != nil {
		broker.ForgetSession(sessionID)
	}

	log.Info().Msgf("Agent gateway session cancelled by Infisical [sessionId=%s] [transports=%d]", sessionID, len(drops))
}

// serveAgentGateway turns one multiplexed mTLS connection into many brokered requests. The gateway speaks the
// forward-proxy protocol itself, so everything inside packages/agentproxy runs unchanged; only the listener
// is different. Session identity comes from the certificate and is captured in the closure below, so no
// request can select a different session.
func (g *Gateway) serveAgentGateway(tlsConn *tls.Conn, reader *bufio.Reader, config *ForwardConfig) error {
	broker, err := g.agentBroker()
	if err != nil {
		return fmt.Errorf("failed to start the agent broker: %w", err)
	}

	if err := negotiateAgentGatewayPreamble(tlsConn, reader); err != nil {
		return err
	}

	session := agentproxy.Session{
		ID:               config.AgentGatewayInfo.SessionId,
		AgentGatewayID:   config.AgentGatewayInfo.AgentGatewayID,
		AgentGatewayName: config.AgentGatewayInfo.AgentGatewayName,
		ActorType:        string(config.ActorType),
		UnmatchedHost:    config.AgentGatewayInfo.UnmatchedHostPolicy,
		AllowedHosts:     config.AgentGatewayInfo.AllowedHosts,
		// A certificate's own expiry bounds the connection: a long-lived mux must not outlive the
		// authorization that opened it.
		ExpiresAt: tlsConn.ConnectionState().PeerCertificates[0].NotAfter,
	}

	log.Info().Msgf(
		"Agent gateway session started [agentGateway=%s] [sessionId=%s]",
		session.AgentGatewayName,
		session.ID,
	)

	deregister := g.registerAgentSession(session.ID, func() { _ = tlsConn.Close() })

	// Whatever happens, this session's credentials leave memory when its transport does, rather than waiting
	// for an idle sweep.
	defer func() {
		deregister()
		broker.ForgetSession(session.ID)
		log.Info().Msgf("Agent gateway session ended [sessionId=%s]", session.ID)
	}()

	return tunnel.Serve(tlsConn, reader, func(stream net.Conn) {
		broker.ServeConn(stream, session)
	})
}

// The preamble is a single JSON line each way. It is deliberately not part of the tunnel: a client that
// speaks a protocol this gateway does not understand has to learn that before it starts framing streams.
func negotiateAgentGatewayPreamble(conn net.Conn, reader *bufio.Reader) error {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("failed to read the agent gateway preamble: %w", err)
	}

	var preamble agentGatewayPreamble
	if err := json.Unmarshal(line, &preamble); err != nil {
		return fmt.Errorf("failed to parse the agent gateway preamble: %w", err)
	}

	ack := agentGatewayPreambleAck{ProtocolVersion: agentGatewayProtocolVersion}
	if preamble.ProtocolVersion != agentGatewayProtocolVersion {
		ack.Error = fmt.Sprintf(
			"this gateway speaks agent gateway protocol %d, the client asked for %d; upgrade whichever is older",
			agentGatewayProtocolVersion,
			preamble.ProtocolVersion,
		)
	}

	encoded, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("failed to write the agent gateway preamble ack: %w", err)
	}

	if ack.Error != "" {
		return fmt.Errorf("%s", ack.Error)
	}
	return nil
}
