package mssql

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

type MssqlProxyConfig struct {
	TargetAddr     string
	InjectUsername string
	InjectPassword string
	InjectDatabase string
	EnableTLS      bool
	TLSConfig      *tls.Config
	SessionID      string
	SessionLogger  session.SessionLogger
}

type pendingQuery struct {
	sql       string
	timestamp time.Time
}

type MssqlProxy struct {
	config       MssqlProxyConfig
	mu           sync.Mutex
	pendingQuery *pendingQuery
}

func NewMssqlProxy(config MssqlProxyConfig) *MssqlProxy {
	return &MssqlProxy{config: config}
}

func (p *MssqlProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	defer p.config.SessionLogger.Close()

	log.Info().Str("sessionID", p.config.SessionID).Msg("MSSQL PAM session started")

	// === PHASE 1: Handle client handshake (proxy acts as MSSQL server) ===
	log.Info().Str("sessionID", p.config.SessionID).Msg("Starting client handshake...")
	if err := p.handleClientHandshake(clientConn); err != nil {
		return fmt.Errorf("client handshake failed: %w", err)
	}
	log.Info().Str("sessionID", p.config.SessionID).Msg("Client handshake completed")

	// === PHASE 2: Connect to server and authenticate (proxy acts as MSSQL client) ===
	serverConn, loginResponse, err := p.connectAndAuthenticateToServer()
	if err != nil {
		return fmt.Errorf("server connection failed: %w", err)
	}
	defer serverConn.Close()

	// === PHASE 3: Forward server's login response to client ===
	for _, pkt := range loginResponse {
		if err := pkt.Write(clientConn); err != nil {
			return fmt.Errorf("forward login response to client: %w", err)
		}
	}
	log.Info().Str("sessionID", p.config.SessionID).Msg("Forwarded login response to client")

	// === PHASE 4: Proxy traffic - just pipe bytes ===
	errCh := make(chan error, 2)
	go p.proxyToServer(clientConn, serverConn, errCh)
	go p.proxyToClient(serverConn, clientConn, errCh)

	select {
	case err := <-errCh:
		if err != nil && err != io.EOF {
			log.Debug().Err(err).Str("sessionID", p.config.SessionID).Msg("Connection ended")
		}
	case <-ctx.Done():
	}

	log.Info().Str("sessionID", p.config.SessionID).Msg("MSSQL PAM session ended")
	return nil
}

// handleClientHandshake handles the client's PRELOGIN and LOGIN7, responding as a server
func (p *MssqlProxy) handleClientHandshake(clientConn net.Conn) error {
	// 1. Read client PRELOGIN
	log.Info().Str("sessionID", p.config.SessionID).Msg("Waiting for client PRELOGIN...")
	clientPrelogin, err := ReadAllPackets(clientConn)
	if err != nil {
		return fmt.Errorf("read client prelogin: %w", err)
	}
	if len(clientPrelogin) == 0 || clientPrelogin[0].Type != PacketTypePrelogin {
		return fmt.Errorf("expected PRELOGIN from client, got 0x%02X", clientPrelogin[0].Type)
	}

	log.Info().Str("sessionID", p.config.SessionID).Msg("Received client PRELOGIN")

	// 2. Send our own PRELOGIN response (no encryption)
	preloginResp := BuildPreloginResponse(EncryptNotSup)
	respPkt := &TDSPacket{
		Type:     PacketTypeTabularResult,
		Status:   StatusEOM,
		PacketID: 1,
		Payload:  preloginResp,
	}
	if err := respPkt.Write(clientConn); err != nil {
		return fmt.Errorf("send prelogin response: %w", err)
	}

	log.Info().Str("sessionID", p.config.SessionID).Msg("Sent PRELOGIN response (no encryption)")

	// 3. Read client LOGIN7
	log.Info().Str("sessionID", p.config.SessionID).Msg("Waiting for client LOGIN7...")
	loginPackets, err := ReadAllPackets(clientConn)
	if err != nil {
		return fmt.Errorf("read login: %w", err)
	}
	if len(loginPackets) == 0 {
		return fmt.Errorf("no login packet received")
	}

	if loginPackets[0].Type == PacketTypeSSPI {
		return fmt.Errorf("Windows/SSPI authentication is not supported; use SQL authentication")
	}
	if loginPackets[0].Type != PacketTypeLogin7 {
		return fmt.Errorf("expected LOGIN7 from client, got packet type 0x%02X", loginPackets[0].Type)
	}

	// Parse LOGIN7 to validate (we don't use client's credentials)
	loginPayload := CombinePayloads(loginPackets)
	loginMsg, err := ParseLogin7(loginPayload)
	if err != nil {
		return fmt.Errorf("parse login: %w", err)
	}

	if err := CheckLogin7Supported(loginMsg); err != nil {
		return err
	}

	log.Info().
		Str("sessionID", p.config.SessionID).
		Str("clientUser", loginMsg.Username).
		Msg("Received client LOGIN7")

	return nil
}

// connectAndAuthenticateToServer connects to the real server and authenticates with injected credentials
// Returns the server connection and the login response to forward to client
func (p *MssqlProxy) connectAndAuthenticateToServer() (net.Conn, []*TDSPacket, error) {
	// Connect to backend
	serverConn, err := net.Dial("tcp", p.config.TargetAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial server: %w", err)
	}

	// 1. Send our PRELOGIN to server
	encOption := uint8(EncryptNotSup)
	if p.config.EnableTLS {
		encOption = EncryptOn
	}
	preloginReq := BuildPreloginRequest(encOption)
	preloginPkt := &TDSPacket{
		Type:     PacketTypePrelogin,
		Status:   StatusEOM,
		PacketID: 1,
		Payload:  preloginReq,
	}
	if err := preloginPkt.Write(serverConn); err != nil {
		serverConn.Close()
		return nil, nil, fmt.Errorf("send prelogin to server: %w", err)
	}
	log.Info().
		Str("sessionID", p.config.SessionID).
		Uint8("encOption", encOption).
		Msg("Sent PRELOGIN to server")

	// 2. Read server's PRELOGIN response
	serverPreloginPkts, err := ReadAllPackets(serverConn)
	if err != nil {
		serverConn.Close()
		return nil, nil, fmt.Errorf("read server prelogin: %w", err)
	}

	// 3. Handle TLS based on EnableTLS config
	if p.config.EnableTLS {
		if p.config.TLSConfig == nil {
			serverConn.Close()
			return nil, nil, fmt.Errorf("TLS requested but no TLS configuration provided")
		}

		// Check server's encryption response
		serverPayload := CombinePayloads(serverPreloginPkts)
		serverEnc := GetPreloginEncryption(serverPayload)

		log.Info().
			Str("sessionID", p.config.SessionID).
			Uint8("serverEnc", serverEnc).
			Msg("Server PRELOGIN encryption response")

		if serverEnc == EncryptNotSup {
			serverConn.Close()
			return nil, nil, fmt.Errorf("server does not support TLS encryption")
		}

		// MSSQL performs TLS handshake wrapped inside TDS PRELOGIN packets.
		// We use a passthrough conn that initially points to TLSHandshakeConn,
		// then switches to the raw connection after handshake completes.
		handshakeConn := NewTLSHandshakeConn(serverConn)
		passthrough := &PassthroughConn{Conn: handshakeConn}
		tlsConn := tls.Client(passthrough, p.config.TLSConfig)

		if err := tlsConn.Handshake(); err != nil {
			serverConn.Close()
			return nil, nil, fmt.Errorf("TLS handshake with server failed: %w", err)
		}

		log.Info().
			Str("sessionID", p.config.SessionID).
			Uint16("tlsVersion", tlsConn.ConnectionState().Version).
			Str("cipherSuite", tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite)).
			Msg("TLS handshake completed")

		// After TLS handshake, switch the passthrough to point directly to the
		// raw TCP connection. TLS records will now go directly to TCP.
		passthrough.Conn = serverConn
		serverConn = tlsConn
		log.Info().Str("sessionID", p.config.SessionID).Msg("TLS established with server")
	}

	// 4. Send LOGIN7 with injected credentials
	loginMsg := &Login7Message{
		Username: p.config.InjectUsername,
		Password: p.config.InjectPassword,
		Database: p.config.InjectDatabase,
		AppName:  "Infisical PAM Proxy",
		Hostname: "infisical-proxy",
	}

	loginPkt := &TDSPacket{
		Type:     PacketTypeLogin7,
		Status:   StatusEOM,
		PacketID: 1,
		Payload:  loginMsg.Encode(),
	}
	if err := loginPkt.Write(serverConn); err != nil {
		serverConn.Close()
		return nil, nil, fmt.Errorf("send login to server: %w", err)
	}

	log.Info().
		Str("sessionID", p.config.SessionID).
		Str("user", p.config.InjectUsername).
		Int("loginPktLen", len(loginPkt.Payload)+TDSHeaderSize).
		Msg("Sent LOGIN7 to server")

	// 5. Read login response - forward to client
	log.Info().Str("sessionID", p.config.SessionID).Msg("Waiting for login response...")
	response, err := ReadAllPackets(serverConn)
	if err != nil {
		serverConn.Close()
		return nil, nil, fmt.Errorf("read login response: %w", err)
	}
	log.Info().
		Str("sessionID", p.config.SessionID).
		Int("responsePackets", len(response)).
		Msg("Received login response")

	respPayload := CombinePayloads(response)
	if ContainsToken(respPayload, TokenError) {
		serverConn.Close()
		return nil, nil, fmt.Errorf("server authentication failed")
	}
	if !ContainsToken(respPayload, TokenLoginAck) {
		serverConn.Close()
		return nil, nil, fmt.Errorf("no login ack from server")
	}

	log.Info().Str("sessionID", p.config.SessionID).Msg("MSSQL server authentication successful")
	return serverConn, response, nil
}

func (p *MssqlProxy) proxyToServer(client, server net.Conn, errCh chan error) {
	defer func() {
		if r := recover(); r != nil {
			errCh <- fmt.Errorf("panic in proxyToServer: %v", r)
		}
	}()

	var payloadBuf []byte
	var currentPktType uint8

	for {
		pkt, err := ReadPacket(client)
		if err != nil {
			errCh <- err
			return
		}

		switch pkt.Type {
		case PacketTypeSQLBatch:
			currentPktType = pkt.Type
			payloadBuf = append(payloadBuf, pkt.Payload...)
			if pkt.IsEOM() {
				sql := ExtractSQL(payloadBuf)
				if sql != "" {
					p.mu.Lock()
					p.pendingQuery = &pendingQuery{
						sql:       sql,
						timestamp: time.Now(),
					}
					p.mu.Unlock()
				}
				payloadBuf = nil
			}

		case PacketTypeRPCRequest:
			currentPktType = pkt.Type
			payloadBuf = append(payloadBuf, pkt.Payload...)
			if pkt.IsEOM() {
				rpcName := ExtractRPCText(payloadBuf)
				p.mu.Lock()
				p.pendingQuery = &pendingQuery{
					sql:       rpcName,
					timestamp: time.Now(),
				}
				p.mu.Unlock()
				payloadBuf = nil
			}

		case PacketTypeBulkLoad:
			if currentPktType != PacketTypeBulkLoad {
				currentPktType = PacketTypeBulkLoad
				p.mu.Lock()
				p.pendingQuery = &pendingQuery{
					sql:       "BULK INSERT",
					timestamp: time.Now(),
				}
				p.mu.Unlock()
			}

		case PacketTypeAttention:
			// Attention/cancel signal - let it through

		case PacketTypeTransMgrReq:
			// Transaction management (BEGIN/COMMIT/ROLLBACK) - let it through

		default:
			log.Warn().
				Str("sessionID", p.config.SessionID).
				Uint8("packetType", pkt.Type).
				Msg("Blocked unrecognized packet type (cannot be session recorded)")
			continue
		}

		if err := pkt.Write(server); err != nil {
			errCh <- err
			return
		}
	}
}

func (p *MssqlProxy) proxyToClient(server, client net.Conn, errCh chan error) {
	defer func() {
		if r := recover(); r != nil {
			errCh <- fmt.Errorf("panic in proxyToClient: %v", r)
		}
	}()

	var responseBuf []byte

	for {
		pkt, err := ReadPacket(server)
		if err != nil {
			errCh <- err
			return
		}

		// Accumulate response packets for TabularResult responses
		if pkt.Type == PacketTypeTabularResult {
			responseBuf = append(responseBuf, pkt.Payload...)

			if pkt.IsEOM() {
				p.mu.Lock()
				pending := p.pendingQuery
				p.pendingQuery = nil
				p.mu.Unlock()

				if pending != nil {
					hasError, errorMsg, rowsAffected := ParseResponseOutcome(responseBuf)

					var output string
					if hasError {
						if errorMsg != "" {
							output = fmt.Sprintf("ERROR: %s", errorMsg)
						} else {
							output = "ERROR"
						}
					} else if rowsAffected > 0 {
						output = fmt.Sprintf("OK (%d rows affected)", rowsAffected)
					} else {
						output = "OK"
					}

					p.config.SessionLogger.LogEntry(session.SessionLogEntry{
						Timestamp: pending.timestamp,
						Input:     pending.sql,
						Output:    output,
					})
				}
				responseBuf = nil
			}
		}

		if err := pkt.Write(client); err != nil {
			errCh <- err
			return
		}
	}
}
