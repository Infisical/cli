package mssql

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
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

type MssqlProxy struct {
	config MssqlProxyConfig
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

	// Check for unsupported features
	clientPayload := CombinePayloads(clientPrelogin)
	if err := CheckPreloginSupported(clientPayload); err != nil {
		return err
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
	preloginReq := BuildPreloginRequest(EncryptNotSup)
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

	// 2. Read server's PRELOGIN response
	serverPrelogin, err := ReadAllPackets(serverConn)
	if err != nil {
		serverConn.Close()
		return nil, nil, fmt.Errorf("read server prelogin: %w", err)
	}

	serverPayload := CombinePayloads(serverPrelogin)
	serverEnc := GetPreloginEncryption(serverPayload)

	log.Debug().
		Str("sessionID", p.config.SessionID).
		Uint8("serverEnc", serverEnc).
		Msg("Received server PRELOGIN response")

	// 3. Handle TLS if server requires it
	if serverEnc == EncryptOn || serverEnc == EncryptReq {
		if p.config.TLSConfig == nil {
			serverConn.Close()
			return nil, nil, fmt.Errorf("server requires TLS but no TLS configuration provided")
		}
		tlsConn := tls.Client(serverConn, p.config.TLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			serverConn.Close()
			return nil, nil, fmt.Errorf("TLS handshake: %w", err)
		}
		serverConn = tlsConn
		log.Debug().Str("sessionID", p.config.SessionID).Msg("TLS established with server")
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

	log.Debug().
		Str("sessionID", p.config.SessionID).
		Str("user", p.config.InjectUsername).
		Msg("Sent LOGIN7 to server")

	// 5. Read login response - forward to client
	response, err := ReadAllPackets(serverConn)
	if err != nil {
		serverConn.Close()
		return nil, nil, fmt.Errorf("read login response: %w", err)
	}

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

	var sqlBatchBuf []byte

	for {
		pkt, err := ReadPacket(client)
		if err != nil {
			errCh <- err
			return
		}

		// Only allow packet types that can be session recorded
		switch pkt.Type {
		case PacketTypeSQLBatch:
			// SQL queries - log them
			sqlBatchBuf = append(sqlBatchBuf, pkt.Payload...)
			if pkt.IsEOM() {
				sql := ExtractSQL(sqlBatchBuf)
				if sql != "" {
					p.config.SessionLogger.LogEntry(session.SessionLogEntry{
						Timestamp: time.Now(),
						Input:     sql,
						Output:    "OK",
					})
				}
				sqlBatchBuf = nil
			}

		case PacketTypeRPCRequest:
			log.Warn().Str("sessionID", p.config.SessionID).Msg("RPC requests (stored procedures) are not supported")
			errCh <- fmt.Errorf("RPC requests (stored procedures) are not supported; use direct SQL queries")
			return

		case PacketTypeBulkLoad:
			log.Warn().Str("sessionID", p.config.SessionID).Msg("Bulk load operations are not supported")
			errCh <- fmt.Errorf("bulk load operations are not supported")
			return

		case PacketTypeTransMgrReq:
			log.Warn().Str("sessionID", p.config.SessionID).Msg("Distributed transactions are not supported")
			errCh <- fmt.Errorf("distributed transactions are not supported")
			return

		case PacketTypeAttention:
			log.Warn().Str("sessionID", p.config.SessionID).Msg("Attention/cancel requests are not supported")
			errCh <- fmt.Errorf("attention/cancel requests are not supported")
			return

		default:
			// Allow other packet types (like TabularResult for responses) to pass through
		}

		// Forward packet to server
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

	for {
		pkt, err := ReadPacket(server)
		if err != nil {
			errCh <- err
			return
		}
		if err := pkt.Write(client); err != nil {
			errCh <- err
			return
		}
	}
}
