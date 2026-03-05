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

	// Connect to backend
	serverConn, err := net.Dial("tcp", p.config.TargetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer serverConn.Close()

	// Handle PRELOGIN and LOGIN
	serverConn, err = p.handleStartup(clientConn, serverConn)
	if err != nil {
		return fmt.Errorf("startup failed: %w", err)
	}

	// Proxy traffic
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

func (p *MssqlProxy) handleStartup(clientConn, serverConn net.Conn) (net.Conn, error) {
	// 1. Read client PRELOGIN
	clientPrelogin, err := ReadAllPackets(clientConn)
	if err != nil {
		return nil, fmt.Errorf("read client prelogin: %w", err)
	}
	if len(clientPrelogin) == 0 || clientPrelogin[0].Type != PacketTypePrelogin {
		return nil, fmt.Errorf("expected PRELOGIN from client")
	}

	// Forward to server
	for _, pkt := range clientPrelogin {
		if err := pkt.Write(serverConn); err != nil {
			return nil, fmt.Errorf("forward prelogin: %w", err)
		}
	}

	// 2. Read server PRELOGIN response
	serverPrelogin, err := ReadAllPackets(serverConn)
	if err != nil {
		return nil, fmt.Errorf("read server prelogin: %w", err)
	}

	// Check for unsupported features in client PRELOGIN
	clientPayload := CombinePayloads(clientPrelogin)
	if err := CheckPreloginSupported(clientPayload); err != nil {
		return nil, err
	}

	// Check if TLS required
	serverPayload := CombinePayloads(serverPrelogin)
	serverEnc := GetPreloginEncryption(serverPayload)
	needTLS := serverEnc == EncryptOn || serverEnc == EncryptReq

	// Forward to client
	for _, pkt := range serverPrelogin {
		if err := pkt.Write(clientConn); err != nil {
			return nil, fmt.Errorf("forward prelogin response: %w", err)
		}
	}

	// 3. TLS handshake with server if needed
	if needTLS {
		if p.config.TLSConfig == nil {
			return nil, fmt.Errorf("server requires TLS but no TLS configuration provided")
		}
		tlsConn := tls.Client(serverConn, p.config.TLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		serverConn = tlsConn
		log.Debug().Str("sessionID", p.config.SessionID).Msg("TLS established with server")
	}

	// 4. Read client LOGIN7 (or SSPI which we don't support)
	loginPackets, err := ReadAllPackets(clientConn)
	if err != nil {
		return nil, fmt.Errorf("read login: %w", err)
	}
	if len(loginPackets) == 0 {
		return nil, fmt.Errorf("no login packet received")
	}

	// Reject SSPI packet type (Windows auth continuation)
	if loginPackets[0].Type == PacketTypeSSPI {
		return nil, fmt.Errorf("Windows/SSPI authentication is not supported; use SQL authentication")
	}
	if loginPackets[0].Type != PacketTypeLogin7 {
		return nil, fmt.Errorf("expected LOGIN7 from client, got packet type 0x%02X", loginPackets[0].Type)
	}

	// Parse and modify LOGIN7
	loginPayload := CombinePayloads(loginPackets)
	loginMsg, err := ParseLogin7(loginPayload)
	if err != nil {
		return nil, fmt.Errorf("parse login: %w", err)
	}

	// Check for unsupported auth methods in LOGIN7
	if err := CheckLogin7Supported(loginMsg); err != nil {
		return nil, err
	}

	log.Debug().
		Str("sessionID", p.config.SessionID).
		Str("origUser", loginMsg.Username).
		Msg("Injecting credentials")

	// Inject our credentials
	loginMsg.Username = p.config.InjectUsername
	loginMsg.Password = p.config.InjectPassword
	if p.config.InjectDatabase != "" {
		loginMsg.Database = p.config.InjectDatabase
	}

	// Send modified LOGIN7
	newLogin := &TDSPacket{
		Type:     PacketTypeLogin7,
		Status:   StatusEOM,
		PacketID: loginPackets[0].PacketID,
		Payload:  loginMsg.Encode(),
	}
	if err := newLogin.Write(serverConn); err != nil {
		return nil, fmt.Errorf("send login: %w", err)
	}

	// 5. Read login response
	response, err := ReadAllPackets(serverConn)
	if err != nil {
		return nil, fmt.Errorf("read login response: %w", err)
	}

	// Forward response to client
	for _, pkt := range response {
		if err := pkt.Write(clientConn); err != nil {
			return nil, fmt.Errorf("forward login response: %w", err)
		}
	}

	// Check for success
	respPayload := CombinePayloads(response)
	if ContainsToken(respPayload, TokenError) {
		return nil, fmt.Errorf("authentication failed")
	}
	if !ContainsToken(respPayload, TokenLoginAck) {
		return nil, fmt.Errorf("no login ack received")
	}

	log.Info().Str("sessionID", p.config.SessionID).Msg("MSSQL authentication successful")
	return serverConn, nil
}

func (p *MssqlProxy) proxyToServer(client, server net.Conn, errCh chan error) {
	defer func() {
		if r := recover(); r != nil {
			errCh <- fmt.Errorf("panic in proxyToServer: %v", r)
		}
	}()

	var sqlBatchBuf []byte // accumulate multi-packet SQL_BATCH

	for {
		pkt, err := ReadPacket(client)
		if err != nil {
			errCh <- err
			return
		}

		switch pkt.Type {
		case PacketTypeSQLBatch:
			// Accumulate payload across packets
			sqlBatchBuf = append(sqlBatchBuf, pkt.Payload...)

			// Log when we have the complete message
			if pkt.IsEOM() {
				sql := ExtractSQL(sqlBatchBuf)
				if sql != "" {
					p.config.SessionLogger.LogEntry(session.SessionLogEntry{
						Timestamp: time.Now(),
						Input:     sql,
						Output:    "OK",
					})
				}
				sqlBatchBuf = nil // reset for next query
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
			log.Warn().Str("sessionID", p.config.SessionID).Uint8("packetType", pkt.Type).Msg("Unsupported packet type")
			errCh <- fmt.Errorf("unsupported packet type: 0x%02X", pkt.Type)
			return
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
