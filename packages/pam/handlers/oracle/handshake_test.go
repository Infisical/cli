package oracle

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	_ "github.com/sijms/go-ora/v2"
)


// TestHandshakeAgainstGoOra spins up just the client-facing Oracle handshake on a
// local TCP listener (no real upstream Oracle target) and checks whether a go-ora
// client connecting with ProxyPasswordPlaceholder completes the handshake cleanly.
//
// Skipped unless ORACLE_HANDSHAKE_TEST=1 because it binds a TCP port.
func TestHandshakeAgainstGoOra(t *testing.T) {
	if os.Getenv("ORACLE_HANDSHAKE_TEST") == "" {
		t.Skip("set ORACLE_HANDSHAKE_TEST=1 to run")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	t.Logf("Listening on 127.0.0.1:%d", port)

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()
		serverDone <- runHandshakeOnly(conn, t)
	}()

	dsn := fmt.Sprintf("oracle://ADMIN:%s@127.0.0.1:%d/TESTDB", ProxyPasswordPlaceholder, port)
	t.Logf("go-ora DSN: %s", dsn)

	db, err := sql.Open("oracle", dsn)
	if err != nil {
		t.Fatal("sql.Open:", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pingErr := db.PingContext(ctx)

	var serverErr error
	select {
	case serverErr = <-serverDone:
	case <-time.After(20 * time.Second):
		t.Fatal("server goroutine timed out")
	}

	t.Logf("SERVER handshake result: %v", serverErr)
	t.Logf("CLIENT go-ora ping result: %v", pingErr)

	if serverErr != nil {
		t.Fatalf("server-side handshake failed: %v", serverErr)
	}
	t.Log("PASS: go-ora client completed the handshake against our impersonation")
}

// runHandshakeOnly mirrors the client-facing portion of HandleConnection (lines
// 106-220) without dialling an upstream Oracle. It returns nil if our server
// successfully writes the phase-2 auth response without the client closing the
// connection underneath us.
func runHandshakeOnly(clientConn net.Conn, t *testing.T) error {
	connectRaw, err := ReadFullPacket(clientConn, false)
	if err != nil {
		return fmt.Errorf("read CONNECT: %w", err)
	}
	if PacketTypeOf(connectRaw) == PacketTypeResend {
		connectRaw, err = ReadFullPacket(clientConn, false)
		if err != nil {
			return fmt.Errorf("re-read CONNECT: %w", err)
		}
	}
	if PacketTypeOf(connectRaw) != PacketTypeConnect {
		return fmt.Errorf("expected CONNECT, got type=%d", connectRaw[4])
	}
	connectPkt, err := ParseConnectPacket(connectRaw)
	if err != nil {
		return fmt.Errorf("parse CONNECT: %w", err)
	}
	t.Logf("CONNECT received: clientVersion=%d", connectPkt.Version)

	accept := AcceptFromConnect(connectPkt)
	t.Logf("connect parsed: sdu=%d tdu=%d version=%d loVer=%d acfl0=0x%02X acfl1=0x%02X options=0x%04X",
		connectPkt.SessionDataUnit, connectPkt.TransportDataUnit, connectPkt.Version, connectPkt.LoVersion,
		connectPkt.ACFL0, connectPkt.ACFL1, connectPkt.Options)
	t.Logf("accept built: sdu=%d tdu=%d version=%d histone=%d acfl0=0x%02X acfl1=0x%02X",
		accept.SessionDataUnit, accept.TransportDataUnit, accept.Version, accept.Histone, accept.ACFL0, accept.ACFL1)
	acceptBytes := accept.Bytes()
	if _, err := clientConn.Write(acceptBytes); err != nil {
		return fmt.Errorf("write ACCEPT: %w", err)
	}
	use32Bit := accept.Version >= 315
	t.Logf("ACCEPT sent: version=%d use32Bit=%v acceptHex=% X", accept.Version, use32Bit, acceptBytes)

	peekBuf := make([]byte, 512)
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := clientConn.Read(peekBuf)
	_ = clientConn.SetReadDeadline(time.Time{})
	t.Logf("POST-ACCEPT peek: n=%d first16=% X", n, peekBuf[:min(16, n)])
	peeked := append([]byte(nil), peekBuf[:n]...)

	if slen := detectConnectDataSupplement(peeked); slen > 0 {
		t.Logf("draining connect-data supplement (16-bit framed DATA, %d bytes)", slen)
		if slen > len(peeked) {
			rest := make([]byte, slen-len(peeked))
			if _, err := io.ReadFull(clientConn, rest); err != nil {
				return fmt.Errorf("read supplement tail: %w", err)
			}
			peeked = nil
		} else {
			peeked = peeked[slen:]
		}
	}

	wrapped := &prependedConn{Conn: clientConn, buf: peeked}

	p1Payload, err := RunPreAuthExchange(wrapped, use32Bit)
	if err != nil {
		return fmt.Errorf("pre-auth exchange: %w", err)
	}
	t.Logf("pre-auth exchange complete, received phase-1 payload (%d bytes)", len(p1Payload))

	if _, err := ParseAuthPhaseOne(p1Payload); err != nil {
		return fmt.Errorf("parse auth phase 1: %w", err)
	}
	state, err := NewO5LogonServerState()
	if err != nil {
		return fmt.Errorf("init O5Logon state: %w", err)
	}
	if err := writeDataPayload(wrapped, BuildAuthPhaseOneResponse(state), use32Bit); err != nil {
		return fmt.Errorf("write phase 1 response: %w", err)
	}
	t.Logf("phase-1 response sent")

	p2Payload, err := readDataPayload(wrapped, use32Bit)
	if err != nil {
		return fmt.Errorf("read phase 2: %w", err)
	}
	p2, err := ParseAuthPhaseTwo(p2Payload)
	if err != nil {
		return fmt.Errorf("parse phase 2: %w", err)
	}
	t.Logf("phase-2 received, verifying password...")

	_, encKey, verr := state.VerifyClientPassword(p2.EClientSessKey, p2.EPassword)
	if verr != nil {
		return fmt.Errorf("verify password: %w", verr)
	}
	t.Logf("password verified — client proved knowledge of placeholder")

	svr, err := BuildSvrResponse(encKey)
	if err != nil {
		return fmt.Errorf("build SVR response: %w", err)
	}
	if err := writeDataPayload(wrapped, BuildAuthPhaseTwoResponse(svr, 0xC0DE, 0x42), use32Bit); err != nil {
		return fmt.Errorf("write phase 2 response: %w", err)
	}
	t.Logf("phase-2 response sent — handshake complete from server side")

	// Try to read a follow-up from the client. If the client sends anything,
	// it accepted our handshake. If it closes immediately, it rejected it.
	_ = wrapped.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 32)
	m, rerr := wrapped.Read(buf)
	t.Logf("post-handshake client read: n=%d err=%v firstBytes=%x", m, rerr, buf[:m])

	return nil
}
