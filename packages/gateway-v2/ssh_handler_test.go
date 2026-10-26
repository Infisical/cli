package gatewayv2

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func startHangingSSHServer(t *testing.T, sessionClosed *atomic.Bool) (string, int) {
	t.Helper()
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil },
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChannel := range chans {
					channel, requests, err := newChannel.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range requests {
							if req.WantReply {
								_ = req.Reply(true, nil)
							}
						}
						sessionClosed.Store(true)
						_ = channel.Close()
					}()
				}
			}(conn)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

func TestDoSSHExecHonoursSingleBudget(t *testing.T) {
	var sessionClosed atomic.Bool
	host, port := startHangingSSHServer(t, &sessionClosed)

	started := time.Now()
	_, err := doSSHExec(t.Context(), host, port, sshExecEnvelope{
		Command:    "sleep 30",
		AuthMethod: "password",
		Username:   "test",
		Password:   "test",
		TimeoutMs:  500,
	})
	elapsed := time.Since(started)

	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout error, got %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("exec took %s, expected to stop near the 500ms budget", elapsed)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !sessionClosed.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !sessionClosed.Load() {
		t.Fatal("the remote session was not closed after the timeout")
	}
}

func TestSSHExecBudgetClamps(t *testing.T) {
	if sshCommandBudget(0, sshExecDefaultTimeout) != sshExecDefaultTimeout {
		t.Fatal("zero should use the default timeout")
	}
	if sshCommandBudget(int((time.Hour).Milliseconds()), sshExecDefaultTimeout) != sshExecMaxTimeout {
		t.Fatal("large timeouts should be clamped")
	}
}
