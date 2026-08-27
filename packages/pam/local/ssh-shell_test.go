package pam

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	gatewayssh "github.com/Infisical/infisical-merge/packages/pam/handlers/ssh"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	testTargetUser     = "target-user"
	testTargetPassword = "target-password"
)

type stubSessionLogger struct{}

func (stubSessionLogger) LogEntry(session.SessionLogEntry) error     { return nil }
func (stubSessionLogger) LogSessionEvent(session.SessionEvent) error { return nil }
func (stubSessionLogger) LogHttpEvent(session.HttpEvent) error       { return nil }
func (stubSessionLogger) Close() error                               { return nil }

func TestSanitizeSSHVersion(t *testing.T) {
	cases := map[string]string{
		"0.44.1":      "0.44.1",
		"0.44.1-rc.1": "0.44.1_rc.1",
		"1.0 beta":    "1.0_beta",
		"":            "unknown",
	}

	for version, want := range cases {
		if got := sanitizeSSHVersion(version); got != want {
			t.Errorf("sanitizeSSHVersion(%q) = %q, want %q", version, got, want)
		}
	}
}

func TestSSHExitCode(t *testing.T) {
	t.Run("missing status reports unavailable", func(t *testing.T) {
		code, err := sshExitCode(&ssh.ExitMissingError{}, false)
		if err != nil || code != sshExitCodeUnavailable {
			t.Fatalf("got (%d, %v), want (%d, nil)", code, err, sshExitCodeUnavailable)
		}
	})

	t.Run("expiry reports unavailable rather than an error", func(t *testing.T) {
		code, err := sshExitCode(errors.New("connection reset"), true)
		if err != nil || code != sshExitCodeUnavailable {
			t.Fatalf("got (%d, %v), want (%d, nil)", code, err, sshExitCodeUnavailable)
		}
	})

	t.Run("other failures surface", func(t *testing.T) {
		want := errors.New("handshake failed")
		code, err := sshExitCode(want, false)
		if !errors.Is(err, want) || code != 0 {
			t.Fatalf("got (%d, %v), want (0, %v)", code, err, want)
		}
	})
}

// Drives the real gateway SSH proxy, covering the handshake the CLI now performs itself.
func TestRunSSHCommandThroughGateway(t *testing.T) {
	gatewayAddr := startGatewaySSHProxy(t, startFakeSSHTarget(t))

	cases := []struct {
		name       string
		command    []string
		wantStdout string
		wantCode   int
	}{
		{
			name:       "runs a command and returns its output",
			command:    []string{"uptime"},
			wantStdout: "ran: uptime\n",
		},
		{
			name:       "joins arguments the way ssh does",
			command:    []string{"systemctl", "status", "nginx"},
			wantStdout: "ran: systemctl status nginx\n",
		},
		{
			name:     "propagates a non-zero exit code",
			command:  []string{"exit-7"},
			wantCode: 7,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := dialTestClient(t, gatewayAddr)

			sshSession, err := client.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			defer sshSession.Close()

			var stdout, stderr bytes.Buffer
			runErr := runSSHCommand(sshSession, tc.command, strings.NewReader(""), &stdout, &stderr)

			code, err := sshExitCode(runErr, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
			if stdout.String() != tc.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tc.wantStdout)
			}
		})
	}
}

func dialTestClient(t *testing.T, gatewayAddr string) *ssh.Client {
	t.Helper()

	conn, err := net.DialTimeout("tcp", gatewayAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}

	// Not the target's username: the gateway ignores it and injects the account's own.
	client, err := newSSHClient(conn, "whoever")
	if err != nil {
		conn.Close()
		t.Fatalf("newSSHClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func startGatewaySSHProxy(t *testing.T, targetAddr string) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	proxy := gatewayssh.NewSSHProxy(gatewayssh.SSHProxyConfig{
		TargetAddr:     targetAddr,
		AuthMethod:     "password",
		InjectUsername: testTargetUser,
		InjectPassword: testTargetPassword,
		SessionID:      "test-session",
		SessionLogger:  stubSessionLogger{},
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _ = proxy.HandleConnection(ctx, conn) }()
		}
	}()

	return listener.Addr().String()
}

// startFakeSSHTarget stands in for the machine a PAM account points at.
func startFakeSSHTarget(t *testing.T) string {
	t.Helper()

	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() != testTargetUser || string(password) != testTargetPassword {
				return nil, fmt.Errorf("authentication failed for %q", conn.User())
			}
			return nil, nil
		},
	}
	config.AddHostKey(newTestHostKey(t))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveFakeTarget(conn, config)
		}
	}()

	return listener.Addr().String()
}

func serveFakeTarget(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	_, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			return
		}
		go serveFakeTargetChannel(channel, channelRequests)
	}
}

func serveFakeTargetChannel(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "exec":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			exitStatus := runFakeCommand(channel, sshStringPayload(req.Payload))
			sendExitStatus(channel, exitStatus)
			_ = channel.CloseWrite()
			return
		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			go echoShell(channel)
		case "pty-req", "window-change", "env":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func runFakeCommand(channel ssh.Channel, command string) uint32 {
	switch command {
	case "exit-7":
		return 7
	default:
		_, _ = fmt.Fprintf(channel, "ran: %s\n", command)
		return 0
	}
}

func echoShell(channel ssh.Channel) {
	buf := make([]byte, 1024)
	for {
		n, err := channel.Read(buf)
		if n > 0 {
			_, _ = fmt.Fprintf(channel, "shell> %s", buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func sshStringPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	length := binary.BigEndian.Uint32(payload)
	if int(length) > len(payload)-4 {
		return ""
	}
	return string(payload[4 : 4+length])
}

func sendExitStatus(channel ssh.Channel, status uint32) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, status)
	_, _ = channel.SendRequest("exit-status", false, payload)
}

func newTestHostKey(t *testing.T) ssh.Signer {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("build host key signer: %v", err)
	}
	return signer
}

// Drives the interactive path against a real terminal: raw mode, stdin pump, and restore.
func TestRunInteractiveShellOverPTY(t *testing.T) {
	gatewayAddr := startGatewaySSHProxy(t, startFakeSSHTarget(t))
	client := dialTestClient(t, gatewayAddr)

	sshSession, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sshSession.Close()

	primary, replica, err := pty.Open()
	if err != nil {
		t.Fatalf("open pty: %v", err)
	}
	t.Cleanup(func() {
		primary.Close()
		replica.Close()
	})

	// runInteractiveShell works on the process's own terminal, so point that at the pty.
	originalStdin, originalStdout := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = replica, replica
	t.Cleanup(func() { os.Stdin, os.Stdout = originalStdin, originalStdout })

	stateBefore, err := term.GetState(int(replica.Fd()))
	if err != nil {
		t.Fatalf("read terminal state: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- runInteractiveShell(sshSession) }()

	// Raw mode has to be on before the pty stops echoing what is written here.
	waitForRawMode(t, replica, stateBefore)

	if _, err := io.WriteString(primary, "hello\n"); err != nil {
		t.Fatalf("write to terminal: %v", err)
	}

	if got := readUntil(t, primary, "shell> hello"); !strings.Contains(got, "shell> hello") {
		t.Errorf("terminal output = %q, want it to contain %q", got, "shell> hello")
	}

	sshSession.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runInteractiveShell did not return after the session closed")
	}

	stateAfter, err := term.GetState(int(replica.Fd()))
	if err != nil {
		t.Fatalf("read terminal state: %v", err)
	}
	if !reflect.DeepEqual(stateBefore, stateAfter) {
		t.Error("terminal was not restored to its original state")
	}
}

func waitForRawMode(t *testing.T, tty *os.File, original *term.State) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		current, err := term.GetState(int(tty.Fd()))
		if err == nil && !reflect.DeepEqual(current, original) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("terminal never entered raw mode")
}

func readUntil(t *testing.T, reader io.Reader, want string) string {
	t.Helper()

	found := make(chan string, 1)
	go func() {
		var seen []byte
		buf := make([]byte, 256)
		for {
			n, err := reader.Read(buf)
			seen = append(seen, buf[:n]...)
			if strings.Contains(string(seen), want) || err != nil {
				found <- string(seen)
				return
			}
		}
	}()

	select {
	case got := <-found:
		return got
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for output on the terminal")
		return ""
	}
}
