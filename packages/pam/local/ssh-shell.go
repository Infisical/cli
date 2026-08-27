package pam

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	sshTunnelAddr          = "infisical-pam-gateway:22"
	sshExitCodeUnavailable = 255
)

var sshClientVersion = "SSH-2.0-Infisical_" + sanitizeSSHVersion(util.CLI_VERSION)

// sanitizeSSHVersion strips what RFC 4253 disallows in a software version: whitespace and minus
func sanitizeSSHVersion(version string) string {
	if version == "" {
		return "unknown"
	}
	return strings.Map(func(r rune) rune {
		if r <= ' ' || r > '~' || r == '-' {
			return '_'
		}
		return r
	}, version)
}

// RunSSHShell attaches the terminal to a shell on the target, or runs one command, and returns the remote exit code
func RunSSHShell(transport *BaseProxyServer, username string, command []string) (int, error) {
	client, err := dialSSHOverTunnel(transport, username)
	if err != nil {
		return 0, err
	}
	defer client.Close()

	expired, stopWatching := watchForSessionEnd(client, transport.sessionExpiry)
	defer stopWatching()

	session, err := client.NewSession()
	if err != nil {
		return 0, fmt.Errorf("failed to open SSH session: %w", err)
	}
	defer session.Close()

	if len(command) > 0 {
		err = runSSHCommand(session, command, os.Stdin, os.Stdout, os.Stderr)
	} else {
		err = runInteractiveShell(session)
	}

	sessionExpired := false
	select {
	case <-expired:
		sessionExpired = true
		util.PrintfStderr("\nPAM session expired.\n")
	default:
	}

	return sshExitCode(err, sessionExpired)
}

func dialSSHOverTunnel(transport *BaseProxyServer, username string) (*ssh.Client, error) {
	relayConn, err := transport.CreateRelayConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay: %w", err)
	}

	gatewayConn, err := transport.CreateGatewayConnection(relayConn, ALPNInfisicalPAMProxy)
	if err != nil {
		relayConn.Close()
		return nil, fmt.Errorf("failed to connect to gateway: %w", err)
	}

	client, err := newSSHClient(gatewayConn, username)
	if err != nil {
		gatewayConn.Close()
		return nil, err
	}
	return client, nil
}

func newSSHClient(conn net.Conn, username string) (*ssh.Client, error) {
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, sshTunnelAddr, &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   sshClientVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to establish SSH connection through the gateway: %w", err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func runInteractiveShell(session *ssh.Session) error {
	fd := int(os.Stdin.Fd())
	width, height := terminalSize()

	// ECHO is the remote pty's, which echoes once the local terminal is raw.
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty(terminalType(), height, width, modes); err != nil {
		return fmt.Errorf("failed to request a terminal on the target: %w", err)
	}

	remoteStdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to open remote stdin: %w", err)
	}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	restore, err := makeTerminalRaw(fd)
	if err != nil {
		return err
	}
	defer restore()

	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start a shell on the target: %w", err)
	}

	stopResizing := watchTerminalResize(session)
	defer stopResizing()

	go func() {
		_, _ = io.Copy(remoteStdin, os.Stdin)
		_ = remoteStdin.Close()
	}()

	return session.Wait()
}

// runSSHCommand joins arguments with spaces for the remote shell to re-parse, as `ssh host cmd` does
func runSSHCommand(session *ssh.Session, command []string, stdin io.Reader, stdout, stderr io.Writer) error {
	session.Stdin = stdin
	session.Stdout = stdout
	session.Stderr = stderr
	return session.Run(strings.Join(command, " "))
}

func makeTerminalRaw(fd int) (restore func(), err error) {
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to put the terminal in raw mode: %w", err)
	}
	return sync.OnceFunc(func() {
		if restoreErr := term.Restore(fd, state); restoreErr != nil {
			log.Debug().Err(restoreErr).Msg("Failed to restore terminal state")
		}
	}), nil
}

// watchForSessionEnd closes the client on expiry or signal
func watchForSessionEnd(client *ssh.Client, expiry time.Time) (expired <-chan struct{}, stop func()) {
	expiredCh := make(chan struct{})
	done := make(chan struct{})

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		timer := time.NewTimer(time.Until(expiry))
		defer timer.Stop()

		select {
		case <-timer.C:
			close(expiredCh)
			client.Close()
		case sig := <-signals:
			log.Debug().Msgf("Received signal %v, ending SSH session", sig)
			client.Close()
		case <-done:
		}
	}()

	return expiredCh, func() {
		signal.Stop(signals)
		close(done)
	}
}

func sshExitCode(err error, sessionExpired bool) (int, error) {
	if err == nil {
		return 0, nil
	}

	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), nil
	}

	var missingErr *ssh.ExitMissingError
	if sessionExpired || errors.As(err, &missingErr) || errors.Is(err, io.EOF) {
		log.Debug().Err(err).Msg("Remote closed the SSH session without an exit status")
		return sshExitCodeUnavailable, nil
	}

	return 0, err
}

func terminalSize() (width, height int) {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 || height <= 0 {
		return 80, 24
	}
	return width, height
}

func terminalType() string {
	if termType := os.Getenv("TERM"); termType != "" {
		return termType
	}
	return "xterm-256color"
}
