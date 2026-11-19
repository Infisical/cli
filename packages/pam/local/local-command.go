package pam

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"k8s.io/client-go/tools/clientcmd"
	k8sapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	EnvPAMHost = "INFISICAL_PAM_HOST"
	EnvPAMPort = "INFISICAL_PAM_PORT"
	EnvPAMURL  = "INFISICAL_PAM_URL"
)

// Account types whose client side is a plain TCP relay, so a local command can be pointed at a port.
var localCommandAccountTypes = map[string]bool{
	AccountTypePostgres:    true,
	AccountTypeCockroachDB: true,
	AccountTypeMySQL:       true,
	AccountTypeMsSQL:       true,
	AccountTypeMongoDB:     true,
	AccountTypeOracleDB:    true,
	AccountTypeClickhouse:  true,
	AccountTypeRedis:       true,
	AccountTypeKubernetes:  true,
}

// SupportsLocalCommand reports whether `pam access <path> -- <command>` runs the command locally
// against a proxy for this account type. SSH runs its command on the target instead.
func SupportsLocalCommand(accountType string) bool {
	return localCommandAccountTypes[accountType]
}

// ErrSessionExpired is returned when the session ended before the command did.
var ErrSessionExpired = errors.New("the PAM session ended before the command finished")

// CommandStartError is returned when the command couldn't be started, usually because it isn't
// installed. Shells exit 127 for the same case.
type CommandStartError struct {
	Command string
	Err     error
}

func (e *CommandStartError) Error() string {
	return fmt.Sprintf("failed to start %s: %v", e.Command, e.Err)
}

func (e *CommandStartError) Unwrap() error { return e.Err }

type staticSessionProvider struct{ session LiveSession }

func (s staticSessionProvider) Ensure(context.Context) (LiveSession, error) { return s.session, nil }
func (s staticSessionProvider) Current() (LiveSession, bool)                { return s.session, true }

// RunLocalCommand serves a loopback proxy for an open session, runs command with the connection in
// its environment, and ends the session when the command exits. It returns the command's exit code.
func RunLocalCommand(httpClient *resty.Client, response *api.PAMAccessResponse, duration time.Duration, port int, command []string) (int, error) {
	session := NewLiveSession(response, time.Now().Add(duration))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := NewLoopbackTransport(ctx, httpClient, response.AccountType, staticSessionProvider{session})
	defer transport.TerminateSession(session)

	if err := transport.ValidateResourceTypeSupported(); err != nil {
		return 1, err
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return 1, fmt.Errorf("failed to listen on 127.0.0.1:%d: %w", port, err)
	}
	boundPort := listener.Addr().(*net.TCPAddr).Port

	var connections sync.WaitGroup
	go serveLoopback(ctx, listener, transport, session, &connections)
	defer func() {
		cancel()
		listener.Close()
		waitWithTimeout(&connections, 5*time.Second)
	}()

	tempDir, err := os.MkdirTemp("", "infisical-pam-")
	if err != nil {
		return 1, fmt.Errorf("failed to create a temporary directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	env, err := localCommandEnv(response, boundPort, tempDir)
	if err != nil {
		return 1, err
	}

	child := exec.Command(command[0], command[1:]...)
	child.Env = env
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		return 127, &CommandStartError{Command: command[0], Err: err}
	}

	// Ctrl+C already reaches the child through the terminal's process group; catching it keeps this
	// process alive long enough to end the session. SIGTERM is addressed to us alone, so forward it.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	expired := make(chan struct{})
	timer := time.AfterFunc(time.Until(session.Expiry), func() {
		close(expired)
		_ = child.Process.Kill()
	})
	defer timer.Stop()

	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-signals:
				if sig == syscall.SIGTERM {
					_ = child.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()

	waitErr := child.Wait()
	close(done)

	select {
	case <-expired:
		return 1, ErrSessionExpired
	default:
	}

	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal()), nil
		}
		return exitErr.ExitCode(), nil
	}
	if waitErr != nil {
		return 1, fmt.Errorf("%s failed: %w", command[0], waitErr)
	}
	return 0, nil
}

// localCommandEnv adds the proxy's address under INFISICAL_PAM_* and under the variables each
// account type's usual client already reads, so `-- psql -c ...` needs no connection flags.
func localCommandEnv(response *api.PAMAccessResponse, port int, tempDir string) ([]string, error) {
	username := response.Metadata["username"]
	database := response.Metadata["database"]
	portStr := strconv.Itoa(port)

	set := map[string]string{
		EnvPAMHost: "127.0.0.1",
		EnvPAMPort: portStr,
	}
	// The proxy injects the real credential, and some protocols refuse a supplied one.
	unset := map[string]bool{"PGPASSWORD": true, "MYSQL_PWD": true, "SQLCMDPASSWORD": true}

	if display, ok := ConnectionDisplayFor(response.AccountType); ok {
		if url := display.Connection(username, database, port); url != "" {
			set[EnvPAMURL] = url
		}
	}

	switch response.AccountType {
	case AccountTypePostgres, AccountTypeCockroachDB:
		set["PGHOST"], set["PGPORT"], set["PGUSER"] = "127.0.0.1", portStr, username
		set["PGSSLMODE"] = "disable"
		if database != "" {
			set["PGDATABASE"] = database
		}
	case AccountTypeMySQL:
		set["MYSQL_HOST"], set["MYSQL_TCP_PORT"] = "127.0.0.1", portStr
	case AccountTypeMsSQL:
		set["SQLCMDSERVER"] = "127.0.0.1," + portStr
		set["SQLCMDUSER"] = username
		if database != "" {
			set["SQLCMDDBNAME"] = database
		}
	case AccountTypeKubernetes:
		path, err := writeLocalKubeconfig(tempDir, port)
		if err != nil {
			return nil, err
		}
		set["KUBECONFIG"] = path
		set[EnvPAMURL] = fmt.Sprintf("http://127.0.0.1:%d", port)
	}

	env := make([]string, 0, len(os.Environ())+len(set))
	for _, entry := range os.Environ() {
		key := entry
		for i := 0; i < len(entry); i++ {
			if entry[i] == '=' {
				key = entry[:i]
				break
			}
		}
		if _, overridden := set[key]; overridden || unset[key] {
			continue
		}
		env = append(env, entry)
	}
	for key, value := range set {
		env = append(env, key+"="+value)
	}
	return env, nil
}

// writeLocalKubeconfig writes a kubeconfig for this command only, leaving ~/.kube/config untouched.
func writeLocalKubeconfig(tempDir string, port int) (string, error) {
	const name = "infisical-pam"
	config := k8sapi.NewConfig()
	config.Clusters[name] = &k8sapi.Cluster{Server: fmt.Sprintf("http://127.0.0.1:%d", port)}
	config.AuthInfos[name] = &k8sapi.AuthInfo{}
	config.Contexts[name] = &k8sapi.Context{Cluster: name, AuthInfo: name}
	config.CurrentContext = name

	path := filepath.Join(tempDir, "kubeconfig")
	if err := clientcmd.WriteToFile(*config, path); err != nil {
		return "", fmt.Errorf("failed to write kubeconfig: %w", err)
	}
	return path, nil
}

func serveLoopback(ctx context.Context, listener net.Listener, transport *BaseProxyServer, session LiveSession, connections *sync.WaitGroup) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Debug().Err(err).Msg("Failed to accept connection")
			continue
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			relayLoopbackConnection(ctx, conn, transport, session)
		}()
	}
}

func relayLoopbackConnection(ctx context.Context, clientConn net.Conn, transport *BaseProxyServer, session LiveSession) {
	defer clientConn.Close()

	relayConn, err := transport.DialRelay(session)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to relay")
		return
	}
	defer relayConn.Close()

	gatewayConn, err := transport.DialGateway(relayConn, ALPNInfisicalPAMProxy, session)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to gateway")
		return
	}
	defer gatewayConn.Close()

	relayBothWays(ctx, clientConn, gatewayConn)
}

// relayBothWays copies until one side finishes. A client that half-closes after a request (HTTP,
// kubectl) still reads the reply, so the gateway side is drained before returning.
func relayBothWays(ctx context.Context, clientConn, gatewayConn net.Conn) {
	gatewayDone := make(chan struct{})
	clientDone := make(chan struct{})

	go func() {
		_, _ = io.Copy(clientConn, gatewayConn)
		halfCloseWrite(clientConn)
		close(gatewayDone)
	}()
	go func() {
		_, _ = io.Copy(gatewayConn, clientConn)
		halfCloseWrite(gatewayConn)
		close(clientDone)
	}()

	select {
	case <-clientDone:
		select {
		case <-gatewayDone:
		case <-ctx.Done():
		}
	case <-gatewayDone:
	case <-ctx.Done():
	}
}

func halfCloseWrite(conn net.Conn) {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
}

func waitWithTimeout(group *sync.WaitGroup, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}
