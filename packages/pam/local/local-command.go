package pam

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog/log"
	"k8s.io/client-go/tools/clientcmd"
	k8sapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	EnvPAMHost = "INFISICAL_PAM_HOST"
	EnvPAMPort = "INFISICAL_PAM_PORT"
	EnvPAMURL  = "INFISICAL_PAM_URL"
)

var localCommandAccountTypes = map[string]bool{
	AccountTypePostgres:          true,
	AccountTypeCockroachDB:       true,
	AccountTypeMySQL:             true,
	AccountTypeMsSQL:             true,
	AccountTypeMongoDB:           true,
	AccountTypeOracleDB:          true,
	AccountTypeClickhouse:        true,
	AccountTypeRedis:             true,
	AccountTypeKubernetes:        true,
	AccountTypeSnowflake:         true,
	AccountTypeGcpServiceAccount: true,
	AccountTypeAzureCli:          true,
	AccountTypeAwsIam:            true,
}

// SupportsLocalCommand reports whether `pam access <path> -- <command>` runs the command locally
// against a proxy for this account type. SSH runs its command on the target instead.
func SupportsLocalCommand(accountType string) bool {
	return localCommandAccountTypes[accountType]
}

var ErrSessionExpired = errors.New("the PAM session ended before the command finished")

var ErrCredentialsExpired = errors.New("the AWS credentials expired before the command finished")

var ErrInterrupted = errors.New("interrupted before the command started")

// interruptWatch catches signals from the moment the session is open, so an interrupt during setup
// still ends the session and removes temp files instead of killing the process.
type interruptWatch struct {
	signals  chan os.Signal
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	stopped  chan struct{}
	doneOnce sync.Once
	caught   os.Signal
	torndown chan struct{}
	stopOnce sync.Once
	mu       sync.Mutex
	temp     []string
}

func signalExitCode(sig os.Signal) int {
	if s, ok := sig.(syscall.Signal); ok {
		return 128 + int(s)
	}
	return 1
}

func (w *interruptWatch) removeOnExit(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.temp = append(w.temp, path)
}

func (w *interruptWatch) exit(sig os.Signal) {
	w.mu.Lock()
	for _, path := range w.temp {
		_ = os.RemoveAll(path)
	}
	w.mu.Unlock()
	os.Exit(signalExitCode(sig))
}

func watchInterrupts() *interruptWatch {
	w := &interruptWatch{signals: make(chan os.Signal, 1), done: make(chan struct{}), stopped: make(chan struct{}), torndown: make(chan struct{})}
	w.ctx, w.cancel = context.WithCancel(context.Background())
	signal.Notify(w.signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		defer close(w.stopped)
		select {
		case sig := <-w.signals:
			w.caught = sig
			w.cancel()
		case <-w.done:
			return
		}
		// A blocking setup step can't see the first interrupt; a second one exits at once.
		select {
		case sig := <-w.signals:
			w.exit(sig)
		case <-w.done:
		}
	}()
	return w
}

// setupFinished hands signals over to the command and reports one that arrived during setup.
func (w *interruptWatch) setupFinished() (int, bool) {
	w.doneOnce.Do(func() { close(w.done) })
	<-w.stopped
	if w.caught == nil {
		return 0, false
	}
	return signalExitCode(w.caught), true
}

// Ending the session can block on the network, so an interrupt during teardown exits at once. A
// SIGINT right after the command exited is the terminal Ctrl+C that stopped it, and is ignored.
func (w *interruptWatch) commandFinished() {
	finished := time.Now()
	go func() {
		for {
			select {
			case sig := <-w.signals:
				if sig == syscall.SIGINT && time.Since(finished) < time.Second {
					continue
				}
				w.exit(sig)
			case <-w.torndown:
				return
			}
		}
	}()
}

func (w *interruptWatch) stop() {
	w.doneOnce.Do(func() { close(w.done) })
	w.stopOnce.Do(func() { close(w.torndown) })
	signal.Stop(w.signals)
	w.cancel()
}

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

// loopbackSetup is what an account type's gateway handler expects on each connection beyond the raw
// client bytes. GCP and Azure terminate the client's TLS at the gateway with a CA this process mints.
type loopbackSetup struct {
	caCertPEM   []byte
	caKeyPEM    []byte
	proxySecret string
}

func (s loopbackSetup) proxyAuthHeader() string {
	if s.proxySecret == "" {
		return ""
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("infisical:"+s.proxySecret))
}

func newLoopbackSetup(accountType string, expiry time.Time) (loopbackSetup, error) {
	var setup loopbackSetup
	switch accountType {
	case AccountTypeGcpServiceAccount:
		ca := &GCPProxyServer{BaseProxyServer: BaseProxyServer{sessionExpiry: expiry}}
		if err := ca.generateCA(); err != nil {
			return setup, err
		}
		setup.caCertPEM, setup.caKeyPEM = ca.caCertPEM, ca.caKeyPEM
	case AccountTypeAzureCli:
		ca := &AzureProxyServer{BaseProxyServer: BaseProxyServer{sessionExpiry: expiry}}
		if err := ca.generateCA(); err != nil {
			return setup, err
		}
		setup.caCertPEM, setup.caKeyPEM = ca.caCertPEM, ca.caKeyPEM
	default:
		return setup, nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return setup, fmt.Errorf("failed to generate a proxy credential: %w", err)
	}
	setup.proxySecret = hex.EncodeToString(secret)
	return setup, nil
}

// RunLocalCommand serves a loopback proxy for an open session, runs command with the connection in
// its environment, and ends the session when the command exits. It returns the command's exit code.
func RunLocalCommand(httpClient *resty.Client, response *api.PAMAccessResponse, duration time.Duration, port int, command []string) (int, error) {
	expiry := time.Now().Add(duration)

	interrupts := watchInterrupts()
	defer interrupts.stop()

	if response.AccountType == AccountTypeAwsIam && response.GatewayId != "" {
		return runAWSGatewayCommand(httpClient, response, expiry, port, command, interrupts)
	}
	if response.AccountType == AccountTypeAwsIam {
		defer EndSession(httpClient, response.SessionId)
		env, credentialsExpiry, err := awsCommandEnv(response)
		if err != nil {
			return 1, err
		}
		credentialsFirst := credentialsExpiry.Before(expiry)
		if credentialsFirst {
			expiry = credentialsExpiry
		}
		if code, interrupted := interrupts.setupFinished(); interrupted {
			return code, ErrInterrupted
		}
		code, err := runLocalChild(command, env, expiry, interrupts)
		if credentialsFirst && errors.Is(err, ErrSessionExpired) {
			return code, ErrCredentialsExpired
		}
		return code, err
	}

	expiry = capToCertificateExpiry(response.GatewayClientCertificate, expiry)
	session := NewLiveSession(response, expiry)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := NewLoopbackTransport(ctx, httpClient, response.AccountType, staticSessionProvider{session})
	defer transport.TerminateSession(session)

	if err := transport.ValidateResourceTypeSupported(); err != nil {
		return 1, err
	}

	setup, err := newLoopbackSetup(response.AccountType, expiry)
	if err != nil {
		return 1, err
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return 1, fmt.Errorf("failed to listen on 127.0.0.1:%d: %w", port, err)
	}
	boundPort := listener.Addr().(*net.TCPAddr).Port

	var connections sync.WaitGroup
	go serveLoopback(ctx, listener, transport, session, setup, &connections)
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
	interrupts.removeOnExit(tempDir)

	env, err := localCommandEnv(response, boundPort, tempDir, setup)
	if err != nil {
		return 1, err
	}

	if response.AccountType == AccountTypeAzureCli {
		loginCtx, cancelLogin := context.WithDeadline(interrupts.ctx, session.Expiry)
		err := azureCommandLogin(loginCtx, env, response.Metadata)
		expired := errors.Is(loginCtx.Err(), context.DeadlineExceeded)
		cancelLogin()
		if err != nil && interrupts.ctx.Err() == nil {
			if expired {
				return 1, ErrSessionExpired
			}
			return 1, err
		}
	}

	if code, interrupted := interrupts.setupFinished(); interrupted {
		return code, ErrInterrupted
	}
	return runLocalChild(command, env, session.Expiry, interrupts)
}

// The backend can shorten the requested duration, and the gateway enforces the certificate's lifetime.
func capToCertificateExpiry(certPEM string, expiry time.Time) time.Time {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return expiry
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.NotAfter.Before(expiry) {
		return expiry
	}
	return cert.NotAfter
}

func runLocalChild(command []string, env []string, expiry time.Time, interrupts *interruptWatch) (int, error) {
	// A terminal's Ctrl+C already reaches a child in the foreground group, so SIGINT is forwarded only
	// when the child has its own group or no stream is a terminal.
	ownGroup := !hasControllingTerminal()
	forwardInterrupt := ownGroup || (!isatty.IsTerminal(os.Stdin.Fd()) && !isatty.IsTerminal(os.Stdout.Fd()) && !isatty.IsTerminal(os.Stderr.Fd()))

	child := exec.Command(command[0], command[1:]...)
	child.Env = env
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if ownGroup {
		startInOwnGroup(child)
	}
	if err := child.Start(); err != nil {
		return 127, &CommandStartError{Command: command[0], Err: err}
	}

	expired := make(chan struct{})
	timer := time.AfterFunc(time.Until(expiry), func() {
		close(expired)
		killCommand(child, ownGroup)
	})
	defer timer.Stop()

	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-interrupts.signals:
				if sig != syscall.SIGINT || forwardInterrupt {
					signalCommand(child, sig, ownGroup)
				}
			case <-done:
				return
			}
		}
	}()

	waitErr := child.Wait()
	close(done)
	interrupts.commandFinished()

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

// runAWSGatewayCommand points the command's AWS tooling at a local proxy. The gateway signs each
// request, so the command only ever holds placeholder credentials.
func runAWSGatewayCommand(httpClient *resty.Client, response *api.PAMAccessResponse, expiry time.Time, port int, command []string, interrupts *interruptWatch) (int, error) {
	if sessionExpiry, err := time.Parse(time.RFC3339, response.Metadata["expiresAt"]); err == nil {
		expiry = sessionExpiry
	}

	ctx, cancel := context.WithCancel(context.Background())
	proxy := &AWSProxyServer{
		BaseProxyServer: BaseProxyServer{
			httpClient:             httpClient,
			directAddress:          response.DirectAddress,
			relayHost:              response.RelayHost,
			relayClientCert:        response.RelayClientCertificate,
			relayClientKey:         response.RelayClientPrivateKey,
			relayServerCertChain:   response.RelayServerCertificateChain,
			gatewayClientCert:      response.GatewayClientCertificate,
			gatewayClientKey:       response.GatewayClientPrivateKey,
			gatewayServerCertChain: response.GatewayServerCertificateChain,
			gatewayId:              response.GatewayId,
			sessionExpiry:          expiry,
			sessionId:              response.SessionId,
			resourceType:           response.AccountType,
			ctx:                    ctx,
			cancel:                 cancel,
			shutdownCh:             make(chan struct{}),
			keepProcessAlive:       true,
		},
	}
	defer proxy.Shutdown()

	if err := proxy.ValidateResourceTypeSupported(); err != nil {
		return 1, err
	}
	if err := proxy.generateCA(); err != nil {
		return 1, err
	}
	if err := proxy.Start(port); err != nil {
		return 1, err
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return 1, fmt.Errorf("failed to generate a proxy credential: %w", err)
	}
	proxySecret := hex.EncodeToString(secret)
	proxy.proxyAuthHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte("infisical:"+proxySecret))
	go proxy.Run()

	caPath, err := writeTempFile("infisical-pam-aws-ca-*.pem", proxy.caCertPEM)
	if err != nil {
		return 1, fmt.Errorf("failed to write the CA file: %w", err)
	}
	defer os.Remove(caPath)
	interrupts.removeOnExit(caPath)

	proxyURL := fmt.Sprintf("http://infisical:%s@127.0.0.1:%d", proxySecret, proxy.port)
	env := awsProxyEnv(os.Environ(), proxyURL, caPath)
	env = append(env, EnvPAMHost+"=127.0.0.1", EnvPAMPort+"="+strconv.Itoa(proxy.port), EnvPAMURL+"="+proxyURL)
	if code, interrupted := interrupts.setupFinished(); interrupted {
		return code, ErrInterrupted
	}
	return runLocalChild(command, env, expiry, interrupts)
}

// awsCommandEnv hands the command the session's STS credentials, for AWS accounts without a gateway.
// The credentials stop working at their own expiry, which it returns.
func awsCommandEnv(response *api.PAMAccessResponse) ([]string, time.Time, error) {
	accessKeyId := response.Metadata["accessKeyId"]
	secretAccessKey := response.Metadata["secretAccessKey"]
	sessionToken := response.Metadata["sessionToken"]
	expiresAtStr := response.Metadata["expiresAt"]
	if accessKeyId == "" || secretAccessKey == "" || sessionToken == "" || expiresAtStr == "" {
		return nil, time.Time{}, errors.New("the server did not return AWS credentials for this session")
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to parse the AWS credentials' expiry: %w", err)
	}
	if !expiresAt.After(time.Now()) {
		return nil, time.Time{}, errors.New("the AWS credentials the server returned have already expired")
	}

	set := map[string]string{
		"AWS_ACCESS_KEY_ID":         accessKeyId,
		"AWS_SECRET_ACCESS_KEY":     secretAccessKey,
		"AWS_SESSION_TOKEN":         sessionToken,
		"AWS_CREDENTIAL_EXPIRATION": expiresAtStr,
	}
	// Some SDKs prefer a named profile over the variables above.
	unset := map[string]bool{"AWS_PROFILE": true, "AWS_DEFAULT_PROFILE": true}
	return mergeEnv(set, unset), expiresAt, nil
}

// azureCommandLogin signs the Azure CLI in to the command's private config directory. The gateway
// swaps the placeholder secret for the real one.
func azureCommandLogin(ctx context.Context, env []string, metadata map[string]string) error {
	tenantId, clientId, subscriptionId := metadata["tenantId"], metadata["clientId"], metadata["subscriptionId"]
	if tenantId == "" || clientId == "" {
		return errors.New("the server did not return the Azure tenant and client for this account")
	}
	if _, err := exec.LookPath("az"); err != nil {
		return errors.New("the Azure CLI ('az') was not found on your PATH. Install it from https://learn.microsoft.com/cli/azure/install-azure-cli")
	}

	login := exec.CommandContext(ctx, "az", "login", "--service-principal",
		"-u", clientId,
		"-p", azureProxyDummySecret,
		"--tenant", tenantId,
		"--allow-no-subscriptions",
		"--output", "none",
	)
	login.Env = env
	login.Stderr = os.Stderr
	if err := login.Run(); err != nil {
		return fmt.Errorf("failed to sign the Azure CLI in through the gateway: %w", err)
	}

	if subscriptionId != "" {
		set := exec.CommandContext(ctx, "az", "account", "set", "--subscription", subscriptionId)
		set.Env = env
		if err := set.Run(); err != nil {
			log.Warn().Err(err).Str("subscription", subscriptionId).Msg("Failed to set the default Azure subscription")
		}
	}
	return nil
}

// localCommandEnv adds the proxy's address under INFISICAL_PAM_* and under the variables each
// account type's usual client already reads, so `-- psql -c ...` needs no connection flags.
func localCommandEnv(response *api.PAMAccessResponse, port int, tempDir string, setup loopbackSetup) ([]string, error) {
	username := response.Metadata["username"]
	database := response.Metadata["database"]
	portStr := strconv.Itoa(port)

	set := map[string]string{
		EnvPAMHost: "127.0.0.1",
		EnvPAMPort: portStr,
	}
	// The proxy injects the real credential, and some protocols refuse a supplied one.
	unset := map[string]bool{"PGPASSWORD": true, "MYSQL_PWD": true}

	if display, ok := ConnectionDisplayFor(response.AccountType); ok {
		if url := display.Connection(username, database, port); url != "" {
			set[EnvPAMURL] = url
		}
	}

	switch response.AccountType {
	case AccountTypePostgres, AccountTypeCockroachDB:
		unset["PGHOSTADDR"] = true
		set["PGHOST"], set["PGPORT"], set["PGUSER"] = "127.0.0.1", portStr, username
		set["PGSSLMODE"] = "disable"
		if database != "" {
			set["PGDATABASE"] = database
		}
	case AccountTypeMySQL:
		set["MYSQL_HOST"], set["MYSQL_TCP_PORT"] = "127.0.0.1", portStr
	case AccountTypeMsSQL:
		set["SQLCMDSERVER"] = "127.0.0.1," + portStr
		set["SQLCMDUSER"], set["SQLCMDPASSWORD"] = username, "x"
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
	case AccountTypeSnowflake:
		account := response.Metadata["account"]
		set["SNOWSQL_ACCOUNT"], set["SNOWSQL_USER"], set["SNOWSQL_PWD"] = account, "pam", "x"
		set["SNOWSQL_HOST"], set["SNOWSQL_PORT"] = "127.0.0.1", portStr
		for key, field := range map[string]string{"SNOWSQL_DATABASE": "database", "SNOWSQL_SCHEMA": "schema", "SNOWSQL_WAREHOUSE": "warehouse"} {
			if value := response.Metadata[field]; value != "" {
				set[key] = value
			}
		}
		set[EnvPAMURL] = fmt.Sprintf("jdbc:snowflake://127.0.0.1:%d/?ssl=off&account=%s%s", port, account,
			jdbcExtras(response.Metadata["database"], response.Metadata["schema"], response.Metadata["warehouse"]))
	case AccountTypeGcpServiceAccount:
		tokenPath, caPath, err := writeProxyFiles(tempDir, setup.caCertPEM)
		if err != nil {
			return nil, err
		}
		set["CLOUDSDK_PROXY_TYPE"], set["CLOUDSDK_PROXY_ADDRESS"], set["CLOUDSDK_PROXY_PORT"] = "http", "127.0.0.1", portStr
		set["CLOUDSDK_PROXY_USERNAME"], set["CLOUDSDK_PROXY_PASSWORD"] = "infisical", setup.proxySecret
		unset["NO_PROXY"], unset["no_proxy"] = true, true
		set["CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"] = tokenPath
		set["CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE"] = caPath
		set[EnvPAMURL] = fmt.Sprintf("http://infisical:%s@127.0.0.1:%d", setup.proxySecret, port)
	case AccountTypeAzureCli:
		_, caPath, err := writeProxyFiles(tempDir, setup.caCertPEM)
		if err != nil {
			return nil, err
		}
		configDir := filepath.Join(tempDir, "azure")
		if err := os.Mkdir(configDir, 0o700); err != nil {
			return nil, fmt.Errorf("failed to create the Azure config directory: %w", err)
		}
		proxyURL := fmt.Sprintf("http://infisical:%s@127.0.0.1:%d", setup.proxySecret, port)
		set["AZURE_CONFIG_DIR"] = configDir
		// A request that skips the proxy would reach Azure with the placeholder secret.
		unset["NO_PROXY"], unset["no_proxy"] = true, true
		set["HTTPS_PROXY"], set["https_proxy"] = proxyURL, proxyURL
		set["REQUESTS_CA_BUNDLE"], set["SSL_CERT_FILE"], set["CURL_CA_BUNDLE"] = caPath, caPath, caPath
		set[EnvPAMURL] = proxyURL
	}

	return mergeEnv(set, unset), nil
}

// writeProxyFiles writes the CA the gateway signs with and a placeholder token the gateway replaces.
func writeProxyFiles(tempDir string, caCertPEM []byte) (string, string, error) {
	tokenPath := filepath.Join(tempDir, "token")
	if err := os.WriteFile(tokenPath, []byte("PROXY_MANAGED"), 0o600); err != nil {
		return "", "", fmt.Errorf("failed to write the token file: %w", err)
	}
	caPath := filepath.Join(tempDir, "ca.pem")
	if err := os.WriteFile(caPath, caCertPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("failed to write the CA file: %w", err)
	}
	return tokenPath, caPath, nil
}

func mergeEnv(set map[string]string, unset map[string]bool) []string {
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
	return env
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

func serveLoopback(ctx context.Context, listener net.Listener, transport *BaseProxyServer, session LiveSession, setup loopbackSetup, connections *sync.WaitGroup) {
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
			relayLoopbackConnection(ctx, conn, transport, session, setup)
		}()
	}
}

func relayLoopbackConnection(ctx context.Context, clientConn net.Conn, transport *BaseProxyServer, session LiveSession, setup loopbackSetup) {
	defer clientConn.Close()

	var initial []byte
	if header := setup.proxyAuthHeader(); header != "" {
		var ok bool
		if initial, ok = readAuthorizedProxyRequest(clientConn, header); !ok {
			return
		}
	}

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

	if setup.caCertPEM != nil {
		if err := writeLengthPrefixed(gatewayConn, setup.caCertPEM); err != nil {
			log.Error().Err(err).Msg("Failed to send CA cert to gateway")
			return
		}
		if err := writeLengthPrefixed(gatewayConn, setup.caKeyPEM); err != nil {
			log.Error().Err(err).Msg("Failed to send CA key to gateway")
			return
		}
	}
	if len(initial) > 0 {
		if _, err := gatewayConn.Write(initial); err != nil {
			log.Error().Err(err).Msg("Failed to forward initial request to gateway")
			return
		}
	}

	relayBothWays(ctx, clientConn, gatewayConn)
}

// readAuthorizedProxyRequest reads the client's first request and returns every byte read so far,
// or false after answering 407 when it lacks the session's Proxy-Authorization.
func readAuthorizedProxyRequest(clientConn net.Conn, header string) ([]byte, bool) {
	var captured bytes.Buffer
	// Any local process can connect, so the unauthenticated read is capped in size and time.
	_ = clientConn.SetReadDeadline(time.Now().Add(awsProxyRequestTimeout))
	defer func() { _ = clientConn.SetReadDeadline(time.Time{}) }()
	req, err := http.ReadRequest(bufio.NewReader(io.TeeReader(io.LimitReader(clientConn, http.DefaultMaxHeaderBytes), &captured)))
	if err != nil {
		if !errors.Is(err, io.EOF) {
			log.Debug().Err(err).Msg("Failed to read initial proxy request")
		}
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(req.Header.Get("Proxy-Authorization")), []byte(header)) != 1 {
		_, _ = clientConn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"infisical-pam\"\r\nContent-Length: 0\r\n\r\n"))
		return nil, false
	}
	return captured.Bytes(), true
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
