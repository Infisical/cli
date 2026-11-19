package pam

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	awshandler "github.com/Infisical/infisical-merge/packages/pam/handlers/aws"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog/log"
)

// The AWS SDKs won't send a request without credentials to sign it with. The gateway replaces the
// signature, so these only have to exist.
const awsProxyDummyCredential = "infisical-pam-proxy-managed"

const awsProxyRequestTimeout = 30 * time.Second

type AWSProxyServer struct {
	BaseProxyServer
	server          net.Listener
	port            int
	caCertPEM       []byte
	caKeyPEM        []byte
	proxyAuthHeader string
}

func (p *AWSProxyServer) generateCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Infisical PAM AWS Proxy CA"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              p.sessionExpiry.Add(5 * time.Minute),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}
	p.caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal CA key: %w", err)
	}
	p.caKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return nil
}

func (p *AWSProxyServer) Start(port int) error {
	var err error
	if port == 0 {
		p.server, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		p.server, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	}
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	p.port = p.server.Addr().(*net.TCPAddr).Port
	return nil
}

func (p *AWSProxyServer) Run() {
	defer p.server.Close()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.shutdownCh:
			return
		default:
		}

		if tcpListener, ok := p.server.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := p.server.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-p.ctx.Done():
				return
			case <-p.shutdownCh:
				return
			default:
				log.Error().Err(err).Msg("Failed to accept connection")
				continue
			}
		}

		p.activeConnections.Add(1)
		go p.handleConnection(conn)
	}
}

// Shutdown stops the proxy and notifies the gateway to tear down the session
func (p *AWSProxyServer) Shutdown() {
	p.shutdownOnce.Do(func() {
		p.NotifySessionTermination()
		close(p.shutdownCh)
		if p.server != nil {
			p.server.Close()
		}
		p.cancel()
		p.WaitForConnectionsWithTimeout(5 * time.Second)
	})
}

func (p *AWSProxyServer) handleConnection(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		p.activeConnections.Done()
	}()

	select {
	case <-p.ctx.Done():
		return
	default:
	}

	var captured bytes.Buffer
	// Any local process can connect, so what's read before the proxy credential is checked is capped in
	// size and time
	_ = clientConn.SetReadDeadline(time.Now().Add(awsProxyRequestTimeout))
	clientReader := bufio.NewReader(io.TeeReader(io.LimitReader(clientConn, http.DefaultMaxHeaderBytes), &captured))
	req, err := http.ReadRequest(clientReader)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			log.Debug().Err(err).Msg("Failed to read initial proxy request")
		}
		return
	}
	_ = clientConn.SetReadDeadline(time.Time{})
	if subtle.ConstantTimeCompare([]byte(req.Header.Get("Proxy-Authorization")), []byte(p.proxyAuthHeader)) != 1 {
		log.Warn().Msg("Rejected local proxy client with missing or invalid Proxy-Authorization")
		_, _ = clientConn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"infisical-pam\"\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	// The shell this proxy is wired into sends all of its HTTPS traffic here, so everything that isn't
	// AWS goes straight out as it would without the proxy
	if !awshandler.IsAWSHost(req.Host) {
		p.passThrough(clientConn, clientReader, req)
		return
	}

	relayConn, err := p.CreateRelayConnection()
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to relay")
		return
	}
	defer relayConn.Close()

	gatewayConn, err := p.CreateGatewayConnection(relayConn, ALPNInfisicalPAMProxy)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to gateway")
		return
	}
	defer gatewayConn.Close()

	if err := writeLengthPrefixed(gatewayConn, p.caCertPEM); err != nil {
		log.Error().Err(err).Msg("Failed to send CA cert to gateway")
		return
	}
	if err := writeLengthPrefixed(gatewayConn, p.caKeyPEM); err != nil {
		log.Error().Err(err).Msg("Failed to send CA key to gateway")
		return
	}

	if _, err := gatewayConn.Write(captured.Bytes()); err != nil {
		log.Error().Err(err).Msg("Failed to forward initial request to gateway")
		return
	}

	splice(p.ctx, clientConn, gatewayConn)
}

func (p *AWSProxyServer) passThrough(clientConn net.Conn, clientReader *bufio.Reader, req *http.Request) {
	if req.Method != http.MethodConnect {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}

	upstream, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(p.ctx, "tcp", req.Host)
	if err != nil {
		log.Debug().Err(err).Str("host", req.Host).Msg("Failed to reach host outside AWS")
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}
	defer upstream.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	if buffered := clientReader.Buffered(); buffered > 0 {
		early, _ := clientReader.Peek(buffered)
		if _, err := upstream.Write(early); err != nil {
			return
		}
	}

	splice(p.ctx, clientConn, upstream)
}

func splice(ctx context.Context, a, b net.Conn) {
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	done := make(chan struct{}, 2)
	go func() {
		defer connCancel()
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		defer connCancel()
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-connCtx.Done():
	}
}

// awsProxyEnv points AWS tooling at the proxy. Inherited credentials and NO_PROXY entries are dropped,
// since a request that skips the proxy would reach AWS signed with the placeholder credentials.
func awsProxyEnv(base []string, proxyURL, caPath string) []string {
	env := make([]string, 0, len(base)+6)
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
			"AWS_CA_BUNDLE", "HTTPS_PROXY", "NO_PROXY":
			continue
		}
		env = append(env, entry)
	}
	return append(env,
		"AWS_ACCESS_KEY_ID="+awsProxyDummyCredential,
		"AWS_SECRET_ACCESS_KEY="+awsProxyDummyCredential,
		"AWS_CA_BUNDLE="+caPath,
		"HTTPS_PROXY="+proxyURL,
		"https_proxy="+proxyURL,
	)
}

// The settings awsProxyEnv applies, as commands for a shell the CLI didn't start
func awsProxyExports(proxyURL, caPath string) string {
	return fmt.Sprintf("export HTTPS_PROXY=%[1]s https_proxy=%[1]s AWS_CA_BUNDLE=%[2]s\n"+
		"export AWS_ACCESS_KEY_ID=%[3]s AWS_SECRET_ACCESS_KEY=%[3]s\n"+
		"unset AWS_SESSION_TOKEN AWS_SECURITY_TOKEN NO_PROXY no_proxy\n",
		util.ShellQuote(proxyURL), util.ShellQuote(caPath), util.ShellQuote(awsProxyDummyCredential))
}

// writeTempFile creates a file only the user can read, and removes it if the content can't be written in full
func writeTempFile(pattern string, content []byte) (string, error) {
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	_, err = file.Write(content)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	return file.Name(), nil
}

func startAWSGatewayAccess(httpClient *resty.Client, response *api.PAMAccessResponse, path, durationStr string, port int) {
	sessionExpiry, err := time.Parse(time.RFC3339, response.Metadata["expiresAt"])
	if err != nil {
		duration, parseErr := time.ParseDuration(durationStr)
		if parseErr != nil {
			endSession(httpClient, response.SessionId)
			util.HandleError(parseErr, "Failed to parse duration")
			return
		}
		sessionExpiry = time.Now().Add(duration)
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
			sessionExpiry:          sessionExpiry,
			sessionId:              response.SessionId,
			resourceType:           response.AccountType,
			ctx:                    ctx,
			cancel:                 cancel,
			shutdownCh:             make(chan struct{}),
		},
	}

	if err := proxy.ValidateResourceTypeSupported(); err != nil {
		endSession(httpClient, response.SessionId)
		util.HandleError(err, "Gateway version outdated")
		return
	}
	if err := proxy.generateCA(); err != nil {
		endSession(httpClient, response.SessionId)
		util.HandleError(err, "Failed to generate CA for proxy")
		return
	}
	if err := proxy.Start(port); err != nil {
		endSession(httpClient, response.SessionId)
		util.HandleError(err, "Failed to start proxy server")
		return
	}

	// per-session credential the local client must present
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		proxy.Shutdown()
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to generate proxy credential: %v", err))
		return
	}
	proxySecret := hex.EncodeToString(secretBytes)
	proxy.proxyAuthHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte("infisical:"+proxySecret))

	go proxy.Run()

	caPath, err := writeTempFile("infisical-pam-aws-ca-*.pem", proxy.caCertPEM)
	if err != nil {
		proxy.Shutdown()
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to write CA file: %v", err))
		return
	}

	proxyURL := fmt.Sprintf("http://infisical:%s@127.0.0.1:%d", proxySecret, proxy.port)

	// The printed tips point at this file, which only the user can read, so they never show the proxy password
	envPath, err := writeTempFile("infisical-pam-aws-env-*.sh", []byte(awsProxyExports(proxyURL, caPath)))
	if err != nil {
		proxy.Shutdown()
		_ = os.Remove(caPath)
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to write environment file: %v", err))
		return
	}

	cleanup := func() {
		proxy.Shutdown()
		_ = os.Remove(caPath)
		_ = os.Remove(envPath)
	}

	awsEnv := awsProxyEnv(os.Environ(), proxyURL, caPath)

	folder, account := parsePath(path)
	interactive := isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())

	printAWSGatewaySessionInfo(folder, account, response.Metadata, sessionExpiry, interactive, envPath)

	if interactive {
		runAWSSubshell(awsEnv, sessionExpiry, cleanup)
		return
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigChan:
		log.Info().Msgf("Received signal %v, cleaning up...", sig)
		cleanup()
	case <-time.After(time.Until(sessionExpiry)):
		fmt.Printf("\n  AWS session expired. Cleaning up...\n\n")
		cleanup()
	}
}

func runAWSSubshell(env []string, expiry time.Time, cleanup func()) {
	shell, args := resolveShell()

	cmd := exec.Command(shell, args...)
	cmd.Env = append(env, "INFISICAL_PAM_AWS=1")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cleanup()
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to start shell: %v", err))
		return
	}

	signal.Ignore(syscall.SIGINT)
	defer signal.Reset(syscall.SIGINT)

	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGTERM)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
	case <-time.After(time.Until(expiry)):
		fmt.Printf("\n  AWS session expired. Ending session and cleaning up...\n\n")
		_ = cmd.Process.Kill()
		<-done
	case <-termChan:
		_ = cmd.Process.Kill()
		<-done
	}

	cleanup()
}

func printAWSGatewaySessionInfo(folder, account string, metadata map[string]string, expiresAt time.Time, interactive bool, envPath string) {
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("              AWS IAM Session Started!                                \n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
	if folder != "" {
		fmt.Printf("  Folder:       %s\n", folder)
	}
	fmt.Printf("  Account:      %s\n", account)
	if roleArn := metadata["roleArn"]; roleArn != "" {
		fmt.Printf("  Role:         %s\n", roleArn)
	}
	fmt.Printf("  Duration:     %s\n", time.Until(expiresAt).Round(time.Second).String())
	fmt.Printf("  Expires:      %s\n", expiresAt.Local().Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("\n")
	fmt.Printf("  Credentials are brokered by the gateway and never leave it. Every\n")
	fmt.Printf("  request is recorded to the session log.\n")
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                           How to Connect                             \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	if interactive {
		fmt.Printf("  You are now in a shell wired to this session. Run 'aws' as usual:\n")
		util.PrintfStderr("    $ aws sts get-caller-identity\n")
		util.PrintfStderr("    $ aws s3 ls\n")
		fmt.Printf("\n")
		fmt.Printf("  To use another terminal or your own tooling against this session,\n")
		fmt.Printf("  load the same settings there:\n")
	} else {
		fmt.Printf("  Point AWS tooling at this session, then run aws commands:\n")
	}
	util.PrintfStderr("    $ . %s\n", util.ShellQuote(envPath))
	if !interactive {
		util.PrintfStderr("    $ aws sts get-caller-identity\n")
	}
	fmt.Printf("\n")
	if interactive {
		fmt.Printf("  Type 'exit' to end the session.\n")
	} else {
		fmt.Printf("  Press Ctrl+C to end the session.\n")
	}
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
}
