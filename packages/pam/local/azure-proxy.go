package pam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog/log"
)

type AzureProxyServer struct {
	BaseProxyServer
	server    net.Listener
	port      int
	caCertPEM []byte
	caKeyPEM  []byte
}

func (p *AzureProxyServer) generateCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial: %w", err)
	}

	caExpiry := time.Until(p.sessionExpiry) + 5*time.Minute
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Infisical PAM Azure Proxy CA"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(caExpiry),
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

func (p *AzureProxyServer) Start(port int) error {
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

func (p *AzureProxyServer) Run() {
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
func (p *AzureProxyServer) Shutdown() {
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

func (p *AzureProxyServer) handleConnection(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		p.activeConnections.Done()
	}()

	select {
	case <-p.ctx.Done():
		return
	default:
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

	connCtx, connCancel := context.WithCancel(p.ctx)
	defer connCancel()

	done := make(chan struct{}, 2)
	go func() {
		defer connCancel()
		_, _ = io.Copy(clientConn, gatewayConn)
		done <- struct{}{}
	}()
	go func() {
		defer connCancel()
		_, _ = io.Copy(gatewayConn, clientConn)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-connCtx.Done():
	}
}

const azureProxyDummySecret = "infisical-pam-proxy-managed"

func startAzureAccess(httpClient *resty.Client, response *api.PAMAccessResponse, path, durationStr string, port int) {
	tenantId := response.Metadata["tenantId"]
	clientId := response.Metadata["clientId"]
	subscriptionId := response.Metadata["subscriptionId"]

	if tenantId == "" || clientId == "" {
		util.PrintErrorMessageAndExit("Backend did not return Azure connection metadata (tenantId/clientId)")
		return
	}

	if _, lookErr := exec.LookPath("az"); lookErr != nil {
		util.PrintErrorMessageAndExit("The Azure CLI ('az') was not found on your PATH. Install it from https://learn.microsoft.com/cli/azure/install-azure-cli")
		return
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &AzureProxyServer{
		BaseProxyServer: BaseProxyServer{
			httpClient:             httpClient,
			relayHost:              response.RelayHost,
			relayClientCert:        response.RelayClientCertificate,
			relayClientKey:         response.RelayClientPrivateKey,
			relayServerCertChain:   response.RelayServerCertificateChain,
			gatewayClientCert:      response.GatewayClientCertificate,
			gatewayClientKey:       response.GatewayClientPrivateKey,
			gatewayServerCertChain: response.GatewayServerCertificateChain,
			sessionExpiry:          time.Now().Add(duration),
			sessionId:              response.SessionId,
			resourceType:           response.AccountType,
			ctx:                    ctx,
			cancel:                 cancel,
			shutdownCh:             make(chan struct{}),
		},
	}

	if err := proxy.ValidateResourceTypeSupported(); err != nil {
		util.HandleError(err, "Gateway version outdated")
		return
	}
	if err := proxy.generateCA(); err != nil {
		util.HandleError(err, "Failed to generate CA for proxy")
		return
	}
	if err := proxy.Start(port); err != nil {
		util.HandleError(err, "Failed to start proxy server")
		return
	}

	go proxy.Run()

	configDir, err := os.MkdirTemp("", "infisical-pam-azure-")
	if err != nil {
		proxy.Shutdown()
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to create isolated Azure config directory: %v", err))
		return
	}
	caFile, err := os.CreateTemp("", "infisical-pam-azure-ca-*.pem")
	if err != nil {
		proxy.Shutdown()
		os.RemoveAll(configDir)
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to create CA file: %v", err))
		return
	}
	caPath := caFile.Name()
	_, _ = caFile.Write(proxy.caCertPEM)
	caFile.Close()

	cleanup := func() {
		proxy.Shutdown()
		_ = os.RemoveAll(configDir)
		_ = os.Remove(caPath)
	}

	setupSig := make(chan os.Signal, 1)
	signal.Notify(setupSig, syscall.SIGINT, syscall.SIGTERM)
	setupDone := make(chan struct{})
	go func() {
		select {
		case <-setupSig:
			cleanup()
			os.Exit(1)
		case <-setupDone:
		}
	}()

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", proxy.port)
	azureEnv := append(os.Environ(),
		"AZURE_CONFIG_DIR="+configDir,
		"HTTPS_PROXY="+proxyURL,
		"https_proxy="+proxyURL,
		"REQUESTS_CA_BUNDLE="+caPath,
		"SSL_CERT_FILE="+caPath,
		"CURL_CA_BUNDLE="+caPath,
	)

	loginCmd := exec.Command(
		"az", "login", "--service-principal",
		"-u", clientId,
		"-p", azureProxyDummySecret,
		"--tenant", tenantId,
		"--allow-no-subscriptions",
		"--output", "none",
	)
	loginCmd.Env = azureEnv
	loginCmd.Stderr = os.Stderr
	if loginErr := loginCmd.Run(); loginErr != nil {
		cleanup()
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to establish Azure CLI session through the gateway: %v", loginErr))
		return
	}

	if subscriptionId != "" {
		setCmd := exec.Command("az", "account", "set", "--subscription", subscriptionId)
		setCmd.Env = azureEnv
		if setErr := setCmd.Run(); setErr != nil {
			log.Warn().Err(setErr).Str("subscription", subscriptionId).Msg("Failed to set default Azure subscription")
		}
	}

	close(setupDone)
	signal.Stop(setupSig)

	folder, account := parsePath(path)
	interactive := isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())

	printAzureSessionInfo(folder, account, duration, subscriptionId, interactive, configDir, proxyURL, caPath)

	if interactive {
		runAzureSubshell(azureEnv, proxy.sessionExpiry, cleanup)
		return
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigChan:
		log.Info().Msgf("Received signal %v, cleaning up...", sig)
		cleanup()
	case <-time.After(time.Until(proxy.sessionExpiry)):
		fmt.Printf("\n  Azure session expired. Cleaning up...\n\n")
		cleanup()
	}
}

func runAzureSubshell(env []string, expiry time.Time, cleanup func()) {
	shell, args := resolveShell()

	cmd := exec.Command(shell, args...)
	cmd.Env = append(env, "INFISICAL_PAM_AZURE=1")
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
		fmt.Printf("\n  Azure session expired. Ending session and cleaning up...\n\n")
		_ = cmd.Process.Kill()
		<-done
	case <-termChan:
		_ = cmd.Process.Kill()
		<-done
	}

	cleanup()
}

func resolveShell() (string, []string) {
	if runtime.GOOS == "windows" {
		if comspec := os.Getenv("COMSPEC"); comspec != "" {
			return comspec, nil
		}
		return "cmd.exe", nil
	}
	if shell := os.Getenv("SHELL"); shell != "" {
		return shell, nil
	}
	return "/bin/sh", nil
}

func printAzureSessionInfo(folder, account string, duration time.Duration, subscriptionId string, interactive bool, configDir, proxyURL, caPath string) {
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("              Azure CLI Session Started!                              \n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
	if folder != "" {
		fmt.Printf("  Folder:       %s\n", folder)
	}
	fmt.Printf("  Account:      %s\n", account)
	fmt.Printf("  Duration:     %s\n", duration.Round(time.Second).String())
	if subscriptionId != "" {
		fmt.Printf("  Subscription: %s\n", subscriptionId)
	}
	fmt.Printf("\n")
	fmt.Printf("  Credentials are brokered by the gateway and never leave it. Every\n")
	fmt.Printf("  command is recorded to the session log.\n")
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                           How to Connect                             \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	if interactive {
		fmt.Printf("  You are now in a shell wired to this session. Run 'az' as usual:\n")
		util.PrintfStderr("    $ az account show\n")
		util.PrintfStderr("    $ az group list\n")
		fmt.Printf("\n")
		fmt.Printf("  Type 'exit' to end the session.\n")
	} else {
		fmt.Printf("  Point the Azure CLI at this session, then run az commands:\n")
		util.PrintfStderr("    $ export AZURE_CONFIG_DIR=\"%s\"\n", configDir)
		util.PrintfStderr("    $ export HTTPS_PROXY=\"%s\"\n", proxyURL)
		util.PrintfStderr("    $ export REQUESTS_CA_BUNDLE=\"%s\"\n", caPath)
		util.PrintfStderr("    $ az group list\n")
		fmt.Printf("\n")
		fmt.Printf("  Press Ctrl+C to end the session.\n")
	}
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
}
