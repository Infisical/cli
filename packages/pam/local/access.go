package pam

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/manifoldco/promptui"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog/log"
)

// Account type constants (match API enum)
const (
	AccountTypePostgres   = "postgres"
	AccountTypeSSH        = "ssh"
	AccountTypeMySQL      = "mysql"
	AccountTypeMsSQL      = "mssql"
	AccountTypeMongoDB    = "mongodb"
	AccountTypeOracleDB   = "oracledb"
	AccountTypeRedis      = "redis"
	AccountTypeKubernetes = "kubernetes"
	AccountTypeAwsIam     = "aws-iam"
	AccountTypeWindows    = "windows"
	AccountTypeWindowsAd  = "windows-ad"
)

const approvalRequiredErrorName = "PAM_APPROVAL_REQUIRED"
const grantExpiredErrorName = "PAM_GRANT_EXPIRED"

// normalizePath ensures the path has a leading slash for display purposes.
// Both "/folder/account" and "folder/account" are accepted as input.
func normalizePath(path string) string {
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

// parsePath extracts the folder and account name from a path like "/folder/account"
func parsePath(path string) (folder, account string) {
	// Remove leading slash if present
	cleanPath := strings.TrimPrefix(path, "/")
	parts := strings.SplitN(cleanPath, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	// If no slash, treat the whole thing as account name
	return "", cleanPath
}

// StartPAMAccess initiates a PAM session for the account at the given path.
// The account type is determined from the API response and routed to the appropriate handler.
func StartPAMAccess(accessToken, path, reason, durationStr, targetHost string, port int) {
	// Normalize path for display (ensure leading slash)
	displayPath := normalizePath(path)

	log.Info().Msgf("Starting PAM access for: %s", strings.TrimPrefix(displayPath, "/"))
	log.Info().Msgf("Session duration: %s", durationStr)

	httpClient := resty.New()
	httpClient.SetAuthToken(accessToken)
	httpClient.SetHeader("User-Agent", api.USER_AGENT)

	// The API parses durations with npm ms, which can't read Go compound formats like "2h30m",
	// so send plain milliseconds and keep the Go format for local parsing/display
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Invalid duration format. Use formats like '1h', '30m', '2h30m'")
		return
	}
	apiDurationStr := fmt.Sprintf("%dms", duration.Milliseconds())

	pamResponse, err := CallPAMAccessWithMFA(httpClient, api.PAMAccessRequest{
		Path:       path,
		Duration:   apiDurationStr,
		Reason:     reason,
		TargetHost: targetHost,
	}, true)
	if err != nil {
		if handleApprovalRequired(httpClient, err, path, reason, apiDurationStr) {
			return
		}
		util.HandleError(err, "Failed to create PAM session")
		return
	}

	log.Info().Msgf("Session created with ID: %s", pamResponse.SessionId)
	log.Info().Msgf("Account type: %s", pamResponse.AccountType)

	// Route based on account type from API response
	switch pamResponse.AccountType {
	// Database types - all use the same proxy mechanism with different display configs
	case AccountTypePostgres, AccountTypeMySQL, AccountTypeMsSQL, AccountTypeMongoDB, AccountTypeOracleDB:
		startDatabaseProxy(httpClient, &pamResponse, displayPath, durationStr, port)

	case AccountTypeSSH:
		startSSHAccess(httpClient, &pamResponse, displayPath, durationStr, port)
	case AccountTypeRedis:
		util.PrintErrorMessageAndExit("Redis access not yet supported in the new PAM model")
	case AccountTypeKubernetes:
		startKubernetesProxy(httpClient, &pamResponse, displayPath, durationStr, port)
	case AccountTypeAwsIam:
		startAWSAccess(httpClient, &pamResponse, displayPath, durationStr, port)
	case AccountTypeWindows, AccountTypeWindowsAd:
		startRDPProxy(httpClient, &pamResponse, displayPath, durationStr, port)
	default:
		util.PrintErrorMessageAndExit(fmt.Sprintf("Unsupported account type: %s", pamResponse.AccountType))
	}
}

// handleApprovalRequired intercepts the PAM_APPROVAL_REQUIRED gate. In an interactive terminal it
// offers to submit an access request for the account; otherwise it prints guidance. Returns true when
// the error was an approval-required error (handled here), false to let normal error handling proceed.
func handleApprovalRequired(httpClient *resty.Client, err error, path, reason, durationStr string) bool {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || (apiErr.Name != approvalRequiredErrorName && apiErr.Name != grantExpiredErrorName) {
		return false
	}

	expired := apiErr.Name == grantExpiredErrorName

	// Non-interactive callers (CI, scripts) must see a non-zero exit since no session was created
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		if expired {
			util.PrintErrorMessageAndExit("Your access grant for this account has expired. Request access again from the Infisical dashboard (PAM > My Access).")
		} else {
			util.PrintErrorMessageAndExit("This account requires approval. Request access from the Infisical dashboard (PAM > My Access).")
		}
		return true
	}

	if expired {
		log.Info().Msg("Your previous access grant has expired.")
	} else {
		log.Info().Msg("This account requires approval before you can launch a session.")
	}

	prompt := promptui.Prompt{Label: "Request access now?", IsConfirm: true}
	if _, promptErr := prompt.Run(); promptErr != nil {
		// Ctrl+C (interrupt) must exit non-zero so scripts don't read it as success; declining with 'n'
		// (ErrAbort) is a graceful choice and exits 0.
		if errors.Is(promptErr, promptui.ErrInterrupt) {
			util.PrintErrorMessageAndExit("Access request cancelled")
		}
		log.Info().Msg("No access request created.")
		return true
	}

	requestReason := reason
	if requestReason == "" {
		// The dashboard requires a reason on every access request; keep the CLI consistent
		reasonPrompt := promptui.Prompt{
			Label: "Reason (visible to approvers)",
			Validate: func(input string) error {
				if strings.TrimSpace(input) == "" {
					return errors.New("a reason is required")
				}
				if len(input) > 500 {
					return errors.New("reason must be at most 500 characters")
				}
				return nil
			},
		}
		reasonInput, reasonErr := reasonPrompt.Run()
		if reasonErr != nil {
			if errors.Is(reasonErr, promptui.ErrInterrupt) {
				util.PrintErrorMessageAndExit("Access request cancelled")
			}
			log.Info().Msg("No access request created.")
			return true
		}
		requestReason = strings.TrimSpace(reasonInput)
	}

	if _, reqErr := api.CallPAMCreateAccessRequest(httpClient, api.PAMCreateAccessRequestBody{
		Path:     path,
		Reason:   requestReason,
		Duration: durationStr,
	}); reqErr != nil {
		util.HandleError(reqErr, "Failed to submit access request")
		return true
	}

	log.Info().Msg("Access request submitted. You'll be able to launch a session once it's approved.")
	return true
}

// DatabaseDisplayConfig holds the display configuration for a database type
type DatabaseDisplayConfig struct {
	TypeLabel        string                                             // e.g., "PostgreSQL", "MySQL", "SQL Server"
	DefaultPort      int                                                // default port for this database type
	ConnectionString func(username, database string, port int) string   // builds the connection string
	UsageExamples    func(username, database string, port int) []string // CLI usage examples
}

// databaseConfigs maps account types to their display configurations
var databaseConfigs = map[string]DatabaseDisplayConfig{
	AccountTypePostgres: {
		TypeLabel:   "PostgreSQL",
		DefaultPort: 5432,
		ConnectionString: func(username, database string, port int) string {
			return fmt.Sprintf("postgres://%s@127.0.0.1:%d/%s", username, port, database)
		},
		UsageExamples: func(username, database string, port int) []string {
			return []string{
				fmt.Sprintf("psql -h 127.0.0.1 -p %d -U %s -d %s", port, username, database),
			}
		},
	},
	AccountTypeMySQL: {
		TypeLabel:   "MySQL",
		DefaultPort: 3306,
		ConnectionString: func(username, database string, port int) string {
			return fmt.Sprintf("mysql://%s@127.0.0.1:%d/%s", username, port, database)
		},
		UsageExamples: func(username, database string, port int) []string {
			return []string{
				fmt.Sprintf("mysql -h 127.0.0.1 -P %d -u %s %s", port, username, database),
			}
		},
	},
	AccountTypeMsSQL: {
		TypeLabel:   "SQL Server",
		DefaultPort: 1433,
		ConnectionString: func(username, database string, port int) string {
			return fmt.Sprintf("sqlserver://%s@127.0.0.1:%d?database=%s", username, port, database)
		},
		UsageExamples: func(username, database string, port int) []string {
			return []string{
				fmt.Sprintf("sqlcmd -S 127.0.0.1,%d -U %s -d %s", port, username, database),
			}
		},
	},
	AccountTypeMongoDB: {
		TypeLabel:   "MongoDB",
		DefaultPort: 27017,
		ConnectionString: func(username, database string, port int) string {
			return fmt.Sprintf("mongodb://127.0.0.1:%d/%s", port, database)
		},
		UsageExamples: func(username, database string, port int) []string {
			return []string{
				fmt.Sprintf("mongosh --host 127.0.0.1 --port %d %s", port, database),
			}
		},
	},
	AccountTypeOracleDB: {
		TypeLabel:   "Oracle",
		DefaultPort: 1521,
		ConnectionString: func(username, database string, port int) string {
			return fmt.Sprintf("%s@127.0.0.1:%d/%s", username, port, database)
		},
		UsageExamples: func(username, database string, port int) []string {
			return []string{
				fmt.Sprintf("sqlplus %s@127.0.0.1:%d/%s", username, port, database),
			}
		},
	},
}

// startDatabaseProxy starts a local database proxy for any SQL-like database type
func startDatabaseProxy(httpClient *resty.Client, response *api.PAMAccessResponse, path, durationStr string, port int) {
	config, ok := databaseConfigs[response.AccountType]
	if !ok {
		util.PrintErrorMessageAndExit(fmt.Sprintf("No display config for database type: %s", response.AccountType))
		return
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	// Get connection details from metadata (validate before starting proxy)
	username, ok := response.Metadata["username"]
	if !ok {
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'username'"), "Failed to start proxy server")
		return
	}
	database, ok := response.Metadata["database"]
	if !ok {
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'database'"), "Failed to start proxy server")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &DatabaseProxyServer{
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

	err = proxy.Start(port)
	if err != nil {
		util.HandleError(err, "Failed to start proxy server")
		return
	}

	// Parse path into folder and account
	folder, account := parsePath(path)

	log.Info().Msgf("%s proxy server listening on port %d", config.TypeLabel, proxy.port)
	printDatabaseSessionInfo(config, folder, account, duration, username, database, proxy.port)

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal %v, initiating graceful shutdown...", sig)
		proxy.gracefulShutdown()
	}()

	proxy.Run()
}

func startRDPProxy(httpClient *resty.Client, response *api.PAMAccessResponse, path, durationStr string, port int) {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	username, ok := response.Metadata["username"]
	if !ok {
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'username'"), "Failed to start RDP proxy")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &RDPProxyServer{
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
			// Windows AD is brokered through the Windows RDP gateway protocol
			resourceType: AccountTypeWindows,
			ctx:          ctx,
			cancel:       cancel,
			shutdownCh:   make(chan struct{}),
		},
	}

	if err := proxy.ValidateResourceTypeSupported(); err != nil {
		util.HandleError(err, "Gateway version outdated")
		return
	}

	if err := proxy.Start(port); err != nil {
		util.HandleError(err, "Failed to start RDP proxy server")
		return
	}

	rdpFilePath, err := writeRDPFile(proxy.port, response.SessionId, username)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to write .rdp file; proxy still running")
	} else {
		proxy.rdpFilePath = rdpFilePath
	}

	folder, account := parsePath(path)

	log.Info().Msgf("RDP proxy server listening on port %d", proxy.port)
	util.PrintfStderr("\n")
	util.PrintfStderr("**********************************************************************\n")
	util.PrintfStderr("                      RDP Proxy Session Started!                      \n")
	util.PrintfStderr("**********************************************************************\n")
	util.PrintfStderr("\n")
	if folder != "" {
		util.PrintfStderr("  Folder:    %s\n", folder)
	}
	util.PrintfStderr("  Account:   %s\n", account)
	util.PrintfStderr("  Duration:  %s\n", duration.String())
	util.PrintfStderr("\n")
	util.PrintfStderr("----------------------------------------------------------------------\n")
	util.PrintfStderr("                        Connection Details                            \n")
	util.PrintfStderr("----------------------------------------------------------------------\n")
	util.PrintfStderr("\n")
	util.PrintfStderr("  Host:      127.0.0.1\n")
	util.PrintfStderr("  Port:      %d\n", proxy.port)
	util.PrintfStderr("  Username:  %s\n", username)
	util.PrintfStderr("  Password:  (leave blank)\n")
	if proxy.rdpFilePath != "" {
		util.PrintfStderr("\n")
		util.PrintfStderr("  .rdp file: %s\n", proxy.rdpFilePath)
	}
	util.PrintfStderr("\n")
	util.PrintfStderr("  Press Ctrl+C to terminate the session.\n")
	util.PrintfStderr("**********************************************************************\n")
	util.PrintfStderr("\n")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal %v, initiating graceful shutdown...", sig)
		proxy.gracefulShutdown()
	}()

	proxy.Run()
}

func startSSHAccess(httpClient *resty.Client, response *api.PAMAccessResponse, path, durationStr string, port int) {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	username, ok := response.Metadata["username"]
	if !ok {
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'username'"), "Failed to start SSH session")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &SSHProxyServer{
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

	err = proxy.Start(port)
	if err != nil {
		util.HandleError(err, "Failed to start SSH proxy server")
		return
	}

	folder, account := parsePath(path)

	log.Info().Msgf("SSH proxy server listening on port %d", proxy.port)
	printSSHSessionInfo(folder, account, duration, username, proxy.port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal %v, initiating graceful shutdown...", sig)
		proxy.gracefulShutdown()
	}()

	proxy.Run()
}

func printSSHSessionInfo(folder, account string, duration time.Duration, username string, port int) {
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("              SSH Proxy Session Started!                \n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
	if folder != "" {
		fmt.Printf("  Folder:    %s\n", folder)
	}
	fmt.Printf("  Account:   %s\n", account)
	fmt.Printf("  Duration:  %s\n", duration.String())
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                        Connection Details                            \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	fmt.Printf("  Host:      127.0.0.1\n")
	fmt.Printf("  Port:      %d\n", port)
	if username != "" {
		fmt.Printf("  Username:  %s\n", username)
	}
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                           How to Connect                             \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	fmt.Printf("  Use your preferred SSH client to connect to 127.0.0.1:%d.\n", port)
	fmt.Printf("  Credentials are handled automatically by the gateway.\n")
	fmt.Printf("\n")
	fmt.Printf("  Examples:\n")
	util.PrintfStderr("    $ ssh -p %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@127.0.0.1\n", port, username)
	util.PrintfStderr("    $ scp -P %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null <local-file> %s@127.0.0.1:<remote-path>\n", port, username)
	fmt.Printf("\n")
	fmt.Printf("  Press Ctrl+C to stop the proxy.\n")
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
}

// printDatabaseSessionInfo prints the connection info banner for database sessions
func printDatabaseSessionInfo(config DatabaseDisplayConfig, folder, account string, duration time.Duration, username, database string, port int) {
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("              %s Proxy Session Started!                \n", config.TypeLabel)
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
	if folder != "" {
		fmt.Printf("  Folder:    %s\n", folder)
	}
	fmt.Printf("  Account:   %s\n", account)
	fmt.Printf("  Duration:  %s\n", duration.String())
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                        Connection Details                            \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	fmt.Printf("  Host:      127.0.0.1\n")
	fmt.Printf("  Port:      %d\n", port)
	if username != "" {
		fmt.Printf("  Username:  %s\n", username)
	}
	fmt.Printf("  Password:  (not required)\n")
	if database != "" {
		fmt.Printf("  Database:  %s\n", database)
	}
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                           How to Connect                             \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	fmt.Printf("  Use your preferred database client (CLI, GUI, or IDE) to connect\n")
	fmt.Printf("  to 127.0.0.1:%d. No password is needed.\n", port)
	fmt.Printf("\n")
	if config.UsageExamples != nil {
		examples := config.UsageExamples(username, database, port)
		if len(examples) > 0 {
			fmt.Printf("  Example:\n")
			for _, ex := range examples {
				util.PrintfStderr("    $ %s\n", ex)
			}
			fmt.Printf("\n")
		}
	}
	fmt.Printf("  Connection string:\n")
	connStr := config.ConnectionString(username, database, port)
	util.PrintfStderr("    %s\n", connStr)
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
}

func startKubernetesProxy(httpClient *resty.Client, response *api.PAMAccessResponse, path, durationStr string, port int) {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &KubernetesProxyServer{
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

	err = proxy.Start(port)
	if err != nil {
		util.HandleError(err, "Failed to start proxy server")
		return
	}

	folder, account := parsePath(path)
	clusterName := fmt.Sprintf("infisical-k8s-pam/%s/%s", folder, account)

	if err := proxy.SetupKubeconfig(clusterName); err != nil {
		util.HandleError(err, "Failed to configure kubeconfig")
		proxy.gracefulShutdown()
		return
	}

	log.Info().Msgf("Kubernetes proxy server listening on port %d", proxy.port)
	printKubernetesSessionInfo(folder, account, duration, clusterName, proxy.port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal %v, initiating graceful shutdown...", sig)
		proxy.gracefulShutdown()
	}()

	proxy.Run()
}

func printKubernetesSessionInfo(folder, account string, duration time.Duration, clusterName string, port int) {
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("              Kubernetes Proxy Session Started!                       \n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
	if folder != "" {
		fmt.Printf("  Folder:    %s\n", folder)
	}
	fmt.Printf("  Account:   %s\n", account)
	fmt.Printf("  Duration:  %s\n", duration.String())
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                        Connection Details                            \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	fmt.Printf("  Your kubectl context has been switched to: %s\n", clusterName)
	fmt.Printf("  You can now use kubectl commands to access your Kubernetes cluster.\n")
	fmt.Printf("\n")
	fmt.Printf("  Example:\n")
	util.PrintfStderr("    $ kubectl get pods\n")
	util.PrintfStderr("    $ kubectl get namespaces\n")
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
}
