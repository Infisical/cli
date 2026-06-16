package pam

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

// Account type constants (match API enum)
const (
	AccountTypePostgres        = "postgres"
	AccountTypeSSH             = "ssh"
	AccountTypeMySQL           = "mysql"
	AccountTypeMsSQL           = "mssql"
	AccountTypeMongoDB         = "mongodb"
	AccountTypeOracleDB        = "oracledb"
	AccountTypeRedis           = "redis"
	AccountTypeKubernetes      = "kubernetes"
	AccountTypeAwsIam          = "aws-iam"
	AccountTypeWindows         = "windows"
	AccountTypeActiveDirectory = "active-directory"
)

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
func StartPAMAccess(accessToken, path, reason, durationStr string, port int) {
	// Normalize path for display (ensure leading slash)
	displayPath := normalizePath(path)

	log.Info().Msgf("Starting PAM access for: %s", displayPath)
	log.Info().Msgf("Session duration: %s", durationStr)

	httpClient := resty.New()
	httpClient.SetAuthToken(accessToken)
	httpClient.SetHeader("User-Agent", api.USER_AGENT)

	pamResponse, err := api.CallPAMAccess(httpClient, api.PAMAccessRequest{
		Path:     path,
		Duration: durationStr,
		Reason:   reason,
	})
	if err != nil {
		util.HandleError(err, "Failed to create PAM session")
		return
	}

	log.Info().Msgf("Session created with ID: %s", pamResponse.SessionId)
	log.Info().Msgf("Account type: %s", pamResponse.AccountType)

	// Route based on account type from API response
	switch pamResponse.AccountType {
	case AccountTypePostgres:
		startPostgresProxy(httpClient, &pamResponse, displayPath, durationStr, port)
	case AccountTypeSSH:
		util.PrintErrorMessageAndExit("SSH access not yet supported in the new PAM model")
	case AccountTypeMySQL:
		util.PrintErrorMessageAndExit("MySQL access not yet supported in the new PAM model")
	case AccountTypeMsSQL:
		util.PrintErrorMessageAndExit("MsSQL access not yet supported in the new PAM model")
	case AccountTypeMongoDB:
		util.PrintErrorMessageAndExit("MongoDB access not yet supported in the new PAM model")
	case AccountTypeOracleDB:
		util.PrintErrorMessageAndExit("OracleDB access not yet supported in the new PAM model")
	case AccountTypeRedis:
		util.PrintErrorMessageAndExit("Redis access not yet supported in the new PAM model")
	case AccountTypeKubernetes:
		util.PrintErrorMessageAndExit("Kubernetes access not yet supported in the new PAM model")
	case AccountTypeAwsIam:
		util.PrintErrorMessageAndExit("AWS IAM access not yet supported in the new PAM model")
	case AccountTypeWindows:
		util.PrintErrorMessageAndExit("Windows/RDP access not yet supported in the new PAM model")
	case AccountTypeActiveDirectory:
		util.PrintErrorMessageAndExit("Active Directory access not yet supported in the new PAM model")
	default:
		util.PrintErrorMessageAndExit(fmt.Sprintf("Unsupported account type: %s", pamResponse.AccountType))
	}
}

// startPostgresProxy starts a local Postgres proxy for the given session
func startPostgresProxy(httpClient *resty.Client, response *api.PAMAccessResponse, path, durationStr string, port int) {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
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

	// Get connection details from metadata
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

	// Parse path into folder and account
	folder, account := parsePath(path)

	log.Info().Msgf("Database proxy server listening on port %d", proxy.port)
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("                  Database Proxy Session Started!                    \n")
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
	fmt.Printf("  Host:      localhost\n")
	fmt.Printf("  Port:      %d\n", proxy.port)
	fmt.Printf("  Username:  %s\n", username)
	fmt.Printf("  Password:  (injected by gateway)\n")
	fmt.Printf("  Database:  %s\n", database)
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                        Connection String                             \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	util.PrintfStderr("  postgres://%s@localhost:%d/%s\n", username, proxy.port, database)
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")

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
