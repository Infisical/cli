package pam

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/pam/handlers/oracle"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/manifoldco/promptui"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog/log"
)

// Account type constants (match API enum)
const (
	AccountTypePostgres          = "postgres"
	AccountTypeCockroachDB       = "cockroachdb"
	AccountTypeSSH               = "ssh"
	AccountTypeMySQL             = "mysql"
	AccountTypeMsSQL             = "mssql"
	AccountTypeMongoDB           = "mongodb"
	AccountTypeOracleDB          = "oracledb"
	AccountTypeRedis             = "redis"
	AccountTypeSnowflake         = "snowflake"
	AccountTypeClickhouse        = "clickhouse"
	AccountTypeKubernetes        = "kubernetes"
	AccountTypeAwsIam            = "aws-iam"
	AccountTypeGcpServiceAccount = "gcp-service-account"
	AccountTypeAzureCli          = "azure-cli"
	AccountTypeWindows           = "windows"
	AccountTypeWindowsAd         = "windows-ad"
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

// AccessOptions is one invocation of `infisical pam access`.
type AccessOptions struct {
	Path         string
	Reason       string
	Duration     string
	TargetHost   string
	Port         int
	Proxy        bool
	Command      []string
	MfaSessionId string

	DeviceVerificationId string
}

// APIDuration renders a duration the way the API parses it: npm ms can't read Go compound formats
// like "2h30m".
func APIDuration(duration time.Duration) string {
	return fmt.Sprintf("%dms", duration.Milliseconds())
}

// OpenSession creates the PAM session for opts.Path. Prompts (reason, MFA) happen only when
// interactive is set and stdin is a terminal; otherwise the API error is returned for the caller to
// report.
func OpenSession(httpClient *resty.Client, opts AccessOptions, interactive bool) (*api.PAMAccessResponse, error) {
	duration, err := time.ParseDuration(opts.Duration)
	if err != nil {
		return nil, fmt.Errorf("invalid duration %q: %w", opts.Duration, err)
	}

	response, err := CallPAMAccessWithMFA(httpClient, api.PAMAccessRequest{
		Path:                 opts.Path,
		Duration:             APIDuration(duration),
		Reason:               opts.Reason,
		TargetHost:           opts.TargetHost,
		MfaSessionId:         opts.MfaSessionId,
		DeviceVerificationId: opts.DeviceVerificationId,
	}, interactive)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// PromptAccessRequest offers a terminal user an access request for an approval gate. approved
// means an auto-approval rule granted it on submission. deviceErr is a device posture failure, and
// deviceVerificationID a passed check the session can reuse.
func PromptAccessRequest(httpClient *resty.Client, err error, opts AccessOptions) (handled, approved bool, deviceVerificationID string, deviceErr error) {
	duration, parseErr := time.ParseDuration(opts.Duration)
	if parseErr != nil {
		return false, false, "", nil
	}
	return handleApprovalRequired(httpClient, err, opts.Path, opts.Reason, APIDuration(duration))
}

// RunAccess hands an open session to the handler for its account type, and returns once it ends.
func RunAccess(httpClient *resty.Client, pamResponse *api.PAMAccessResponse, opts AccessOptions) {
	displayPath := normalizePath(opts.Path)
	durationStr, port := opts.Duration, opts.Port

	log.Debug().Msgf("Session created with ID: %s", pamResponse.SessionId)
	log.Debug().Msgf("Account type: %s", pamResponse.AccountType)

	switch pamResponse.AccountType {
	case AccountTypePostgres, AccountTypeCockroachDB, AccountTypeMySQL, AccountTypeMsSQL, AccountTypeMongoDB, AccountTypeOracleDB, AccountTypeClickhouse:
		startDatabaseProxy(httpClient, pamResponse, displayPath, durationStr, port)
	case AccountTypeSSH:
		startSSHAccess(httpClient, pamResponse, displayPath, opts)
	case AccountTypeRedis:
		startRedisProxy(httpClient, pamResponse, displayPath, durationStr, port)
	case AccountTypeSnowflake:
		startSnowflakeProxy(httpClient, pamResponse, displayPath, durationStr, port)
	case AccountTypeKubernetes:
		startKubernetesProxy(httpClient, pamResponse, displayPath, durationStr, port)
	case AccountTypeAwsIam:
		startAWSAccess(httpClient, pamResponse, displayPath, durationStr, port)
	case AccountTypeGcpServiceAccount:
		startGCPProxy(httpClient, pamResponse, displayPath, durationStr, port)
	case AccountTypeAzureCli:
		startAzureAccess(httpClient, pamResponse, displayPath, durationStr, port)
	case AccountTypeWindows, AccountTypeWindowsAd:
		startRDPProxy(httpClient, pamResponse, displayPath, durationStr, port)
	default:
		EndSession(httpClient, pamResponse.SessionId)
		util.PrintErrorMessageAndExit(fmt.Sprintf("Unsupported account type: %s", pamResponse.AccountType))
	}
}

// EndSession releases a created session on paths that exit before a proxy or shell owns it
func EndSession(httpClient *resty.Client, sessionId string) {
	if err := api.CallPAMSessionTermination(httpClient, sessionId); err != nil {
		log.Debug().Err(err).Msg("Failed to end session while exiting early")
	}
}

// NewLiveSession converts an access response into the session details a proxy dials through.
func NewLiveSession(response *api.PAMAccessResponse, expiry time.Time) LiveSession {
	return LiveSession{
		SessionId:              response.SessionId,
		GatewayId:              response.GatewayId,
		DirectAddress:          response.DirectAddress,
		RelayHost:              response.RelayHost,
		RelayClientCert:        response.RelayClientCertificate,
		RelayClientKey:         response.RelayClientPrivateKey,
		RelayServerCertChain:   response.RelayServerCertificateChain,
		GatewayClientCert:      response.GatewayClientCertificate,
		GatewayClientKey:       response.GatewayClientPrivateKey,
		GatewayServerCertChain: response.GatewayServerCertificateChain,
		Expiry:                 expiry,
	}
}

// handleApprovalRequired intercepts the PAM_APPROVAL_REQUIRED gate. In an interactive terminal it
// offers to submit an access request for the account; otherwise it prints guidance. Returns true when
// the error was an approval-required error (handled here), false to let normal error handling proceed.
func handleApprovalRequired(httpClient *resty.Client, err error, path, reason, durationStr string) (handled, approved bool, deviceVerificationID string, deviceErr error) {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || (apiErr.Name != approvalRequiredErrorName && apiErr.Name != grantExpiredErrorName) {
		return false, false, "", nil
	}

	expired := apiErr.Name == grantExpiredErrorName

	// Reason requiredness follows the account template's Require Reason policy, surfaced in the
	// approval-gate error details; the dashboard and API enforce the same rule.
	requireReason := false
	hasPendingRequest := false
	hasApprovalPolicy := true
	if details, ok := apiErr.Details.(map[string]any); ok {
		if v, ok := details["requireReason"].(bool); ok {
			requireReason = v
		}
		if v, ok := details["hasPendingRequest"].(bool); ok {
			hasPendingRequest = v
		}
		if v, ok := details["hasApprovalPolicy"].(bool); ok {
			hasApprovalPolicy = v
		}
	}

	// Requesting would only hit a no-approvers error, so explain the misconfiguration instead
	if !hasApprovalPolicy {
		util.PrintErrorMessageAndExit("This account requires approval, but its folder has no approvers configured yet. Ask a folder admin to add approvers under the folder's Approvals tab.")
		return true, false, "", nil
	}

	// Submitting again would only hit the duplicate-request error, so point at the existing one
	if hasPendingRequest {
		util.PrintErrorMessageAndExit("Your access request for this account is awaiting approval. You'll be able to launch a session once it's approved.")
		return true, false, "", nil
	}

	// Non-interactive callers (CI, scripts) must see a non-zero exit since no session was created
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		if expired {
			util.PrintErrorMessageAndExit("Your access grant for this account has expired. Request access again from the Infisical dashboard (PAM > My Access).")
		} else {
			util.PrintErrorMessageAndExit("This account requires approval. Request access from the Infisical dashboard (PAM > My Access).")
		}
		return true, false, "", nil
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
		return true, false, "", nil
	}

	requestReason := reason
	if requestReason == "" {
		label := "Reason (visible to approvers, optional)"
		if requireReason {
			label = "Reason (visible to approvers)"
		}
		reasonPrompt := promptui.Prompt{
			Label: label,
			Validate: func(input string) error {
				if requireReason && strings.TrimSpace(input) == "" {
					return errors.New("a reason is required for this account")
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
			return true, false, "", nil
		}
		requestReason = strings.TrimSpace(reasonInput)
	}

	created, deviceVerificationID, reqErr := createAccessRequest(httpClient, api.PAMCreateAccessRequestBody{
		Path:     path,
		Reason:   requestReason,
		Duration: durationStr,
	})
	if reqErr != nil {
		if IsDeviceError(reqErr) {
			return true, false, "", reqErr
		}
		util.HandleError(reqErr, "Failed to submit access request")
		return true, false, "", nil
	}
	if created.Request.Status == accessRequestStatusApproved {
		log.Info().Msg("Access request approved automatically. Connecting.")
		return true, true, deviceVerificationID, nil
	}

	log.Info().Msg("Access request submitted. You'll be able to launch a session once it's approved.")
	return true, false, "", nil
}

// AccountConnectionDisplay describes how a client reaches one account type through a local proxy.
//
// This is the single source of truth for it. Both the banner `infisical pam access` prints and the
// instructions handed to an agent are built from these, so the two cannot describe the same account
// differently, and a fix to how one connects is a fix for both.
type AccountConnectionDisplay struct {
	TypeLabel   string // e.g., "PostgreSQL", "MySQL", "SQL Server"
	DefaultPort int    // default port for this account type
	// RequiredPassword is the literal string a client must send in its password field, for the account types
	// whose login protocol refuses an empty one. The proxy swaps the real credential in during login. Empty
	// for every type that accepts no password at all.
	RequiredPassword string
	// Note is guidance shown under "How to Connect", one banner line per entry, for an account type
	// whose port does not behave the way a client would assume. Empty for every type that needs none.
	Note []string
	// ConnectionString builds the connection string, and is nil for account types that have none.
	ConnectionString func(username, database string, port int) string
	// UsageExamples builds sample CLI commands, and is nil for account types reached without one.
	UsageExamples func(username, database string, port int) []string
}

// accountDisplays maps account types to how a client connects to them.
//
// A caller that knows the account's real username and database passes them; the agent flow creates
// sessions lazily and so has neither, and passes placeholders. Every entry therefore has to render
// something sane for an empty database.
var accountDisplays = map[string]AccountConnectionDisplay{
	AccountTypePostgres:    postgresWireDisplay("PostgreSQL", 5432),
	AccountTypeCockroachDB: postgresWireDisplay("CockroachDB", 26257),
	AccountTypeMySQL: {
		TypeLabel:   "MySQL",
		DefaultPort: 3306,
		ConnectionString: func(username, database string, port int) string {
			return fmt.Sprintf("mysql://%s@127.0.0.1:%d/%s", urlUser(username), port, url.PathEscape(database))
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
			return fmt.Sprintf("sqlserver://%s@127.0.0.1:%d?database=%s", urlUser(username), port, url.QueryEscape(database))
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
			return mongoDBURI(database, port)
		},
		// Given as a URI rather than --host/--port so the option below cannot be lost by someone
		// adapting the command.
		UsageExamples: func(username, database string, port int) []string {
			return []string{fmt.Sprintf("mongosh %q", mongoDBURI(database, port))}
		},
	},
	AccountTypeOracleDB: {
		TypeLabel:        "Oracle",
		DefaultPort:      1521,
		RequiredPassword: oracle.ProxyPasswordPlaceholder,
		ConnectionString: func(username, database string, port int) string {
			return fmt.Sprintf("%s/%s@127.0.0.1:%d/%s", username, oracle.ProxyPasswordPlaceholder, port, database)
		},
		UsageExamples: func(username, database string, port int) []string {
			return []string{
				fmt.Sprintf("sqlplus %s/%s@127.0.0.1:%d/%s", username, oracle.ProxyPasswordPlaceholder, port, database),
			}
		},
	},
	AccountTypeClickhouse: {
		TypeLabel:   "ClickHouse",
		DefaultPort: 8123,
		Note: []string{
			"This port serves whichever of ClickHouse's two interfaces the account",
			"has configured, detected per connection. JDBC, clickhouse-connect and",
			"curl use the HTTP one; clickhouse-client needs a native port set.",
		},
		ConnectionString: func(username, database string, port int) string {
			return fmt.Sprintf("jdbc:clickhouse://127.0.0.1:%d/%s", port, url.PathEscape(database))
		},
		UsageExamples: func(username, database string, port int) []string {
			return []string{
				fmt.Sprintf("curl 'http://127.0.0.1:%d/?database=%s&query=SELECT+1'", port, url.QueryEscape(database)),
				fmt.Sprintf("clickhouse-client --host 127.0.0.1 --port %d --database %s   # needs a native port",
					port, database),
			}
		},
	},
	AccountTypeRedis: {
		TypeLabel:   "Redis",
		DefaultPort: 6379,
		ConnectionString: func(username, database string, port int) string {
			if username == "" {
				return fmt.Sprintf("redis://127.0.0.1:%d", port)
			}
			return fmt.Sprintf("redis://%s@127.0.0.1:%d", urlUser(username), port)
		},
		UsageExamples: func(username, database string, port int) []string {
			return []string{fmt.Sprintf("redis-cli -h 127.0.0.1 -p %d", port)}
		},
	},
	AccountTypeSSH: {
		TypeLabel:   "SSH",
		DefaultPort: 22,
		// Host key checking is disabled because the proxy presents a different key per session, so
		// a client that remembers one would refuse the next.
		UsageExamples: func(username, database string, port int) []string {
			return []string{
				fmt.Sprintf("ssh -p %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@127.0.0.1", port, username),
				fmt.Sprintf("scp -P %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null <local-file> %s@127.0.0.1:<remote-path>", port, username),
			}
		},
	},
	// Kubernetes and Windows are reached through a generated kubeconfig and an RDP client rather
	// than an address a caller types, so they carry a label and nothing else. Their instructions
	// depend on what else the session set up, and are built by the flow that set it up.
	AccountTypeKubernetes: {
		TypeLabel:   "Kubernetes",
		DefaultPort: 443,
	},
	AccountTypeWindows: {
		TypeLabel:   "Windows RDP",
		DefaultPort: 3389,
	},
}

// urlUser escapes a server-supplied name for the userinfo part of a URL, so it can't add a host or
// query parameters that a client would follow.
func urlUser(name string) string {
	return url.User(name).String()
}

// postgresWireDisplay is shared by the account types reached over the Postgres wire protocol.
func postgresWireDisplay(typeLabel string, defaultPort int) AccountConnectionDisplay {
	return AccountConnectionDisplay{
		TypeLabel:   typeLabel,
		DefaultPort: defaultPort,
		ConnectionString: func(username, database string, port int) string {
			return fmt.Sprintf("postgres://%s@127.0.0.1:%d/%s", urlUser(username), port, url.PathEscape(database))
		},
		UsageExamples: func(username, database string, port int) []string {
			return []string{
				fmt.Sprintf("psql -h 127.0.0.1 -p %d -U %s -d %s", port, username, database),
			}
		},
	}
}

// mongoDBURI builds the loopback URI for a MongoDB proxy, for an account whose database is known or
// not.
//
// directConnection=true is load-bearing, not decoration. The gateway relays the target's hello reply
// to the client, and that reply still names the target's replica set and lists its members' real
// addresses. A driver that reads those abandons the loopback address it was given and dials the
// members instead, which nothing on the client's side can reach, so it hangs until it times out.
// This keeps the driver on the only address that works.
//
// Suppressing those fields gateway-side would fix it for every client without asking any of them to
// pass this, and would be the better fix. Until that happens, this is the fix, so do not drop it as
// redundant.
func mongoDBURI(database string, port int) string {
	return fmt.Sprintf("mongodb://127.0.0.1:%d/%s?directConnection=true", port, url.PathEscape(database))
}

// ConnectionDisplayFor returns how a client reaches the given account type, and whether anything is
// known about it.
func ConnectionDisplayFor(accountType string) (AccountConnectionDisplay, bool) {
	display, ok := accountDisplays[accountType]
	return display, ok
}

// ConnectionExamples returns the sample commands for an account type, or nil if it has none.
func (d AccountConnectionDisplay) ConnectionExamples(username, database string, port int) []string {
	if d.UsageExamples == nil {
		return nil
	}
	return d.UsageExamples(username, database, port)
}

// Connection returns the connection string for an account type, or "" if it has none.
func (d AccountConnectionDisplay) Connection(username, database string, port int) string {
	if d.ConnectionString == nil {
		return ""
	}
	return d.ConnectionString(username, database, port)
}

// startDatabaseProxy starts a local database proxy for any SQL-like database type
func startDatabaseProxy(httpClient *resty.Client, response *api.PAMAccessResponse, path, durationStr string, port int) {
	config, ok := accountDisplays[response.AccountType]
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
			directAddress:          response.DirectAddress,
			relayHost:              response.RelayHost,
			relayClientCert:        response.RelayClientCertificate,
			relayClientKey:         response.RelayClientPrivateKey,
			relayServerCertChain:   response.RelayServerCertificateChain,
			gatewayClientCert:      response.GatewayClientCertificate,
			gatewayClientKey:       response.GatewayClientPrivateKey,
			gatewayServerCertChain: response.GatewayServerCertificateChain,
			gatewayId:              response.GatewayId,
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

func startRedisProxy(httpClient *resty.Client, response *api.PAMAccessResponse, path, durationStr string, port int) {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &RedisProxyServer{
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

	if err := proxy.Start(port); err != nil {
		util.HandleError(err, "Failed to start proxy server")
		return
	}

	folder, account := parsePath(path)
	log.Info().Msgf("Redis proxy server listening on port %d", proxy.port)
	printRedisSessionInfo(folder, account, duration, response.Metadata["username"], proxy.port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal %v, initiating graceful shutdown...", sig)
		proxy.gracefulShutdown()
	}()

	proxy.Run()
}

func printRedisSessionInfo(folder, account string, duration time.Duration, username string, port int) {
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("              Redis Proxy Session Started!                \n")
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
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                           How to Connect                             \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	fmt.Printf("  Use your preferred Redis client to connect to 127.0.0.1:%d.\n", port)
	fmt.Printf("  No password is needed.\n")
	fmt.Printf("\n")
	config := accountDisplays[AccountTypeRedis]
	fmt.Printf("  Example:\n")
	for _, ex := range config.ConnectionExamples(username, "", port) {
		util.PrintfStderr("    $ %s\n", ex)
	}
	fmt.Printf("\n")
	fmt.Printf("  Connection string:\n")
	util.PrintfStderr("    %s\n", config.Connection(username, "", port))
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
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
			directAddress:          response.DirectAddress,
			relayHost:              response.RelayHost,
			relayClientCert:        response.RelayClientCertificate,
			relayClientKey:         response.RelayClientPrivateKey,
			relayServerCertChain:   response.RelayServerCertificateChain,
			gatewayClientCert:      response.GatewayClientCertificate,
			gatewayClientKey:       response.GatewayClientPrivateKey,
			gatewayServerCertChain: response.GatewayServerCertificateChain,
			gatewayId:              response.GatewayId,
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

// startSSHAccess connects straight through as a shell, or by way of a local proxy.
func startSSHAccess(httpClient *resty.Client, response *api.PAMAccessResponse, path string, opts AccessOptions) {
	duration, err := time.ParseDuration(opts.Duration)
	if err != nil {
		EndSession(httpClient, response.SessionId)
		util.HandleError(err, "Failed to parse duration")
		return
	}

	username, ok := response.Metadata["username"]
	if !ok {
		EndSession(httpClient, response.SessionId)
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'username'"), "Failed to start SSH session")
		return
	}

	if opts.Proxy {
		startSSHProxy(httpClient, response, path, duration, username, opts.Port)
		return
	}

	if len(opts.Command) == 0 && !hasInteractiveTerminal() {
		util.PrintfStderr("No terminal attached, so starting a local SSH proxy instead. Pass --proxy to ask for one directly.\n")
		startSSHProxy(httpClient, response, path, duration, username, opts.Port)
		return
	}

	startSSHShell(httpClient, response, path, duration, username, opts.Command)
}

func hasInteractiveTerminal() bool {
	return isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())
}

func startSSHShell(httpClient *resty.Client, response *api.PAMAccessResponse, path string, duration time.Duration, username string, command []string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &BaseProxyServer{
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
		sessionExpiry:          time.Now().Add(duration),
		sessionId:              response.SessionId,
		resourceType:           response.AccountType,
		ctx:                    ctx,
		cancel:                 cancel,
		shutdownCh:             make(chan struct{}),
	}

	// Armed before the gateway round-trip below and the dial that follows, so an interrupt during
	// either still ends the session that StartPAMAccess already created.
	watch, stopWatching := watchForSessionEnd(transport)
	defer stopWatching()

	if err := transport.ValidateResourceTypeSupported(); err != nil {
		transport.NotifySessionTermination()
		util.HandleError(err, "Gateway version outdated")
		return
	}

	if len(command) == 0 {
		util.PrintfStderr("Connecting to %s as %s (session ends in %s)...\n", strings.TrimPrefix(path, "/"), username, duration.String())
	}

	exitCode, err := RunSSHShell(transport, watch, username, command)

	transport.NotifySessionTermination()

	if err != nil {
		util.HandleError(err, "SSH session failed")
		return
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func startSSHProxy(httpClient *resty.Client, response *api.PAMAccessResponse, path string, duration time.Duration, username string, port int) {
	ctx, cancel := context.WithCancel(context.Background())

	proxy := &SSHProxyServer{
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
			sessionExpiry:          time.Now().Add(duration),
			sessionId:              response.SessionId,
			resourceType:           response.AccountType,
			ctx:                    ctx,
			cancel:                 cancel,
			shutdownCh:             make(chan struct{}),
		},
	}

	if err := proxy.ValidateResourceTypeSupported(); err != nil {
		proxy.NotifySessionTermination()
		util.HandleError(err, "Gateway version outdated")
		return
	}

	if err := proxy.Start(port); err != nil {
		proxy.NotifySessionTermination()
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
	for _, ex := range accountDisplays[AccountTypeSSH].ConnectionExamples(username, "", port) {
		util.PrintfStderr("    $ %s\n", ex)
	}
	fmt.Printf("\n")
	fmt.Printf("  Run this from a terminal without --proxy and it connects you straight\n")
	fmt.Printf("  to a shell on the target instead.\n")
	fmt.Printf("\n")
	fmt.Printf("  Press Ctrl+C to stop the proxy.\n")
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
}

// printDatabaseSessionInfo prints the connection info banner for database sessions
func printDatabaseSessionInfo(config AccountConnectionDisplay, folder, account string, duration time.Duration, username, database string, port int) {
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
	if config.RequiredPassword != "" {
		fmt.Printf("  Password:  %s\n", config.RequiredPassword)
	} else {
		fmt.Printf("  Password:  (not required)\n")
	}
	if database != "" {
		fmt.Printf("  Database:  %s\n", database)
	}
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                           How to Connect                             \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	fmt.Printf("  Use your preferred database client (CLI, GUI, or IDE) to connect\n")
	if config.RequiredPassword != "" {
		fmt.Printf("  to 127.0.0.1:%d. Type %s literally as the password; the Gateway\n", port, config.RequiredPassword)
		fmt.Printf("  swaps in the real credential during login.\n")
	} else {
		fmt.Printf("  to 127.0.0.1:%d. No password is needed.\n", port)
	}
	for _, line := range config.Note {
		fmt.Printf("  %s\n", line)
	}
	fmt.Printf("\n")
	if examples := config.ConnectionExamples(username, database, port); len(examples) > 0 {
		fmt.Printf("  Example:\n")
		for _, ex := range examples {
			util.PrintfStderr("    $ %s\n", ex)
		}
		fmt.Printf("\n")
	}
	if connStr := config.Connection(username, database, port); connStr != "" {
		fmt.Printf("  Connection string:\n")
		util.PrintfStderr("    %s\n", connStr)
		fmt.Printf("\n")
	}
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
			directAddress:          response.DirectAddress,
			relayHost:              response.RelayHost,
			relayClientCert:        response.RelayClientCertificate,
			relayClientKey:         response.RelayClientPrivateKey,
			relayServerCertChain:   response.RelayServerCertificateChain,
			gatewayClientCert:      response.GatewayClientCertificate,
			gatewayClientKey:       response.GatewayClientPrivateKey,
			gatewayServerCertChain: response.GatewayServerCertificateChain,
			gatewayId:              response.GatewayId,
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
