package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	pamagent "github.com/Infisical/infisical-merge/packages/pam/agent"
	pam "github.com/Infisical/infisical-merge/packages/pam/local"
	"github.com/Infisical/infisical-merge/packages/util"
	infisicalSdk "github.com/infisical/go-sdk"
	"github.com/spf13/cobra"
)

var pamCmd = &cobra.Command{
	Use:                   "pam",
	Short:                 "PAM-related commands",
	Long:                  "PAM-related commands for Infisical",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var pamAccessCmd = &cobra.Command{
	Use:   "access <path>",
	Short: "Launch a PAM session for the account at the given path",
	Long: `Launch a PAM session for the account at the given path.
The path format is: /folder/account-name (leading slash optional)`,
	Example:               "infisical pam access /production/postgres-main --duration 2h",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()

		path := args[0]

		reason, err := cmd.Flags().GetString("reason")
		if err != nil {
			util.HandleError(err, "Unable to parse reason flag")
		}

		durationStr, err := cmd.Flags().GetString("duration")
		if err != nil {
			util.HandleError(err, "Unable to parse duration flag")
		}

		_, err = time.ParseDuration(durationStr)
		if err != nil {
			util.HandleError(err, "Invalid duration format. Use formats like '1h', '30m', '2h30m'")
		}

		port, err := cmd.Flags().GetInt("port")
		if err != nil {
			util.HandleError(err, "Unable to parse port flag")
		}

		targetHost, err := cmd.Flags().GetString("target")
		if err != nil {
			util.HandleError(err, "Unable to parse target flag")
		}

		loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
		if err != nil {
			util.HandleError(err, "Unable to get logged in user details")
		}

		isConnected := util.ValidateInfisicalAPIConnection()
		if isConnected && loggedInUserDetails.LoginExpired {
			loggedInUserDetails = util.EstablishUserLoginSession()
		}

		pam.StartPAMAccess(loggedInUserDetails.UserCredentials.JTWToken, path, reason, durationStr, targetHost, port)
	},
}

var pamAgenticCmd = &cobra.Command{
	Use:                   "agentic",
	Short:                 "Run AI agents against PAM accounts",
	Long:                  "Run AI agents against PAM accounts through local proxies",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

// agenticAccessUsage is shown with every argument error, since the '--' separator is easy to get
// wrong and the usual cobra error doesn't show the shape of the command.
const agenticAccessUsage = "  infisical pam agentic access -- <agent command>"

var pamAgenticAccessCmd = &cobra.Command{
	Use:   "access -- <agent command>",
	Short: "Start local proxies for your PAM accounts and launch an AI agent against them",
	Long: `Start a local proxy for each PAM account you can launch, then launch an AI agent with
instructions describing how to reach them.

By default every account you have access to is included. Narrow it with --account, which
may be repeated.

Instructions are delivered in whatever format the agent understands, and their path is
always exported as INFISICAL_PAM_CONTEXT_FILE so custom agents can pick them up too.`,
	Example: `  infisical pam agentic access -- claude
  infisical pam agentic access --account prod/orders-db -- codex --model gpt-5
  infisical pam agentic access --account prod/orders-db --account prod/bastion --duration 30m -- claude
  infisical pam agentic access --reason "investigating INC-4021" -- claude`,
	Args: cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		agentOverride, err := cmd.Flags().GetString("agent")
		if err != nil {
			util.HandleError(err, "Unable to parse agent flag")
		}

		logFile, err := cmd.Flags().GetString("log-file")
		if err != nil {
			util.HandleError(err, "Unable to parse log-file flag")
		}

		accounts, err := cmd.Flags().GetStringArray("account")
		if err != nil {
			util.HandleError(err, "Unable to parse account flag")
		}

		reason, err := cmd.Flags().GetString("reason")
		if err != nil {
			util.HandleError(err, "Unable to parse reason flag")
		}

		noApprovalRequest, err := cmd.Flags().GetBool("no-approval-request")
		if err != nil {
			util.HandleError(err, "Unable to parse no-approval-request flag")
		}

		noSandbox, err := cmd.Flags().GetBool("no-sandbox")
		if err != nil {
			util.HandleError(err, "Unable to parse no-sandbox flag")
		}

		durationStr, err := cmd.Flags().GetString("duration")
		if err != nil {
			util.HandleError(err, "Unable to parse duration flag")
		}
		duration, err := time.ParseDuration(durationStr)
		if err != nil {
			util.PrintErrorMessageAndExit(fmt.Sprintf("Invalid duration %q. Use formats like '1h', '30m', '2h30m'.", durationStr))
		}
		if duration <= 0 {
			util.PrintErrorMessageAndExit(fmt.Sprintf("Duration %q must be positive.", durationStr))
		}

		accounts, namedNothing := resolveAccountFlags(accounts, cmd.Flags().Changed("account"))
		if namedNothing {
			util.PrintErrorMessageAndExit(
				"--account was given but names no account. Pass a path like 'prod/orders-db', " +
					"or drop the flag entirely to include every account you have access to.")
		}

		// Everything after '--' is the agent command, passed through untouched. Without a separator
		// the arguments are still taken as the command, but anything with flags of its own needs the
		// '--', or cobra would try to parse them here.
		childArgs := args
		if dash := cmd.ArgsLenAtDash(); dash >= 0 {
			childArgs = args[dash:]
		}

		if len(childArgs) == 0 {
			util.PrintErrorMessageAndExit("No agent command given. Pass one after '--', for example:\n" + agenticAccessUsage)
		}

		accessToken, stopAuth := resolveAgentAccessToken(cmd)
		defer stopAuth()

		exitCode, err := pamagent.Run(pamagent.Options{
			Accounts:        accounts,
			Duration:        duration,
			Reason:          reason,
			Argv:            childArgs,
			AgentOverride:   agentOverride,
			LogFile:         logFile,
			AccessToken:     accessToken,
			RequestApproval: !noApprovalRequest,
			NoSandbox:       noSandbox,
		})
		if err != nil {
			util.PrintErrorMessageAndExit(err.Error())
		}

		if exitCode != 0 {
			os.Exit(exitCode)
		}
	},
}

// resolveAccountFlags turns repeated and comma-separated --account values into the accounts to bind,
// and reports whether the flag was given but named none.
//
// That second result is the point. An empty list means every account in the organization, so
// '--account ","' or '--account " "' would otherwise widen the run to the whole org, which is the
// opposite of what naming a scope asks for.
//
// flagGiven has to come from the flag set rather than from the values, because pflag discards an empty
// one: '--account ""' and '--account=' both parse to an empty slice, indistinguishable from the flag
// never appearing. Only the flag set remembers that it was set.
func resolveAccountFlags(values []string, flagGiven bool) (accounts []string, namedNothing bool) {
	accounts = splitAccountFlags(values)
	return accounts, flagGiven && len(accounts) == 0
}

// splitAccountFlags lets one --account carry a comma-separated list, so both
// '--account a/b --account c/d' and '--account a/b,c/d' work. Blank entries are dropped rather than
// sent on to be reported as a missing account, so a trailing comma or a stray space is forgiving.
func splitAccountFlags(values []string) []string {
	var accounts []string
	for _, value := range values {
		for _, account := range strings.Split(value, ",") {
			if account = strings.TrimSpace(account); account != "" {
				accounts = append(accounts, account)
			}
		}
	}
	return accounts
}

// resolveAgentAccessToken returns the token to authenticate with, and a stop function to release
// whatever backs it. A machine identity access token takes precedence when one is supplied, since an
// unattended agent shouldn't depend on a human's browser login session staying alive. Otherwise we
// fall back to the stored user login.
//
// The token is returned as a getter because only the machine identity path can be renewed: the SDK
// keeps that one fresh in the background, so the run reads the current value instead of the one it
// started with. A supplied token and a stored login are both fixed for the run.
func resolveAgentAccessToken(cmd *cobra.Command) (accessToken func() string, stop func()) {
	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to parse token")
	}

	if token != nil {
		if token.Type == util.SERVICE_TOKEN_IDENTIFIER {
			util.PrintErrorMessageAndExit("PAM does not support service tokens. Use a machine identity access token, or log in as a user.")
		}
		// Neither of the fixed-token paths can be renewed, so an already-expired one is worth catching
		// now: the alternative is a run that binds every proxy, prints its banner, launches the agent,
		// and only fails once the agent tries its first connection.
		failIfTokenExpired(token.Token, "the provided token")
		return func() string { return token.Token }, func() {}
	}

	// No ready-made token, so a machine identity may still authenticate itself with its own
	// credentials. Only if it asked to: otherwise this falls through to the stored login.
	if source, stopAuth := authenticateMachineIdentity(cmd); source != nil {
		return source, stopAuth
	}

	util.RequireLogin()

	loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
	if err != nil {
		util.HandleError(err, "Unable to get logged in user details")
	}

	if util.ValidateInfisicalAPIConnection() && loggedInUserDetails.LoginExpired {
		loggedInUserDetails = util.EstablishUserLoginSession()
	}

	// Reached with an expired login when the API was unreachable, so the refresh above was skipped.
	jwt := loggedInUserDetails.UserCredentials.JTWToken
	failIfTokenExpired(jwt, "your login")
	return func() string { return jwt }, func() {}
}

// agenticAuthMethods lists what --auth-method accepts, for the flag help and for the error when it
// doesn't. Kept next to the strategy table below so the two cannot drift apart.
const agenticAuthMethods = "universal-auth, kubernetes, azure, gcp-id-token, gcp-iam, aws-iam, oidc-auth, jwt-auth, ldap-auth"

// authenticateMachineIdentity authenticates a machine identity with its own credentials when
// --auth-method (or INFISICAL_AUTH_METHOD) names one, returning a getter for its current access token
// and a stop function. Both are nil when no method was asked for, which leaves the caller on its
// stored-login path.
func authenticateMachineIdentity(cmd *cobra.Command) (accessToken func() string, stop func()) {
	authMethod, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "auth-method", []string{util.INFISICAL_AUTH_METHOD_NAME}, "")
	if err != nil {
		util.HandleError(err, "Unable to parse auth-method flag")
	}

	// "user" is spelled out by some callers to mean the human login, which is already the fallback.
	if authMethod == "" || authMethod == "user" {
		return nil, nil
	}

	valid, strategy := util.IsAuthMethodValid(authMethod, false)
	if !valid {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Invalid auth method %q. Supported: %s.", authMethod, agenticAuthMethods))
	}

	customHeaders, err := util.GetInfisicalCustomHeadersMap()
	if err != nil {
		util.HandleError(err, "Unable to get custom headers")
	}

	// AutoTokenRefresh is left at its default of true, so the client runs a background lifecycle
	// goroutine that keeps this identity's token renewed for as long as ctx lives. An agent session is
	// long-running and outlives the first token, and the caller reads the current one per request, so
	// this is what keeps PAM API calls working late in a run. Same arrangement as the gateway.
	ctx, cancel := context.WithCancel(cmd.Context())
	client := infisicalSdk.NewInfisicalClient(ctx, infisicalSdk.Config{
		SiteUrl:       config.INFISICAL_URL,
		UserAgent:     api.USER_AGENT,
		CustomHeaders: customHeaders,
	})

	authenticator := util.NewSdkAuthenticator(client, cmd)
	strategies := map[util.AuthStrategyType]func() (infisicalSdk.MachineIdentityCredential, error){
		util.AuthStrategy.UNIVERSAL_AUTH:    authenticator.HandleUniversalAuthLogin,
		util.AuthStrategy.KUBERNETES_AUTH:   authenticator.HandleKubernetesAuthLogin,
		util.AuthStrategy.AZURE_AUTH:        authenticator.HandleAzureAuthLogin,
		util.AuthStrategy.GCP_ID_TOKEN_AUTH: authenticator.HandleGcpIdTokenAuthLogin,
		util.AuthStrategy.GCP_IAM_AUTH:      authenticator.HandleGcpIamAuthLogin,
		util.AuthStrategy.AWS_IAM_AUTH:      authenticator.HandleAwsIamAuthLogin,
		util.AuthStrategy.OIDC_AUTH:         authenticator.HandleOidcAuthLogin,
		util.AuthStrategy.JWT_AUTH:          authenticator.HandleJwtAuthLogin,
		util.AuthStrategy.LDAP_AUTH:         authenticator.HandleLdapAuthLogin,
	}

	// IsAuthMethodValid accepts every strategy in util.AVAILABLE_AUTH_STRATEGIES, so a method added
	// there without a handler here has to be reported. Indexing a missing key yields a nil func, and
	// calling that panics, which is what the same table does elsewhere in the CLI for ldap-auth.
	login, supported := strategies[strategy]
	if !supported {
		cancel()
		util.PrintErrorMessageAndExit(fmt.Sprintf("Auth method %q is not supported here. Supported: %s.", authMethod, agenticAuthMethods))
	}

	credential, err := login()
	if err != nil {
		cancel()
		util.HandleError(err, fmt.Sprintf("Unable to authenticate with %s", authMethod))
	}
	if credential.AccessToken == "" {
		cancel()
		util.PrintErrorMessageAndExit(fmt.Sprintf("Authenticating with %s returned no access token.", authMethod))
	}

	// The client's own getter, not the credential we just received: it returns whatever the lifecycle
	// goroutine last renewed to.
	return client.Auth().GetAccessToken, cancel
}

func init() {
	pamAccessCmd.Flags().String("reason", "", "Reason for accessing the account (stored for audit purposes)")
	pamAccessCmd.Flags().String("duration", "1h", "Duration for access session (e.g., '1h', '30m', '2h30m')")
	pamAccessCmd.Flags().Int("port", 0, "Port for the local proxy server (0 for auto-assign)")
	pamAccessCmd.Flags().String("target", "", "Target host to connect to (for accounts that allow multiple hosts, e.g. Windows AD)")

	pamAgenticAccessCmd.Flags().StringArray("account", nil, "Account to expose, as folder/account. Repeatable. Defaults to every account you can launch")
	pamAgenticAccessCmd.Flags().String("duration", "1h", "How long each PAM session may last (e.g. '1h', '30m', '2h30m')")
	pamAgenticAccessCmd.Flags().String("reason", "", "Reason for access, recorded for audit. Required by accounts whose policy demands one")
	pamAgenticAccessCmd.Flags().String("agent", "", "Override agent detection (claude, codex, gemini, generic)")
	pamAgenticAccessCmd.Flags().String("token", "", "Run as a machine identity using its access token")

	// Machine identity auth. Every input the util.SdkAuthenticator handlers read has to be declared
	// here, not just documented: GetCmdFlagOrEnv asks cobra for the flag first and fails on an
	// undeclared one, so the environment variable fallbacks are unreachable without these.
	pamAgenticAccessCmd.Flags().String("auth-method", "", "Authenticate as a machine identity with its own credentials instead of a ready-made --token ["+agenticAuthMethods+"]")
	pamAgenticAccessCmd.Flags().String("client-id", "", "Client id for universal auth")
	pamAgenticAccessCmd.Flags().String("client-secret", "", "Client secret for universal auth")
	pamAgenticAccessCmd.Flags().String("machine-identity-id", "", "Machine identity id for the kubernetes, azure, gcp-id-token, gcp-iam, aws-iam, oidc-auth, jwt-auth and ldap-auth methods")
	pamAgenticAccessCmd.Flags().String("service-account-token-path", "", "Service account token path for kubernetes auth")
	pamAgenticAccessCmd.Flags().String("service-account-key-file-path", "", "Service account key file path for gcp-iam auth")
	pamAgenticAccessCmd.Flags().String("jwt", "", "JWT for the jwt-based methods [oidc-auth, jwt-auth]")
	pamAgenticAccessCmd.Flags().String("ldap-username", "", "Username for ldap-auth")
	pamAgenticAccessCmd.Flags().String("ldap-password", "", "Password for ldap-auth")
	pamAgenticAccessCmd.Flags().String("organization-slug", "", "Scope the session to this sub-organization the machine identity can reach. Defaults to the organization the identity was created in")
	pamAgenticAccessCmd.Flags().String("log-file", "", "Write proxy logs to this file while the agent runs; without it they are not recorded")
	pamAgenticAccessCmd.Flags().Bool("no-approval-request", false, "Don't raise access requests for accounts that need approval; leave those accounts out of the run")
	pamAgenticAccessCmd.Flags().Bool("no-sandbox", false, "Run the agent uncontained, letting it read your Infisical login and other credential files")

	pamAgenticCmd.AddCommand(pamAgenticAccessCmd)

	pamCmd.AddCommand(pamAccessCmd)
	pamCmd.AddCommand(pamAgenticCmd)
	RootCmd.AddCommand(pamCmd)
}
