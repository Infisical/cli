package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	pam "github.com/Infisical/infisical-merge/packages/pam/local"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
)

var pamCmd = &cobra.Command{
	Use:   "pam",
	Short: "Connect to accounts managed by Infisical PAM",
	Long: `Connect to databases, servers and clusters managed by Infisical Privileged Access
Management (PAM). Credentials never reach your machine: the Infisical Gateway adds them
to the connection, and every session is recorded.

The same commands work for people and AI agents:

  1. List the accounts you can access:
       infisical pam accounts get

  2. Run one command against an account, then exit with its exit code:
       infisical pam access prod/orders-db -- psql -c "select 1"
       infisical pam access prod/bastion -- uptime

  3. If the account needs approval, the command files an access request and exits with
     approval_pending. A person approves it in Infisical; check the status with
     'infisical pam accounts get <folder/account>' and run the command again.

Run as a machine identity by setting INFISICAL_TOKEN, or INFISICAL_AUTH_METHOD with that
method's credentials. Otherwise the user logged in with 'infisical login' is used.`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var pamAccessCmd = &cobra.Command{
	Use:   "access <folder/account> [-- <command>]",
	Short: "Launch a PAM session for the account at the given path",
	Long: `Launch a PAM session for the account at the given path (folder/account).

With a command after '--', the command runs once and the session ends when it exits.
The CLI exits with the command's exit code:

  - SSH accounts run the command on the target.
  - Database, Redis and Kubernetes accounts run the command on this machine, pointed at a
    local proxy. INFISICAL_PAM_HOST, INFISICAL_PAM_PORT and INFISICAL_PAM_URL hold the
    address, and so do the variables each client reads (PGHOST/PGPORT/PGUSER/PGDATABASE,
    MYSQL_HOST/MYSQL_TCP_PORT, SQLCMDSERVER/SQLCMDUSER, KUBECONFIG). To use a variable in
    the command itself, wrap it in a shell: -- sh -c 'redis-cli -u "$INFISICAL_PAM_URL" ping'

Connecting through the proxy:
  - Any username works and no password is needed: the Gateway swaps in the real
    credential. Leave password fields empty. Oracle is the exception and needs the
    placeholder password shown by 'infisical pam accounts get <folder/account>'.
  - MongoDB has no database preselected: name one explicitly.

Without '--', SSH accounts open a shell and every other type starts a local proxy (or
credential helper) for your own client until you stop it.

Without a terminal, nothing prompts. An account that needs approval gets an access request
filed with --reason and --duration, and the command exits with approval_pending. An account
that requires MFA exits with mfa_required and a link a person opens; run the command again
with --mfa-session afterwards. Pass -o json to get errors as JSON with a stable code.`,
	Example: `  infisical pam access prod/orders-db -- psql -c "select count(*) from orders"
  infisical pam access prod/cluster -- kubectl get pods -A
  infisical pam access servers/prod-bastion -- systemctl status nginx
  infisical pam access prod/payments-db --reason "INC-4021" --duration 30m -- psql -c "select 1"
  infisical pam access production/postgres-main --duration 2h
  infisical pam access servers/prod-bastion --proxy`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.MinimumNArgs(1),
	Run:                   runPAMAccess,
}

func runPAMAccess(cmd *cobra.Command, args []string) {
	path := args[0]
	var command []string
	if dash := cmd.ArgsLenAtDash(); dash >= 0 {
		if dash != 1 {
			util.PrintErrorMessageAndExit("Only one account path may be given. Put the command after '--', for example:\n  infisical pam access servers/prod-bastion -- uptime")
		}
		command = args[1:]
	} else if len(args) > 1 {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Unexpected argument %q. To run a command, put it after '--', for example:\n  infisical pam access %s -- uptime", args[1], path))
	}

	reason, _ := cmd.Flags().GetString("reason")
	durationStr, _ := cmd.Flags().GetString("duration")
	port, _ := cmd.Flags().GetInt("port")
	targetHost, _ := cmd.Flags().GetString("target")
	proxy, _ := cmd.Flags().GetBool("proxy")
	mfaSessionID, _ := cmd.Flags().GetString("mfa-session")
	noApprovalRequest, _ := cmd.Flags().GetBool("no-approval-request")

	duration, err := time.ParseDuration(durationStr)
	if err != nil || duration <= 0 {
		exitWithError(cmd, errPAMInvalidDuration(durationStr))
	}

	if proxy && len(command) > 0 {
		util.PrintErrorMessageAndExit("--proxy starts a local proxy for your own client, so it cannot also run a command. Drop one of the two.")
	}

	accessToken, stopAuth := resolvePAMAccessToken(cmd)
	defer stopAuth()
	httpClient := newPAMHTTPClient(accessToken)

	opts := pam.AccessOptions{
		Path:         path,
		Reason:       reason,
		Duration:     durationStr,
		TargetHost:   targetHost,
		Port:         port,
		Proxy:        proxy,
		Command:      command,
		MfaSessionId: mfaSessionID,
	}
	invocation := pamAccessInvocation{Path: path, HasCommand: len(command) > 0}

	response, err := pam.OpenSession(httpClient, opts, true)
	if err != nil {
		handlePAMAccessError(cmd, httpClient, err, opts, invocation, duration, noApprovalRequest)
		return
	}

	if len(command) > 0 && response.AccountType != pam.AccountTypeSSH {
		if !pam.SupportsLocalCommand(response.AccountType) {
			pam.EndSession(httpClient, response.SessionId)
			exitWithError(cmd, errPAMCommandNotSupported(invocation, pamTypeLabel(response.AccountType)))
		}

		exitCode, err := pam.RunLocalCommand(httpClient, response, duration, port, command)
		stopAuth()
		if errors.Is(err, pam.ErrSessionExpired) {
			exitWithError(cmd, errPAMSessionExpired(invocation, duration))
		}
		var startErr *pam.CommandStartError
		if errors.As(err, &startErr) {
			util.PrintfStderr("%s: couldn't start it. Check that it's installed and on PATH.\n", util.SanitizeDisplay(startErr.Command))
			os.Exit(exitCode)
		}
		if err != nil {
			exitWithError(cmd, err, "Failed to run the command")
		}
		os.Exit(exitCode)
	}

	pam.RunAccess(httpClient, response, opts)
}

// handlePAMAccessError reports why a session couldn't be created. In a terminal an approval gate
// still offers to file a request; without one, the request is filed (unless --no-approval-request)
// and the error says what to wait for.
func handlePAMAccessError(cmd *cobra.Command, httpClient *resty.Client, err error, opts pam.AccessOptions, invocation pamAccessInvocation, duration time.Duration, noApprovalRequest bool) {
	if gate, ok := pam.ApprovalGateFrom(err); ok {
		switch {
		case !gate.HasApprovalPolicy:
			exitWithError(cmd, errPAMApprovalNotConfigured(invocation))
		case gate.HasPendingRequest:
			exitWithError(cmd, errPAMApprovalPending(invocation, "", gate.Expired))
		case noApprovalRequest:
			exitWithError(cmd, errPAMApprovalRequired(invocation))
		}

		if stdinIsTerminal() && pam.PromptAccessRequest(httpClient, err, opts) {
			return
		}

		if gate.RequireReason && strings.TrimSpace(opts.Reason) == "" {
			exitWithError(cmd, errPAMReasonRequired(invocation, true))
		}

		requestID, requestErr := pam.RaiseAccessRequest(httpClient, opts.Path, strings.TrimSpace(opts.Reason), duration)
		if requestErr != nil {
			exitWithError(cmd, classifyPAMAPIError(requestErr, opts.Path), "Failed to file an access request")
		}
		exitWithError(cmd, errPAMApprovalPending(invocation, requestID, gate.Expired))
	}

	if pam.IsReasonRequired(err) {
		exitWithError(cmd, errPAMReasonRequired(invocation, false))
	}

	if challenge, ok := pam.MFAChallengeFrom(err); ok {
		exitWithError(cmd, errPAMMFARequired(invocation, challenge.URL(), challenge.SessionID))
	}

	exitWithError(cmd, classifyPAMAPIError(err, opts.Path), "Failed to create PAM session")
}

// classifyPAMAPIError reads only the status code and the error names the backend guarantees.
func classifyPAMAPIError(err error, path string) error {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	switch {
	case apiErr.StatusCode == 401, apiErr.StatusCode == 403 && apiErr.Name == "TokenError":
		return errPAMAuthRequired(err)
	case apiErr.StatusCode == 403 && apiErr.Name == "PermissionDenied":
		return errPAMPermissionDenied(err)
	case apiErr.StatusCode == 404 && path != "":
		return errPAMAccountNotFound(path, err)
	}
	return err
}

func pamTypeLabel(accountType string) string {
	if display, ok := pam.ConnectionDisplayFor(accountType); ok && display.TypeLabel != "" {
		return display.TypeLabel
	}
	return accountType
}

var pamAgenticCmd = &cobra.Command{
	Use:                   "agentic",
	Short:                 "Run AI agents against PAM accounts (removed)",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Hidden:                true,
}

var pamAgenticAccessCmd = &cobra.Command{
	Use:     "access -- <agent command>",
	Short:   "Removed: agents now run 'infisical pam accounts get' and 'infisical pam access' directly",
	Example: "  infisical pam access prod/orders-db -- psql -c \"select 1\"",
	Args:    cobra.ArbitraryArgs,
	Hidden:  true,
	Run: func(cmd *cobra.Command, args []string) {
		exitWithError(cmd, errPAMAgenticRemoved())
	},
}

func init() {
	pamAccessCmd.Flags().String("reason", "", "Reason for accessing the account, recorded for audit and shown to approvers")
	pamAccessCmd.Flags().String("duration", "1h", "Duration for access session (e.g., '1h', '30m', '2h30m')")
	pamAccessCmd.Flags().Int("port", 0, "Port for the local proxy server (0 for auto-assign)")
	pamAccessCmd.Flags().String("target", "", "Target host to connect to (for accounts that allow multiple hosts, e.g. Windows AD)")
	pamAccessCmd.Flags().Bool("proxy", false, "Start a local proxy to point your own client at, instead of connecting you to the target. Only SSH accounts connect directly today")
	pamAccessCmd.Flags().String("mfa-session", "", "MFA session to use after a person completed verification in the browser, from an mfa_required error")
	pamAccessCmd.Flags().Bool("no-approval-request", false, "Don't file an access request when the account needs approval; exit with approval_required instead")
	pamAccessCmd.Flags().StringP("output", "o", "", "Print errors as json or yaml instead of text, with a stable code")
	addPAMAuthFlags(pamAccessCmd)

	// Kept, hidden, so scripts that pass these flags get the removal message rather than a flag error.
	pamAgenticAccessCmd.Flags().StringArray("account", nil, "Removed")
	pamAgenticAccessCmd.Flags().String("duration", "1h", "Removed")
	pamAgenticAccessCmd.Flags().String("reason", "", "Removed")
	pamAgenticAccessCmd.Flags().String("agent", "", "Removed")
	pamAgenticAccessCmd.Flags().String("log-file", "", "Removed")
	pamAgenticAccessCmd.Flags().Bool("no-approval-request", false, "Removed")
	pamAgenticAccessCmd.Flags().Bool("no-sandbox", false, "Removed")
	addPAMAuthFlags(pamAgenticAccessCmd)

	pamAgenticCmd.AddCommand(pamAgenticAccessCmd)

	pamCmd.AddCommand(pamAccessCmd)
	pamCmd.AddCommand(buildPAMAccountsCmd())
	pamCmd.AddCommand(pamAgenticCmd)
	RootCmd.AddCommand(pamCmd)
}
