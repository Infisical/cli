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
to the connection, and every session is recorded. AWS IAM accounts without a Gateway are
the exception: they get temporary credentials on this machine.

The same commands work for people and AI agents:

  1. List the accounts you can access:
       infisical pam accounts get

  2. Run one command against an account, then exit with its exit code:
       infisical pam access prod/orders-db -- psql -c "select 1"
       infisical pam access prod/bastion -- uptime

  3. If the account needs approval, the command files an access request. When an
     auto-approval rule approves it, the command connects right away. Otherwise it exits
     with an error saying so; a person approves it in Infisical, and you check the status
     with 'infisical pam accounts get <folder/account>' and run the command again.

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
  - Database, Redis, Snowflake, Kubernetes, GCP and Azure accounts run the command on this
    machine, pointed at a local proxy. INFISICAL_PAM_HOST, INFISICAL_PAM_PORT and
    INFISICAL_PAM_URL hold the address, and so do the variables each client reads
    (PGHOST/PGPORT/PGUSER/PGDATABASE, MYSQL_HOST/MYSQL_TCP_PORT, SQLCMDSERVER/SQLCMDUSER,
    SNOWSQL_*, KUBECONFIG, CLOUDSDK_* for gcloud, AZURE_CONFIG_DIR/HTTPS_PROXY for az, which
    is signed in first). To use a variable in the command itself, wrap it in a shell:
    -- sh -c 'redis-cli -u "$INFISICAL_PAM_URL" ping'
    A host or port in a MySQL option file (~/.my.cnf, /etc/my.cnf) overrides MYSQL_HOST and
    MYSQL_TCP_PORT and skips the proxy, so pass them as flags instead:
    -- sh -c 'mysql --no-defaults -h "$INFISICAL_PAM_HOST" -P "$INFISICAL_PAM_PORT" -e "select 1"'
  - AWS IAM accounts with a Gateway run the command against a local proxy (HTTPS_PROXY,
    AWS_CA_BUNDLE and placeholder credentials), and the Gateway signs each request. Without
    a Gateway, the command gets the session's temporary credentials in AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN.
  - Windows accounts can't run a command. Without '--' they start an RDP proxy; run it in
    the background and open the .rdp file it prints with an RDP client.

Connecting through the proxy:
  - Any username works and no password is needed: the Gateway swaps in the real
    credential. Leave password fields empty. Oracle is the exception and needs the
    placeholder password shown by 'infisical pam accounts get <folder/account>'.
  - MongoDB has no database preselected: name one explicitly.

Without '--', SSH accounts open a shell and every other type starts a local proxy (or
credential helper) for your own client until you stop it.

To use several database, Redis or SSH (--proxy) accounts at once, such as copying data
between two databases, start a proxy for each in the background, each on its own --port,
then stop each with kill to end its session:
  infisical pam access prod/orders-db --port 15432 < /dev/null > orders-db.log 2>&1 &
  infisical pam access staging/orders-db --port 15433 < /dev/null > staging-db.log 2>&1 &
Kubernetes and GCP proxies edit your shared kubeconfig and gcloud config, so for those run
one command per account with '--' instead.

Without a terminal, nothing prompts. An account that needs approval gets an access request
filed with --reason and --duration. If an auto-approval rule approves it, the command
connects; otherwise it exits with an error saying it's waiting for approval. An account
that requires MFA exits with an error that has a link a person opens; run the command
again with --mfa-session afterwards.

An account with a device posture policy first checks this device with your device management
provider, by its hardware serial number, and prints each check. A device that fails is denied.
On Linux, the serial number must be readable by your user.`,
	Example: `  infisical pam access prod/orders-db -- psql -c "select count(*) from orders"
  infisical pam access prod/cluster -- kubectl get pods -A
  infisical pam access servers/prod-bastion -- systemctl status nginx
  infisical pam access cloud/gcp-prod -- gcloud storage ls
  infisical pam access cloud/aws-prod -- aws s3 ls
  infisical pam access prod/payments-db --reason "INC-4021" --duration 30m -- psql -c "select 1"
  infisical pam access production/postgres-main --duration 2h
  infisical pam access servers/prod-bastion --proxy`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.MinimumNArgs(1),
	Run:                   runPAMAccess,
}

func runPAMAccess(cmd *cobra.Command, args []string) {
	path := strings.Trim(strings.TrimSpace(args[0]), "/")
	var command []string
	if dash := cmd.ArgsLenAtDash(); dash >= 0 {
		if dash == 0 {
			util.PrintErrorMessageAndExit("Name the account before '--', for example:\n  infisical pam access prod/orders-db -- psql -c \"select 1\"\nTo list the accounts you can access, run: infisical pam accounts get")
		}
		if dash != 1 {
			util.PrintErrorMessageAndExit("Only one account path may be given. Put the command after '--', for example:\n  infisical pam access servers/prod-bastion -- uptime")
		}
		command = args[1:]
		if len(command) == 0 {
			exitWithError(cmd, errPAMMissingCommand(path))
		}
	} else if len(args) > 1 {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Unexpected argument %q. To run a command, put it after '--', for example:\n  infisical pam access %s -- uptime", args[1], path))
	}

	if !pamIsAccountPath(path) {
		exitWithError(cmd, errPAMInvalidPath(args[0]))
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

	accessToken, stopAuth, machineIdentity := resolvePAMAccessToken(cmd)
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
	invocation := pamAccessInvocation{Path: path, HasCommand: len(command) > 0, Reason: strings.TrimSpace(reason), Duration: duration, Interactive: stdinIsTerminal()}
	failure := pamAccessFailure{opts: opts, invocation: invocation, duration: duration, noApprovalRequest: noApprovalRequest, machineIdentity: machineIdentity}

	response, err := openPAMSession(cmd, httpClient, &opts, failure)
	if err != nil {
		approved, deviceVerificationID := handlePAMAccessError(cmd, httpClient, err, failure)
		if !approved {
			return
		}
		// The backend uses up an MFA session before it checks for approval, so it can't be sent twice.
		opts.MfaSessionId = ""
		opts.DeviceVerificationId = deviceVerificationID
		response, err = openPAMSession(cmd, httpClient, &opts, failure)
		if _, gated := pam.ApprovalGateFrom(err); gated {
			exitWithError(cmd, errPAMApprovedRerun(invocation))
		}
		if challenge, ok := pam.MFAChallengeFrom(err); ok {
			exitWithError(cmd, errPAMMFARequiredAfterApproval(invocation, challenge.URL(), challenge.SessionID))
		}
		if err != nil {
			handlePAMAccessError(cmd, httpClient, err, failure)
			return
		}
	}

	if len(command) > 0 && response.AccountType != pam.AccountTypeSSH {
		if !pam.SupportsLocalCommand(response.AccountType) {
			pam.EndSession(httpClient, response.SessionId)
			exitWithError(cmd, errPAMCommandNotSupported(invocation, pamTypeLabel(response.AccountType)))
		}

		started := time.Now()
		exitCode, err := pam.RunLocalCommand(httpClient, response, duration, port, command)
		stopAuth()
		if errors.Is(err, pam.ErrSessionExpired) || errors.Is(err, pam.ErrCredentialsExpired) {
			exitWithError(cmd, errPAMSessionExpired(invocation, time.Since(started).Round(time.Second), errors.Is(err, pam.ErrCredentialsExpired)))
		}
		if errors.Is(err, pam.ErrInterrupted) {
			os.Exit(exitCode)
		}
		var startErr *pam.CommandStartError
		if errors.As(err, &startErr) {
			util.PrintfStderr("%s: couldn't start it. Check that it's installed and on PATH.\n", util.RedactCredentials(util.SanitizeDisplay(startErr.Command)))
			os.Exit(exitCode)
		}
		if err != nil {
			exitWithError(cmd, err, "Failed to run the command")
		}
		os.Exit(exitCode)
	}

	pam.RunAccess(httpClient, response, opts)
}

func openPAMSession(cmd *cobra.Command, httpClient *resty.Client, opts *pam.AccessOptions, f pamAccessFailure) (*api.PAMAccessResponse, error) {
	response, err := pam.OpenSession(httpClient, *opts, true)
	if err == nil {
		return response, nil
	}
	verificationID, handled, deviceErr := pam.ResolveDeviceGate(httpClient, err, util.GetStderrWriter(), false)
	if !handled {
		return nil, err
	}
	if deviceErr != nil {
		exitWithError(cmd, classifyPAMDeviceError(deviceErr, opts.Path, f.machineIdentity), "Failed to check this device")
	}
	opts.DeviceVerificationId = verificationID
	response, err = pam.OpenSession(httpClient, *opts, true)
	if verification, failed := pam.DevicePostureFailedFrom(err); failed {
		pam.PrintDeviceChecks(util.GetStderrWriter(), pam.CheckingDeviceHeader(verification, ""), verification, api.PAMDeviceInfo{})
		exitWithError(cmd, errPAMDevicePostureFailed(opts.Path, err))
	}
	if _, required := pam.DeviceVerificationRequiredFrom(err); required {
		exitWithError(cmd, errPAMDevicePostureFailed(opts.Path, err))
	}
	return response, err
}

func classifyPAMDeviceError(err error, path string, machineIdentity bool) error {
	var postureErr *pam.DevicePostureError
	if errors.As(err, &postureErr) {
		if postureErr.Verification != nil && postureErr.Verification.Status == api.PAMDeviceVerificationError {
			return errPAMDeviceCheckUnavailable(err)
		}
		return errPAMDevicePostureFailed(path, err)
	}
	var infoErr *util.DeviceInfoError
	if errors.As(err, &infoErr) {
		return errPAMDeviceInfoUnavailable(err)
	}
	return classifyPAMAPIError(err, path, pamDeniedLaunch, machineIdentity)
}

type pamAccessFailure struct {
	opts              pam.AccessOptions
	invocation        pamAccessInvocation
	duration          time.Duration
	noApprovalRequest bool
	machineIdentity   bool
}

// handlePAMAccessError exits with why a session couldn't be created. It returns true only when an
// auto-approval rule approved the request it filed, with the device check the session can reuse.
func handlePAMAccessError(cmd *cobra.Command, httpClient *resty.Client, err error, f pamAccessFailure) (bool, string) {
	opts, invocation := f.opts, f.invocation
	if gate, ok := pam.ApprovalGateFrom(err); ok {
		switch {
		case !gate.HasApprovalPolicy:
			exitWithError(cmd, errPAMApprovalNotConfigured(invocation))
		case gate.HasPendingRequest:
			exitWithError(cmd, errPAMApprovalPending(invocation, "", gate.Expired))
		case f.noApprovalRequest:
			exitWithError(cmd, errPAMApprovalRequired(invocation))
		}

		if stdinIsTerminal() {
			if handled, approved, deviceVerificationID, deviceErr := pam.PromptAccessRequest(httpClient, err, opts); handled {
				if deviceErr != nil {
					exitWithError(cmd, classifyPAMDeviceError(deviceErr, opts.Path, f.machineIdentity))
				}
				if approved {
					return true, deviceVerificationID
				}
				if invocation.HasCommand {
					os.Exit(1)
				}
				return false, ""
			}
		}

		if gate.RequireReason && strings.TrimSpace(opts.Reason) == "" {
			exitWithError(cmd, errPAMReasonRequired(invocation, true))
		}

		requestID, approved, deviceVerificationID, requestErr := pam.RaiseAccessRequest(httpClient, opts.Path, strings.TrimSpace(opts.Reason), f.duration)
		if requestErr != nil {
			if pam.IsDeviceError(requestErr) {
				exitWithError(cmd, classifyPAMDeviceError(requestErr, opts.Path, f.machineIdentity))
			}
			exitWithError(cmd, classifyPAMAPIError(requestErr, opts.Path, pamDeniedRequest, f.machineIdentity), "Failed to file an access request")
		}
		if approved {
			return true, deviceVerificationID
		}
		exitWithError(cmd, errPAMApprovalPending(invocation, requestID, gate.Expired))
	}

	if pam.IsReasonRequired(err) {
		exitWithError(cmd, errPAMReasonRequired(invocation, false))
	}

	if challenge, ok := pam.MFAChallengeFrom(err); ok {
		exitWithError(cmd, errPAMMFARequired(invocation, challenge.URL(), challenge.SessionID))
	}

	exitWithError(cmd, classifyPAMAPIError(err, opts.Path, pamDeniedLaunch, f.machineIdentity), "Failed to create PAM session")
	return false, ""
}

// classifyPAMAPIError reads only the status code and the error names the backend guarantees.
func classifyPAMAPIError(err error, path string, denied string, machineIdentity bool) error {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	switch {
	case apiErr.StatusCode == 401, apiErr.StatusCode == 403 && apiErr.Name == "TokenError":
		if machineIdentity {
			return errPAMTokenRejected(err)
		}
		return errPAMAuthRequired(err)
	case apiErr.StatusCode == 403 && apiErr.Name == "ProjectMembershipNotFound":
		return errPAMNotMember(err, machineIdentity)
	case apiErr.StatusCode == 403 && apiErr.Name == "PermissionDenied":
		return errPAMPermissionDenied(err, denied)
	case apiErr.StatusCode == 404 && path != "":
		return errPAMAccountNotFound(path, err)
	}
	return err
}

var pamExtraTypeLabels = map[string]string{
	pam.AccountTypeSnowflake:         "Snowflake",
	pam.AccountTypeAwsIam:            "AWS IAM",
	pam.AccountTypeGcpServiceAccount: "GCP service account",
	pam.AccountTypeAzureCli:          "Azure",
	pam.AccountTypeWindowsAd:         "Windows AD",
}

func pamTypeLabel(accountType string) string {
	if display, ok := pam.ConnectionDisplayFor(accountType); ok && display.TypeLabel != "" {
		return display.TypeLabel
	}
	if label, ok := pamExtraTypeLabels[accountType]; ok {
		return label
	}
	return accountType
}

var pamAgenticCmd = &cobra.Command{
	Use:                   "agentic",
	Short:                 "Run AI agents against PAM accounts (removed)",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ArbitraryArgs,
	Hidden:                true,
	FParseErrWhitelist:    cobra.FParseErrWhitelist{UnknownFlags: true},
	Run: func(cmd *cobra.Command, args []string) {
		exitWithError(cmd, errPAMAgenticRemoved())
	},
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
	pamAccessCmd.Flags().String("mfa-session", "", "MFA session to use after a person completed verification in the browser, from the MFA error")
	pamAccessCmd.Flags().Bool("no-approval-request", false, "Don't file an access request when the account needs approval; exit with an error instead")
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
