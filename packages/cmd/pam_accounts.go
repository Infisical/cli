package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	pam "github.com/Infisical/infisical-merge/packages/pam/local"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/Infisical/infisical-merge/packages/visualize"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

const (
	pamAccessReady         = "ready"
	pamAccessNeedsApproval = "needs_approval"
	pamAccessPending       = "pending"
	pamAccessApproved      = "approved"
	pamAccessUnavailable   = "unavailable"
)

// pamAccountView is the -o json / -o yaml shape of one account.
type pamAccountView struct {
	Path             string     `json:"path" yaml:"path"`
	Folder           string     `json:"folder" yaml:"folder"`
	Name             string     `json:"name" yaml:"name"`
	Description      string     `json:"description" yaml:"description"`
	Type             string     `json:"type" yaml:"type"`
	TypeLabel        string     `json:"typeLabel" yaml:"typeLabel"`
	Access           string     `json:"access" yaml:"access"`
	RequiresApproval bool       `json:"requiresApproval" yaml:"requiresApproval"`
	RequireReason    bool       `json:"requireReason" yaml:"requireReason"`
	RequireMfa       bool       `json:"requireMfa" yaml:"requireMfa"`
	GrantExpiresAt   *time.Time `json:"grantExpiresAt" yaml:"grantExpiresAt"`
	DisabledReason   *string    `json:"disabledReason" yaml:"disabledReason"`
	Example          string     `json:"example" yaml:"example"`
}

func buildPAMAccountsCmd() *cobra.Command {
	accountsCmd := &cobra.Command{
		Use:                   "accounts",
		Short:                 "List the PAM accounts you can access",
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
	}

	getCmd := &cobra.Command{
		Use:   "get [folder | folder/account]",
		Short: "List the PAM accounts you can access, or show one",
		Long: `List the PAM accounts you can access, with whether each is ready to use, needs
approval, or has a request pending. Name a folder to list only its accounts, name one
account (folder/account) to see how to connect to it, or give a bare account name to find
it in any folder.

ACCESS is one of:
  ready           run 'infisical pam access <folder/account>' now
  needs approval  'infisical pam access' files an access request for a person to approve
  pending         a request is waiting for approval
  approved        approved access is active until the time shown
  unavailable     the account can't be used right now; 'accounts get <folder/account>' shows why`,
		Example: `  infisical pam accounts get
  infisical pam accounts get prod
  infisical pam accounts get prod/orders-db
  infisical pam accounts get -o json`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.MaximumNArgs(1),
		Run:                   runPAMAccountsGet,
	}
	addProjectsOutputFlag(getCmd, "Print the accounts in a structured format")
	addPAMAuthFlags(getCmd)

	accountsCmd.AddCommand(getCmd)
	return accountsCmd
}

func runPAMAccountsGet(cmd *cobra.Command, args []string) {
	outputFormat := crudOutputFormat(cmd, "accounts")

	accessToken, stopAuth, machineIdentity := resolvePAMAccessToken(cmd)
	defer stopAuth()
	httpClient := newPAMHTTPClient(accessToken)

	if len(args) == 1 && !strings.HasSuffix(strings.TrimSpace(args[0]), "/") {
		account, found, err := pam.LookupAccessibleAccount(httpClient, args[0])
		if err != nil {
			exitWithError(cmd, classifyPAMAPIError(err, "", pamDeniedList, machineIdentity), "Unable to look up the PAM account")
		}
		if found {
			view := newPAMAccountView(account, machineIdentity)
			if outputFormat != "" {
				printFormattedOutput(outputFormat, view)
			} else {
				printPAMAccountDetails(view)
			}
			Telemetry.CaptureEvent("cli-command:pam accounts get", posthog.NewProperties().Set("version", util.CLI_VERSION))
			return
		}
		if strings.Contains(strings.Trim(strings.TrimSpace(args[0]), "/"), "/") {
			exitWithError(cmd, errPAMAccountOrFolderNotFound(args[0]))
		}
	}

	accounts, err := pam.ListAccessibleAccounts(httpClient, "")
	if err != nil {
		exitWithError(cmd, classifyPAMAPIError(err, "", pamDeniedList, machineIdentity), "Unable to list PAM accounts")
	}

	if len(args) == 1 {
		name := strings.Trim(strings.TrimSpace(args[0]), "/")
		matched := pam.FilterAccountsByFolder(accounts, name)
		if len(matched) == 0 && !strings.Contains(name, "/") {
			matched = pam.FilterAccountsByName(accounts, name)
		}
		accounts = matched
		if len(accounts) == 0 {
			exitWithError(cmd, errPAMAccountOrFolderNotFound(args[0]))
		}
	}

	views := make([]pamAccountView, 0, len(accounts))
	for _, account := range accounts {
		views = append(views, newPAMAccountView(account, machineIdentity))
	}

	if outputFormat != "" {
		printFormattedOutput(outputFormat, views)
	} else if len(views) == 0 {
		printProjectsTip(cmd, "You don't have access to any PAM accounts. Ask a PAM admin for a role on the folders or accounts you need.")
	} else {
		rows := make([][]string, 0, len(views))
		for _, view := range views {
			rows = append(rows, []string{util.SanitizeDisplay(view.Path), view.TypeLabel, pamAccessText(view), strings.Join(pamAccountRequirements(view), ", ")})
		}
		visualize.GenericTable([]string{"PATH", "TYPE", "ACCESS", "REQUIRES"}, rows)
		for _, view := range views {
			if view.Access == pamAccessUnavailable {
				printProjectsTip(cmd, "To see why an account is unavailable, run: infisical pam accounts get <folder/account>")
				break
			}
		}
		printProjectsTip(cmd, "To connect, run: infisical pam access <folder/account> -- <command>. For one account's details, run: infisical pam accounts get <folder/account>")
	}

	Telemetry.CaptureEvent("cli-command:pam accounts get", posthog.NewProperties().Set("accountCount", len(views)).Set("version", util.CLI_VERSION))
}

func newPAMAccountView(account api.PAMAccessibleAccount, machineIdentity bool) pamAccountView {
	view := pamAccountView{
		Path:             pam.AccountPath(account),
		Folder:           account.FolderName,
		Name:             account.Name,
		Description:      account.Description,
		Type:             account.AccountType,
		TypeLabel:        util.SanitizeDisplay(pamTypeLabel(account.AccountType)),
		RequiresApproval: account.RequiresApproval,
		RequireReason:    account.RequireReason,
		RequireMfa:       account.RequireMfa,
		GrantExpiresAt:   account.GrantExpiresAt,
		DisabledReason:   account.DisabledReason,
	}

	switch {
	case !account.CanLaunch:
		view.Access = pamAccessUnavailable
		if view.DisabledReason == nil || strings.TrimSpace(*view.DisabledReason) == "" {
			reason := pamDeniedLaunch
			view.DisabledReason = &reason
		}
	case account.DisabledReason != nil && strings.TrimSpace(*account.DisabledReason) != "":
		view.Access = pamAccessUnavailable
	case machineIdentity && account.RequireMfa:
		view.Access = pamAccessUnavailable
		reason := "This account requires MFA, which a machine identity can't complete."
		view.DisabledReason = &reason
	case !account.RequiresApproval:
		view.Access = pamAccessReady
	case account.AccessStatus == pam.AccessStatusGranted:
		view.Access = pamAccessApproved
	case account.AccessStatus == pam.AccessStatusPending:
		view.Access = pamAccessPending
	default:
		view.Access = pamAccessNeedsApproval
	}

	if view.Access != pamAccessUnavailable {
		view.Example = pamExampleCommand(view)
	}
	return view
}

func pamAccessText(view pamAccountView) string {
	switch view.Access {
	case pamAccessNeedsApproval:
		return "needs approval"
	case pamAccessApproved:
		if view.GrantExpiresAt != nil {
			return "approved until " + view.GrantExpiresAt.Local().Format("Jan 2 15:04")
		}
		return "approved"
	case pamAccessUnavailable:
		return "unavailable"
	}
	return view.Access
}

func pamAccountRequirements(view pamAccountView) []string {
	var notes []string
	if view.RequireReason {
		notes = append(notes, "reason")
	}
	if view.RequireMfa {
		notes = append(notes, "MFA")
	}
	return notes
}

func shellQuotePath(path string) string {
	if strings.ContainsAny(path, " \t'\"$`\\!*?[]{}()<>|&;#~\n") {
		return util.ShellQuote(path)
	}
	return path
}

// pamExampleCommand is the shortest command that proves the account works.
func pamExampleCommand(view pamAccountView) string {
	base := "infisical pam access " + shellQuotePath(view.Path)
	if view.RequireReason {
		base += " --reason \"<reason>\""
	}
	switch view.Type {
	case pam.AccountTypePostgres, pam.AccountTypeCockroachDB:
		return base + " -- psql -c \"select 1\""
	case pam.AccountTypeMySQL:
		// A host in ~/.my.cnf beats MYSQL_HOST; flags beat both, and --no-defaults skips the file.
		return base + " -- sh -c 'mysql --no-defaults -h \"$INFISICAL_PAM_HOST\" -P \"$INFISICAL_PAM_PORT\" -e \"select 1\"'"
	case pam.AccountTypeMsSQL:
		return base + " -- sqlcmd -Q \"select 1\""
	case pam.AccountTypeMongoDB:
		return base + " -- sh -c 'mongosh \"$INFISICAL_PAM_URL\" --quiet --eval \"db.adminCommand({listDatabases: 1})\"'"
	case pam.AccountTypeOracleDB:
		return base + " -- sh -c 'echo \"select 1 from dual;\" | sqlplus -s \"$INFISICAL_PAM_URL\"'"
	case pam.AccountTypeClickhouse:
		return base + " -- sh -c 'curl -s \"http://$INFISICAL_PAM_HOST:$INFISICAL_PAM_PORT/?query=SELECT+1\"'"
	case pam.AccountTypeRedis:
		return base + " -- sh -c 'redis-cli -u \"$INFISICAL_PAM_URL\" ping'"
	case pam.AccountTypeKubernetes:
		return base + " -- kubectl get namespaces"
	case pam.AccountTypeSSH:
		return base + " -- uptime"
	case pam.AccountTypeSnowflake:
		return base + " -- snowsql -q \"select 1\""
	case pam.AccountTypeGcpServiceAccount:
		return base + " -- gcloud projects list --limit 1"
	case pam.AccountTypeAzureCli:
		return base + " -- az account show"
	case pam.AccountTypeAwsIam:
		return base + " -- aws sts get-caller-identity"
	case pam.AccountTypeWindows, pam.AccountTypeWindowsAd:
		return base + " < /dev/null > infisical-rdp.log 2>&1 &"
	}
	return base
}

func printPAMAccountDetails(view pamAccountView) {
	lines := []string{
		fmt.Sprintf("Path:     %s", util.SanitizeDisplay(view.Path)),
		fmt.Sprintf("Type:     %s", view.TypeLabel),
		fmt.Sprintf("Access:   %s", pamAccessText(view)),
	}
	if view.Access == pamAccessUnavailable && view.DisabledReason != nil && *view.DisabledReason != "" {
		lines = append(lines, fmt.Sprintf("Reason:   %s", util.SanitizeDisplay(*view.DisabledReason)))
	}
	if view.Description != "" {
		lines = append(lines, fmt.Sprintf("About:    %s", util.SanitizeDisplay(view.Description)))
	}
	if notes := pamAccountRequirements(view); len(notes) > 0 {
		lines = append(lines, fmt.Sprintf("Requires: %s", strings.Join(notes, ", ")))
	}
	if display, ok := pam.ConnectionDisplayFor(view.Type); ok && display.RequiredPassword != "" {
		lines = append(lines, fmt.Sprintf("Password: send %s; the real credential is swapped in", display.RequiredPassword))
	}
	if view.Type == pam.AccountTypeMongoDB {
		lines = append(lines, "Database: none is preselected; name one explicitly")
	}
	isWindows := view.Type == pam.AccountTypeWindows || view.Type == pam.AccountTypeWindowsAd

	if view.Example == "" {
		util.PrintStdout(strings.Join(lines, "\n") + "\n")
		return
	}
	lines = append(lines, "", "Connect:", "  "+view.Example)
	if isWindows {
		lines = append(lines, "", "This starts an RDP proxy in the background. Open the .rdp file named in infisical-rdp.log with an RDP client; the password is left blank. Stop the CLI with kill to end the session.")
	}
	switch view.Access {
	case pamAccessNeedsApproval:
		lines = append(lines, "", "This files an access request. Unless an auto-approval rule approves it, it exits with an error until a person does.")
	case pamAccessPending:
		lines = append(lines, "", "A request is waiting for a person to approve it. Check again later.")
	}
	if view.RequireMfa && view.Access != pamAccessUnavailable {
		lines = append(lines, "", "MFA: without a terminal this exits with an error that has a link for a person to open.")
	}

	util.PrintStdout(strings.Join(lines, "\n") + "\n")
}
