package agent

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
)

// Account types that expose a local port and can therefore be proxied on demand. The value is the
// label shown to the agent.
var portBasedAccountTypes = map[string]string{
	"postgres":   "PostgreSQL",
	"mysql":      "MySQL",
	"mssql":      "SQL Server",
	"oracledb":   "Oracle",
	"mongodb":    "MongoDB",
	"redis":      "Redis",
	"ssh":        "SSH",
	"kubernetes": "Kubernetes",
	"windows":    "Windows RDP",
}

// Account types held back from the agent flow on purpose, with the reason to show when one turns up.
var withheldAccountTypes = map[string]string{
	// A Windows AD account fronts a whole domain and its host is chosen when the session is created,
	// so a single bound port cannot stand for the account.
	"windows-ad": "Windows AD accounts choose a target host per session, which nothing here can pick on your behalf. Use 'infisical pam access <account> --target <host>'",
}

const accessStatusGranted = "granted"
const accessStatusPending = "pending"

// ResolvedAccount is one account we are going to bind a proxy for.
type ResolvedAccount struct {
	// Path is folderName/name exactly as Infisical spells it. Sessions are created against this
	// rather than what the user typed, which is matched case-insensitively.
	Path        string
	AccountType string
	TypeLabel   string
	Description string
	Duration    time.Duration
	Reason      string
}

// SkippedAccount is an account that was discovered but cannot be proxied, with the reason. The
// reason is reported, so "why isn't my database in the list" has an answer.
type SkippedAccount struct {
	Path   string
	Reason string
}

// ResolveAccounts decides which accounts to bind proxies for. It creates no sessions, so problems
// surface here, while we still own the terminal, rather than later as a dropped connection inside
// the agent.
//
// With no --account flags every account the caller can actually launch is included, and anything
// unusable is skipped with a reason. When accounts are named explicitly, a problem with any one of
// them is fatal: the caller asked for that account by name, so it has to work or say why not.
func ResolveAccounts(httpClient *resty.Client, opts Options) ([]ResolvedAccount, []SkippedAccount, error) {
	accounts, err := listAllAccessibleAccounts(httpClient)
	if err != nil {
		return nil, nil, err
	}

	if len(opts.Accounts) > 0 {
		resolved, err := resolveRequested(accounts, opts)
		return resolved, nil, err
	}
	return resolveEverything(accounts, opts)
}

// resolveRequested handles an explicit --account list. Every problem is collected and reported
// together, so one run shows a caller everything they need to fix.
func resolveRequested(accounts []api.PAMAccessibleAccount, opts Options) ([]ResolvedAccount, error) {
	byPath := make(map[string]api.PAMAccessibleAccount, len(accounts))
	for _, account := range accounts {
		byPath[strings.ToLower(accountPath(account))] = account
	}

	var resolved []ResolvedAccount
	var problems []string
	anyNotFound := false

	for _, requested := range opts.Accounts {
		label := requested

		account, found := byPath[strings.ToLower(strings.TrimPrefix(requested, "/"))]
		if !found {
			problems = append(problems, fmt.Sprintf("%s: not found, or you don't have access to it", label))
			anyNotFound = true
			continue
		}

		if reason := unusableReason(account, opts); reason != "" {
			problems = append(problems, fmt.Sprintf("%s: %s", label, reason))
			continue
		}

		resolved = append(resolved, newResolvedAccount(account, opts))
	}

	if len(problems) > 0 {
		message := fmt.Sprintf("cannot start the following accounts:\n  - %s", strings.Join(problems, "\n  - "))
		// Listed once at the end, so several bad paths don't each repeat the whole thing.
		if anyNotFound {
			message += "\n\n" + availableAccounts(accounts)
		}
		return nil, errors.New(message)
	}
	return resolved, nil
}

// resolveEverything takes every account the caller can launch, skipping the rest with a reason.
func resolveEverything(accounts []api.PAMAccessibleAccount, opts Options) ([]ResolvedAccount, []SkippedAccount, error) {
	var resolved []ResolvedAccount
	var skipped []SkippedAccount

	for _, account := range accounts {
		if reason := unusableReason(account, opts); reason != "" {
			skipped = append(skipped, SkippedAccount{Path: accountPath(account), Reason: reason})
			continue
		}
		resolved = append(resolved, newResolvedAccount(account, opts))
	}

	// Deterministic order: the listing order decides the port assignment, the banner, and which
	// cluster the session kubeconfig makes current, none of which should drift between runs.
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].Path < resolved[j].Path })
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Path < skipped[j].Path })

	if len(resolved) == 0 {
		return nil, nil, errors.New(noUsableAccountsMessage(accounts, skipped))
	}
	return resolved, skipped, nil
}

// unusableReason explains why an account cannot be proxied, or returns "" if it can be.
func unusableReason(account api.PAMAccessibleAccount, opts Options) string {
	if account.DisabledReason != nil && *account.DisabledReason != "" {
		return fmt.Sprintf("account is disabled: %s", *account.DisabledReason)
	}

	if reason, withheld := withheldAccountTypes[account.AccountType]; withheld {
		return reason
	}

	if _, portBased := portBasedAccountTypes[account.AccountType]; !portBased {
		return fmt.Sprintf("%s accounts deliver credentials as files rather than over a port, so they can't be proxied here", account.AccountType)
	}

	if !account.CanLaunch {
		return "you don't have permission to launch sessions for this account"
	}

	if account.RequiresApproval && account.AccessStatus != accessStatusGranted {
		if account.AccessStatus == accessStatusPending {
			return "your access request is still awaiting approval"
		}
		return fmt.Sprintf("requires approval. Request access with 'infisical pam access %s' or from the dashboard", accountPath(account))
	}

	// Prompting is impossible once the agent owns the terminal, so a reason has to come from --reason.
	if account.RequireReason && strings.TrimSpace(opts.Reason) == "" {
		return "requires a reason for access. Pass --reason"
	}

	return ""
}

func newResolvedAccount(account api.PAMAccessibleAccount, opts Options) ResolvedAccount {
	return ResolvedAccount{
		Path:        accountPath(account),
		AccountType: account.AccountType,
		TypeLabel:   portBasedAccountTypes[account.AccountType],
		Description: account.Description,
		Duration:    opts.Duration,
		Reason:      opts.Reason,
	}
}

func accountPath(account api.PAMAccessibleAccount) string {
	return fmt.Sprintf("%s/%s", account.FolderName, account.Name)
}

// noUsableAccountsMessage explains an empty result, listing why each candidate was skipped so the
// fix is obvious without going to the dashboard.
func noUsableAccountsMessage(accounts []api.PAMAccessibleAccount, skipped []SkippedAccount) string {
	if len(accounts) == 0 {
		return "you don't have access to any PAM accounts, so there is nothing to proxy"
	}

	var out strings.Builder
	out.WriteString("none of the accounts you have access to can be proxied:")
	for _, account := range skipped {
		fmt.Fprintf(&out, "\n  - %s: %s", account.Path, account.Reason)
	}
	return out.String()
}

// availableAccounts lists the paths the caller can actually use, so a wrong --account is fixable
// without going to the dashboard to look one up.
func availableAccounts(accounts []api.PAMAccessibleAccount) string {
	if len(accounts) == 0 {
		return "You don't have access to any PAM accounts."
	}

	paths := make([]string, 0, len(accounts))
	for _, account := range accounts {
		paths = append(paths, accountPath(account))
	}
	sort.Strings(paths)

	const limit = 10
	if len(paths) > limit {
		return fmt.Sprintf("Accounts available to you:\n  - %s\n  ...and %d more",
			strings.Join(paths[:limit], "\n  - "), len(paths)-limit)
	}
	return fmt.Sprintf("Accounts available to you:\n  - %s", strings.Join(paths, "\n  - "))
}

// listAllAccessibleAccounts pages through the accessible-accounts endpoint.
func listAllAccessibleAccounts(httpClient *resty.Client) ([]api.PAMAccessibleAccount, error) {
	const pageSize = 100

	var all []api.PAMAccessibleAccount
	for offset := 0; ; offset += pageSize {
		page, err := api.CallPAMListAccessibleAccounts(httpClient, offset, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to list PAM accounts: %w", err)
		}

		all = append(all, page.Accounts...)

		if len(page.Accounts) < pageSize || len(all) >= page.TotalCount {
			break
		}
	}
	return all, nil
}
