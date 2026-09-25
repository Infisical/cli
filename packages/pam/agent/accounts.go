package agent

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	pam "github.com/Infisical/infisical-merge/packages/pam/local"
	"github.com/go-resty/resty/v2"
)

// Account types the agent flow can expose. Deliberately a list of its own rather than everything the
// CLI can reach: aws-iam, gcp-service-account and azure-cli hand out credentials rather than front a
// port, so nothing here can contain what an agent does with them.
var supportedAccountTypes = map[string]bool{
	"postgres":   true,
	"mysql":      true,
	"mssql":      true,
	"oracledb":   true,
	"mongodb":    true,
	"redis":      true,
	"ssh":        true,
	"kubernetes": true,
	"windows":    true,
}

// typeLabelFor names an account type for display, from the same table the `infisical pam access`
// banner reads, so an agent and a human are shown the same name for the same type.
func typeLabelFor(accountType string) string {
	if display, ok := pam.ConnectionDisplayFor(accountType); ok && display.TypeLabel != "" {
		return display.TypeLabel
	}
	return accountType
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
	Duration    time.Duration
	Reason      string

	// RequiresApproval and AccessStatus are the approval gate as it stood at resolve time.
	RequiresApproval bool
	AccessStatus     string
}

// AwaitingApproval reports whether a session for this account is gated behind a reviewer. Such an
// account still gets a port: the request is raised on first use, and approval landing mid-run brings
// the account to life on the next connection without anything being restarted.
func (a ResolvedAccount) AwaitingApproval() bool {
	return a.RequiresApproval && a.AccessStatus != accessStatusGranted
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
//
// An account named more than once is bound once. Naming it twice is a typo rather than a request for
// two of it, and honouring it literally would cost a second port and open a second session against
// the same account, leaving a duplicate in the audit trail for nothing.
func resolveRequested(accounts []api.PAMAccessibleAccount, opts Options) ([]ResolvedAccount, error) {
	byPath := make(map[string]api.PAMAccessibleAccount, len(accounts))
	for _, account := range accounts {
		byPath[strings.ToLower(accountPath(account))] = account
	}

	var resolved []ResolvedAccount
	var problems []string
	anyNotFound := false

	// Keyed by the lookup key rather than by what was typed, which is the account's own path once it
	// resolves. Spellings that differ only by case or a leading slash therefore collapse together, the
	// same way they do when matching. A name that resolves to nothing is deduplicated on what was
	// typed, so repeating a typo reports it once rather than once per mention.
	seen := make(map[string]bool, len(opts.Accounts))

	for _, requested := range opts.Accounts {
		label := requested

		key := strings.ToLower(strings.TrimPrefix(requested, "/"))
		if seen[key] {
			continue
		}
		seen[key] = true

		account, found := byPath[key]
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

	if _, supported := supportedAccountTypes[account.AccountType]; !supported {
		return fmt.Sprintf("%s accounts are not supported by the agent flow yet", account.AccountType)
	}

	if !account.CanLaunch {
		return "you don't have permission to launch sessions for this account"
	}

	// MFA needs a human in a browser at the moment the session is created, and an agent run has
	// nobody there. Unlike an approval gate, nothing can change that part-way through, so the account
	// is left out rather than given a port that could only ever refuse.
	if account.RequireMfa {
		return "requires MFA, which cannot be completed from an agent run. Use 'infisical pam access' from your own terminal"
	}

	// An approval gate is deliberately not a reason to skip while requests can be raised: one is
	// raised for the account on first use and its proxy is bound anyway, so approval landing part-way
	// through a run brings the account up without restarting the agent.
	//
	// Without --no-approval-request that hope is real. With it, nothing will ever raise the request, so
	// the account cannot come up no matter how long the agent waits. Reserving a port for it and
	// telling the agent to keep retrying would promise something this run has been told not to do.
	if account.RequiresApproval && account.AccessStatus != accessStatusGranted && !opts.RequestApproval {
		return "requires approval, and --no-approval-request was set, so no request can be raised for it"
	}

	// Prompting is impossible once the agent owns the terminal, so a reason has to come from --reason.
	if account.RequireReason && strings.TrimSpace(opts.Reason) == "" {
		return "requires a reason for access. Pass --reason"
	}

	return ""
}

func newResolvedAccount(account api.PAMAccessibleAccount, opts Options) ResolvedAccount {
	return ResolvedAccount{
		Path:             accountPath(account),
		AccountType:      account.AccountType,
		TypeLabel:        typeLabelFor(account.AccountType),
		Duration:         opts.Duration,
		Reason:           opts.Reason,
		RequiresApproval: account.RequiresApproval,
		AccessStatus:     account.AccessStatus,
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
//
// pageSize is what we ask for, never what we assume arrives. A server may return fewer than requested,
// and against one that caps pages lower the two obvious shortcuts both lose accounts without saying
// so: stepping the offset by the requested size skips whatever was not returned, and treating a short
// page as the final one stops at the first capped response. Either way an account the caller can reach
// goes quietly missing from the run, which is the worst way for this to fail.
//
// So the offset advances by what actually arrived, and the loop ends only on a page with nothing in it
// or on having collected everything the server said there was.
func listAllAccessibleAccounts(httpClient *resty.Client) ([]api.PAMAccessibleAccount, error) {
	const pageSize = 100

	// Purely a runaway guard, not a pagination assumption. A server that ignored the offset would
	// return the same page forever and every page would look like progress; TotalCount ends that in
	// practice, and this ends it even when the response carries no total, so a broken endpoint fails
	// instead of hanging before the agent has started.
	const maxPages = 1000

	var all []api.PAMAccessibleAccount
	offset := 0

	for pages := 0; ; pages++ {
		if pages >= maxPages {
			return nil, fmt.Errorf(
				"failed to list PAM accounts: gave up after %d pages, which means the endpoint is not paging", maxPages)
		}

		page, err := api.CallPAMListAccessibleAccounts(httpClient, offset, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to list PAM accounts: %w", err)
		}

		// An empty page is the end, whatever any total claims.
		if len(page.Accounts) == 0 {
			break
		}

		all = append(all, page.Accounts...)
		offset += len(page.Accounts)

		if page.TotalCount > 0 && len(all) >= page.TotalCount {
			break
		}
	}
	return all, nil
}
