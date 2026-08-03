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

// Account types that expose a local port and can therefore be proxied on demand.
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
	"windows-ad": "Windows AD RDP",
}

const accessStatusGranted = "granted"
const accessStatusPending = "pending"

// ResolvedAccount is a manifest entry joined with what the API says about it.
type ResolvedAccount struct {
	Entry       AccountEntry
	AccountType string
	TypeLabel   string
	Description string
	Duration    time.Duration
	Reason      string

	// canonicalPath is folderName/name exactly as Infisical spells it. Manifest paths are matched
	// case-insensitively, so this can differ from what the user wrote.
	canonicalPath string
}

// Path returns the account path as Infisical spells it. Sessions are created against this rather
// than the manifest's spelling, and it is what the agent is shown.
func (r ResolvedAccount) Path() string {
	return r.canonicalPath
}

// Preflight resolves every manifest account against the accounts the caller can actually reach and
// reports everything that would block a launch. It creates no sessions, so a manifest with a typo
// or a missing approval fails here, while we still own the terminal, rather than surfacing later
// as an unexplained dropped connection inside the agent.
func Preflight(httpClient *resty.Client, manifest *Manifest) ([]ResolvedAccount, error) {
	accounts, err := listAllAccessibleAccounts(httpClient)
	if err != nil {
		return nil, err
	}

	byPath := make(map[string]api.PAMAccessibleAccount, len(accounts))
	for _, account := range accounts {
		byPath[strings.ToLower(fmt.Sprintf("%s/%s", account.FolderName, account.Name))] = account
	}

	var resolved []ResolvedAccount
	var problems []string
	anyNotFound := false

	for _, entry := range manifest.Accounts {
		label := entry.Account
		key := strings.ToLower(strings.TrimPrefix(entry.Account, "/"))

		account, found := byPath[key]
		if !found {
			problems = append(problems, fmt.Sprintf("%s: not found, or you don't have access to it", label))
			anyNotFound = true
			continue
		}

		if account.DisabledReason != nil && *account.DisabledReason != "" {
			problems = append(problems, fmt.Sprintf("%s: account is disabled: %s", label, *account.DisabledReason))
			continue
		}

		typeLabel, portBased := portBasedAccountTypes[account.AccountType]
		if !portBased {
			problems = append(problems, fmt.Sprintf(
				"%s: %s accounts deliver credentials as files rather than over a port, so they can't be proxied here. Supported types: %s",
				label, account.AccountType, supportedTypeList()))
			continue
		}

		if !account.CanLaunch {
			problems = append(problems, fmt.Sprintf("%s: you don't have permission to launch sessions for this account", label))
			continue
		}

		if account.RequiresApproval && account.AccessStatus != accessStatusGranted {
			if account.AccessStatus == accessStatusPending {
				problems = append(problems, fmt.Sprintf("%s: your access request is still awaiting approval", label))
			} else {
				problems = append(problems, fmt.Sprintf("%s: requires approval. Request access with 'infisical pam access %s' or from the dashboard", label, label))
			}
			continue
		}

		reason := entry.EffectiveReason(manifest.Defaults)
		if account.RequireReason && strings.TrimSpace(reason) == "" {
			problems = append(problems, fmt.Sprintf("%s: requires a reason. Set 'reason:' on the account or under 'defaults:'", label))
			continue
		}

		resolved = append(resolved, ResolvedAccount{
			Entry:         entry,
			AccountType:   account.AccountType,
			TypeLabel:     typeLabel,
			Description:   account.Description,
			Duration:      entry.EffectiveDuration(manifest.Defaults),
			Reason:        reason,
			canonicalPath: fmt.Sprintf("%s/%s", account.FolderName, account.Name),
		})
	}

	if len(problems) > 0 {
		message := fmt.Sprintf("cannot start the following accounts:\n  - %s", strings.Join(problems, "\n  - "))
		// Listed once at the end rather than per account, so several bad paths don't repeat it.
		if anyNotFound {
			message += "\n\n" + availableAccounts(accounts)
		}
		return nil, errors.New(message)
	}
	return resolved, nil
}

// availableAccounts lists the paths the caller can actually use, so a wrong path in the manifest
// is fixable without going to the dashboard to look one up.
func availableAccounts(accounts []api.PAMAccessibleAccount) string {
	if len(accounts) == 0 {
		return "You don't have access to any PAM accounts."
	}

	paths := make([]string, 0, len(accounts))
	for _, account := range accounts {
		paths = append(paths, fmt.Sprintf("%s/%s", account.FolderName, account.Name))
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

func supportedTypeList() string {
	types := make([]string, 0, len(portBasedAccountTypes))
	for accountType := range portBasedAccountTypes {
		types = append(types, accountType)
	}
	sort.Strings(types)
	return strings.Join(types, ", ")
}
