package pam

import (
	"fmt"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
)

const (
	AccessStatusNone    = "none"
	AccessStatusPending = "pending"
	AccessStatusGranted = "granted"
)

// AccountPath is folder/name exactly as Infisical spells it, the form `pam access` takes.
func AccountPath(account api.PAMAccessibleAccount) string {
	if account.FolderName == "" {
		return account.Name
	}
	return account.FolderName + "/" + account.Name
}

// ListAccessibleAccounts pages through every account the caller can see whose name contains
// search (all of them when it's empty). It creates no sessions.
func ListAccessibleAccounts(httpClient *resty.Client, search string) ([]api.PAMAccessibleAccount, error) {
	const pageSize = 100
	// A server that ignored the offset would return the same page forever.
	const maxPages = 1000

	var all []api.PAMAccessibleAccount
	offset := 0

	for pages := 0; ; pages++ {
		if pages >= maxPages {
			return nil, fmt.Errorf("stopped after %d PAM accounts, which is too many to list. Look up one account instead: infisical pam accounts get <folder/account>", len(all))
		}

		page, err := api.CallPAMListAccessibleAccounts(httpClient, offset, pageSize, search)
		if err != nil {
			return nil, err
		}
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

// FindAccessibleAccount matches a path case-insensitively, with or without a leading slash.
func FilterAccountsByFolder(accounts []api.PAMAccessibleAccount, folder string) []api.PAMAccessibleAccount {
	var matched []api.PAMAccessibleAccount
	for _, account := range accounts {
		if account.FolderName != "" && strings.EqualFold(account.FolderName, folder) {
			matched = append(matched, account)
		}
	}
	return matched
}

// LookupAccessibleAccount finds one account by path without listing every account.
func LookupAccessibleAccount(httpClient *resty.Client, path string) (api.PAMAccessibleAccount, bool, error) {
	key := strings.Trim(strings.TrimSpace(path), "/")
	name := key[strings.LastIndex(key, "/")+1:]
	if name == "" {
		return api.PAMAccessibleAccount{}, false, nil
	}
	candidates, err := ListAccessibleAccounts(httpClient, name)
	if err != nil {
		return api.PAMAccessibleAccount{}, false, err
	}
	account, found := FindAccessibleAccount(candidates, key)
	return account, found, nil
}

func FindAccessibleAccount(accounts []api.PAMAccessibleAccount, path string) (api.PAMAccessibleAccount, bool) {
	key := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(path), "/"))
	for _, account := range accounts {
		if strings.ToLower(AccountPath(account)) == key {
			return account, true
		}
	}
	return api.PAMAccessibleAccount{}, false
}
