package util

import (
	"errors"
	"fmt"
	"os"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/rs/zerolog/log"
	"github.com/zalando/go-keyring"
)

// LogoutResult reports what happened to one profile during a logout.
type LogoutResult struct {
	ProfileName string
	// HadSession is false when the profile had no stored credentials, e.g.
	// because it was already logged out.
	HadSession bool
	// Revoked is true when at least one server-side session was revoked.
	Revoked bool
	// SharedWith names a profile that still uses the same server session, in
	// which case the session is left alone and only local credentials are
	// removed.
	SharedWith string
	// RevokeErr is set when revocation was attempted and failed. Local
	// credentials are still removed in that case.
	RevokeErr error
	// LocalErr is set when the stored credentials could not be removed.
	LocalErr error
}

// profileTokens loads every session token stored for a profile: its own and
// the cached organization-scoped ones listed in its index. ok is false when the
// profile has no stored session at all.
func profileTokens(profile models.Profile) (tokens []string, ok bool) {
	creds, err := GetUserCredsFromKeyRing(profile.Name)
	if err != nil {
		return nil, false
	}
	if creds.JTWToken != "" {
		tokens = append(tokens, creds.JTWToken)
	}
	for _, ref := range profile.OrgSessions {
		if token, found := GetOrgSessionToken(profile.Name, ref.OrgID); found {
			tokens = append(tokens, token)
		}
	}
	return tokens, true
}

// collectSessionIDs returns every distinct server-side session id represented
// by the given tokens.
func collectSessionIDs(tokens []string) []string {
	seen := map[string]bool{}
	ids := []string{}
	for _, token := range tokens {
		if id := ParseTokenSessionID(token); id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

// liveToken returns the first token that is still valid. Tokens are ordered
// with the profile's own first; an organization token cached later can outlive
// it, and revocation needs some live token to authenticate with.
func liveToken(tokens []string) string {
	for _, token := range tokens {
		if token != "" && !IsJWTExpired(token) {
			return token
		}
	}
	return ""
}

// IsKeyringEntryAbsent reports whether a keyring delete or read failed only
// because the entry does not exist. The system keyrings report
// keyring.ErrNotFound; the encrypted file backend surfaces the missing file.
func IsKeyringEntryAbsent(err error) bool {
	return errors.Is(err, keyring.ErrNotFound) || errors.Is(err, os.ErrNotExist)
}

// ClearStoredSession removes a profile's stored credentials, including its
// cached organization sessions. Entries that are already absent count as
// success, since the goal is that nothing remains.
func ClearStoredSession(profile models.Profile) error {
	var firstErr error
	if err := DeleteValueInKeyring(profile.Name); err != nil && !IsKeyringEntryAbsent(err) {
		firstErr = err
	}
	for _, ref := range profile.OrgSessions {
		if err := DeleteOrgSessionToken(profile.Name, ref.OrgID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// RevokeSession ends a server-side session by id, authenticating with a token
// that belongs to the account owning it.
func RevokeSession(sessionToken string, sessionID string) error {
	httpClient, err := GetRestyClientWithCustomHeaders()
	if err != nil {
		return err
	}
	httpClient.SetAuthToken(sessionToken)

	return api.CallRevokeUserSession(httpClient, sessionID)
}

// LogoutProfiles revokes the server-side sessions belonging to targetNames and
// removes their stored credentials.
//
// The server keys sessions by user, IP, and user agent, so several profiles for
// the same account on one machine share a single session. A session still used
// by a profile that is not being logged out is therefore left intact, and only
// the local credentials are removed; otherwise logging out of one tenant would
// silently sign the user out of the others.
func LogoutProfiles(configFile models.ConfigFile, targetNames []string, localOnly bool) []LogoutResult {
	targets := map[string]bool{}
	for _, name := range targetNames {
		targets[name] = true
	}

	// Session ids that must survive because a profile we are keeping uses them.
	retained := map[string]string{}
	for _, profile := range configFile.Profiles {
		if targets[profile.Name] {
			continue
		}
		tokens, ok := profileTokens(profile)
		if !ok {
			continue
		}
		for _, id := range collectSessionIDs(tokens) {
			retained[id] = profile.Name
		}
	}

	results := make([]LogoutResult, 0, len(targetNames))
	for _, name := range targetNames {
		result := LogoutResult{ProfileName: name}

		profile, found := FindProfile(configFile, name)
		if !found {
			profile = models.Profile{Name: name}
		}

		tokens, ok := profileTokens(profile)
		if !ok {
			results = append(results, result)
			continue
		}
		result.HadSession = true

		if !localOnly {
			// Any unexpired token authenticates revocation. Checking only the
			// profile's own token would skip revocation while a cached
			// organization token was still usable, leaving it live on the
			// server after the local copy was deleted.
			authToken := liveToken(tokens)
			for _, sessionID := range collectSessionIDs(tokens) {
				if owner, shared := retained[sessionID]; shared {
					result.SharedWith = owner
					continue
				}
				if authToken == "" {
					result.RevokeErr = fmt.Errorf("every stored session has expired, so none could be revoked")
					continue
				}
				if err := RevokeSession(authToken, sessionID); err != nil {
					result.RevokeErr = err
					log.Debug().Err(err).Str("profile", name).Msg("unable to revoke session")
					continue
				}
				result.Revoked = true
			}
		}

		if err := ClearStoredSession(profile); err != nil {
			result.LocalErr = err
			log.Debug().Err(err).Str("profile", name).Msg("unable to remove stored credentials")
		}

		results = append(results, result)
	}

	return results
}

// SessionStatus describes whether a profile currently holds usable credentials.
func SessionStatus(profile models.Profile) string {
	creds, err := GetUserCredsFromKeyRing(profile.Name)
	if err != nil {
		return "none"
	}
	if IsJWTExpired(creds.JTWToken) {
		return "expired"
	}
	if cached := len(profile.OrgSessions); cached > 0 {
		return fmt.Sprintf("active (+%d org)", cached)
	}
	return "active"
}

// LogoutProfilesAcrossDomains logs out profiles that may live on different
// Infisical instances, pointing each revocation at the instance that issued the
// session. The process-wide domain is restored afterwards.
func LogoutProfilesAcrossDomains(configFile models.ConfigFile, targetNames []string, localOnly bool) []LogoutResult {
	originalURL := config.INFISICAL_URL
	defer func() { config.INFISICAL_URL = originalURL }()

	byDomain := map[string][]string{}
	for _, name := range targetNames {
		domain := originalURL
		if profile, found := FindProfile(configFile, name); found && profile.Domain != "" {
			domain = AppendAPIEndpoint(profile.Domain)
		}
		byDomain[domain] = append(byDomain[domain], name)
	}

	// Preserve the caller's ordering in the combined result.
	resultsByName := map[string]LogoutResult{}
	for domain, names := range byDomain {
		config.INFISICAL_URL = domain
		for _, result := range LogoutProfiles(configFile, names, localOnly) {
			resultsByName[result.ProfileName] = result
		}
	}

	results := make([]LogoutResult, 0, len(targetNames))
	for _, name := range targetNames {
		if result, ok := resultsByName[name]; ok {
			results = append(results, result)
		}
	}
	return results
}
