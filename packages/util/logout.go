package util

import (
	"errors"
	"fmt"

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

// collectSessionIDs returns every distinct server-side session id represented
// by a profile's stored credentials, including organization-scoped tokens.
func collectSessionIDs(creds models.UserCredentials) []string {
	seen := map[string]bool{}
	ids := []string{}

	add := func(token string) {
		if id := ParseTokenSessionID(token); id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}

	add(creds.JTWToken)
	for _, cached := range creds.OrgTokens {
		add(cached.Token)
	}

	return ids
}

// liveToken returns a session token that is still valid, preferring the
// profile's own. An organization token cached later can outlive it, and
// revocation needs some live token to authenticate with.
func liveToken(creds models.UserCredentials) string {
	if creds.JTWToken != "" && !IsJWTExpired(creds.JTWToken) {
		return creds.JTWToken
	}
	for _, cached := range creds.OrgTokens {
		if cached.Token != "" && !IsJWTExpired(cached.Token) {
			return cached.Token
		}
	}
	return ""
}

// ClearStoredSession removes a profile's stored credentials. An entry that is
// already absent counts as success, since the goal is that nothing remains.
func ClearStoredSession(profileName string) error {
	err := DeleteValueInKeyring(profileName)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
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
		creds, err := GetUserCredsFromKeyRing(profile.Name)
		if err != nil {
			continue
		}
		for _, id := range collectSessionIDs(creds) {
			retained[id] = profile.Name
		}
	}

	results := make([]LogoutResult, 0, len(targetNames))
	for _, name := range targetNames {
		result := LogoutResult{ProfileName: name}

		creds, err := GetUserCredsFromKeyRing(name)
		if err != nil {
			results = append(results, result)
			continue
		}
		result.HadSession = true

		if !localOnly {
			// Any unexpired token authenticates revocation. Checking only the
			// profile's own token would skip revocation while a cached
			// organization token was still usable, leaving it live on the
			// server after the local copy was deleted.
			authToken := liveToken(creds)
			for _, sessionID := range collectSessionIDs(creds) {
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

		if err := DeleteValueInKeyring(name); err != nil {
			result.LocalErr = err
			log.Debug().Err(err).Str("profile", name).Msg("unable to remove stored credentials")
		}

		results = append(results, result)
	}

	return results
}

// SessionStatus describes whether a profile currently holds usable credentials.
func SessionStatus(profileName string) string {
	creds, err := GetUserCredsFromKeyRing(profileName)
	if err != nil {
		return "none"
	}
	if IsJWTExpired(creds.JTWToken) {
		return "expired"
	}
	if len(creds.OrgTokens) > 0 {
		return fmt.Sprintf("active (+%d org)", len(creds.OrgTokens))
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
