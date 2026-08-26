package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"github.com/zalando/go-keyring"
)

type LoggedInUserDetails struct {
	IsUserLoggedIn bool
	LoginExpired   bool
	// ProfileName is the resolved profile whose session is loaded; it is also
	// the keyring key holding UserCredentials.
	ProfileName string
	// ProfileSource describes how the profile was selected (flag, env var,
	// directory scope, or the global default).
	ProfileSource   string
	Profile         models.Profile
	UserCredentials models.UserCredentials
	// OrganizationID/Name describe the organization this invocation is actually
	// scoped to, which is the profile's default unless --org/INFISICAL_ORG
	// selected another one. OrganizationSource says which of the two it was.
	OrganizationID     string
	OrganizationName   string
	OrganizationSource string
}

var ErrUserNotLoggedIn = errors.New("we couldn't find your logged in details, try running [infisical login] then try again")

// ErrProfileNotFound wraps errors caused by an explicitly selected profile
// (--profile flag, INFISICAL_PROFILE env var, or directory scope) that has no
// entry in the config file. Callers that create profiles (login) treat it as
// "not logged in yet" rather than a failure.
var ErrProfileNotFound = errors.New("profile not found")

// ErrOrgSwitchNeedsMFA is returned when scoping a session to another
// organization requires MFA, which cannot be completed non-interactively.
var ErrOrgSwitchNeedsMFA = errors.New("organization requires MFA")

// ErrProfileDomainMismatch is returned when an explicitly requested instance is
// not the one the resolved profile belongs to. Commands that create sessions
// (login) treat it as "no usable session yet" rather than a failure.
var ErrProfileDomainMismatch = errors.New("profile belongs to a different instance")

var domainMismatchNoticeOnce sync.Once

// StoreUserCredsInKeyRing stores the session credentials under the given
// keyring key. The key is the profile name; for profiles migrated from the
// pre-profile config that name is the account email, which matches the legacy
// keyring entries.
func StoreUserCredsInKeyRing(keyName string, userCred *models.UserCredentials) error {
	// Refresh tokens are deliberately never written to the vault. The CLI does
	// not renew sessions (see GetCurrentLoggedInUserDetails), so storing one
	// would only mean a stolen vault yields a long-lived rotating credential
	// instead of an access token that expires with JWT_AUTH_LIFETIME. Clearing
	// it here also purges tokens written by earlier versions on the next write.
	toStore := *userCred
	toStore.RefreshToken = ""

	userCredMarshalled, err := json.Marshal(&toStore)
	if err != nil {
		return fmt.Errorf("StoreUserCredsInKeyRing: something went wrong when marshalling user creds [err=%s]", err)
	}

	err = SetValueInKeyring(keyName, string(userCredMarshalled))
	if err != nil {
		return fmt.Errorf("StoreUserCredsInKeyRing: unable to store user credentials because [err=%s]", err)
	}

	return err
}

func GetUserCredsFromKeyRing(keyName string) (credentials models.UserCredentials, err error) {
	credentialsValue, err := GetValueInKeyring(keyName)
	if err != nil {
		if err == keyring.ErrUnsupportedPlatform {
			return models.UserCredentials{}, errors.New("your OS does not support keyring. Consider using a service token https://infisical.com/docs/documentation/platform/token")
		} else if err == keyring.ErrNotFound {
			return models.UserCredentials{}, errors.New("credentials not found in system keyring")
		} else {
			return models.UserCredentials{}, fmt.Errorf("something went wrong, failed to retrieve value from system keyring [error=%v]", err)
		}
	}

	var userCredentials models.UserCredentials

	err = json.Unmarshal([]byte(credentialsValue), &userCredentials)
	if err != nil {
		return models.UserCredentials{}, fmt.Errorf("getUserCredsFromKeyRing: Something went wrong when unmarshalling user creds [err=%s]", err)
	}

	return userCredentials, err
}

func GetCurrentLoggedInUserDetails(setConfigVariables bool) (LoggedInUserDetails, error) {
	if !ConfigFileExists() {
		return LoggedInUserDetails{}, nil
	}

	configFile, err := GetMigratedConfigFile()
	if err != nil {
		return LoggedInUserDetails{}, fmt.Errorf("getCurrentLoggedInUserDetails: unable to get logged in user from config file [err=%s]", err)
	}

	resolved := ResolveProfile(configFile)
	if resolved.Name == "" {
		return LoggedInUserDetails{}, nil
	}

	profile, profileFound := FindProfile(configFile, resolved.Name)
	if !profileFound {
		if resolved.Source != ProfileSourceDefault {
			return LoggedInUserDetails{}, fmt.Errorf("%w: profile '%s' (selected via %s) does not exist. Run [infisical profile list] to see available profiles, or [infisical login --profile %s] to create it", ErrProfileNotFound, resolved.Name, resolved.Source, resolved.Name)
		}
		// Unmigrated legacy state: treat the email as an implicit profile.
		profile = models.Profile{Name: resolved.Name, Email: resolved.Name, Domain: configFile.LoggedInUserDomain}
	}

	userCreds, err := GetUserCredsFromKeyRing(profile.Name)
	if err != nil {
		if strings.Contains(err.Error(), "credentials not found in system keyring") {
			return LoggedInUserDetails{}, ErrUserNotLoggedIn
		} else {
			return LoggedInUserDetails{}, fmt.Errorf("failed to fetch credentials from keyring because [err=%s]", err)
		}
	}

	if setConfigVariables {
		config.INFISICAL_URL_MANUAL_OVERRIDE = config.INFISICAL_URL
		if profile.Domain != "" {
			profileURL := AppendAPIEndpoint(profile.Domain)
			if config.INFISICAL_DOMAIN_EXPLICITLY_SET {
				// An explicit domain is honored, but this profile's session was
				// issued by a different instance and must not be sent there: it
				// would hand a valid bearer token to whoever runs that host.
				if profileURL != config.INFISICAL_URL {
					return LoggedInUserDetails{}, fmt.Errorf("%w: profile '%s' belongs to %s, but %s was requested. Its session is not valid there and will not be sent. Log in to that instance with [infisical login --domain %s --profile <name>], or select a profile that uses it with --profile",
						ErrProfileDomainMismatch, profile.Name, DisplayDomain(profileURL), DisplayDomain(config.INFISICAL_URL), DisplayDomain(config.INFISICAL_URL))
				}
			} else {
				config.INFISICAL_URL = profileURL
			}
		}
	}

	// Sessions are intentionally not renewed with the refresh token, so a
	// session lives at most JWT_AUTH_LIFETIME and expiry sends the user back
	// through login. Renewing correctly would require handling the server's
	// refresh-token rotation (it invalidates the previous token outside a
	// 10-second grace window and treats later reuse as theft by revoking the
	// session), which a CLI cannot do safely while several processes share one
	// vault entry. The bounded lifetime also keeps forgotten sessions from
	// living on indefinitely.
	isAuthenticated := !IsJWTExpired(userCreds.JTWToken)

	details := LoggedInUserDetails{
		IsUserLoggedIn:     true, // was logged in
		LoginExpired:       !isAuthenticated,
		ProfileName:        profile.Name,
		ProfileSource:      resolved.Source,
		Profile:            profile,
		UserCredentials:    userCreds,
		OrganizationID:     profile.OrganizationID,
		OrganizationName:   profile.OrganizationName,
		OrganizationSource: OrgSourceProfileDefault,
	}

	// The organization is a field of the profile, so --org/INFISICAL_ORG can
	// retarget this one invocation without touching the profile's default. Only
	// on setConfigVariables paths: read-only probes must not make network calls
	// or write to the keyring.
	if selector, selectorSource := GetOrgOverride(); selector != "" && setConfigVariables && isAuthenticated {
		if err := applyOrgOverride(&details, selector, selectorSource); err != nil {
			return LoggedInUserDetails{}, err
		}
	}

	return details, nil
}

// applyOrgOverride retargets the session to the organization named by the
// --org/INFISICAL_ORG selector, minting and caching a token for it when needed.
func applyOrgOverride(details *LoggedInUserDetails, selector string, selectorSource string) error {
	profile := details.Profile

	// Already on the requested organization: nothing to do, and no API calls.
	// Only an id match is trusted here, since a name or slug could belong to a
	// different organization and would skip the exchange wrongly.
	if OrgMatchTier(selector, profile.OrganizationID, "", "") == orgMatchID {
		details.OrganizationSource = selectorSource
		return nil
	}

	// A previously minted token for this organization avoids both the lookup
	// and the exchange. Pick the strongest match rather than the first, so a
	// cached entry matching only by name cannot shadow one matching by id.
	bestCached := models.CachedOrgSession{}
	bestTier := 0
	for _, cached := range details.UserCredentials.OrgTokens {
		tier := OrgMatchTier(selector, cached.OrgID, cached.OrgSlug, cached.OrgName)
		if tier > bestTier && !IsJWTExpired(cached.Token) {
			bestCached, bestTier = cached, tier
		}
	}
	if bestTier != 0 {
		details.UserCredentials.JTWToken = bestCached.Token
		details.OrganizationID = bestCached.OrgID
		details.OrganizationName = bestCached.OrgName
		details.OrganizationSource = selectorSource
		return nil
	}

	resolvedOrg, err := ResolveOrgSelector(details.UserCredentials.JTWToken, selector)
	if err != nil {
		return err
	}

	if resolvedOrg.ID == profile.OrganizationID {
		details.OrganizationName = resolvedOrg.Name
		details.OrganizationSource = selectorSource
		return nil
	}

	orgToken, err := ExchangeSessionForOrganization(details.UserCredentials.JTWToken, resolvedOrg.ID)
	if err != nil {
		if errors.Is(err, ErrOrgSwitchNeedsMFA) {
			return fmt.Errorf("organization '%s' requires MFA, which cannot be completed with %s. Run [infisical profile set-org %s --profile %s] once to verify and cache the session", resolvedOrg.Name, selectorSource, selector, profile.Name)
		}
		return fmt.Errorf("unable to scope your session to organization '%s' [err=%s]", resolvedOrg.Name, err)
	}

	if details.UserCredentials.OrgTokens == nil {
		details.UserCredentials.OrgTokens = map[string]models.CachedOrgSession{}
	}
	details.UserCredentials.OrgTokens[resolvedOrg.ID] = models.CachedOrgSession{
		Token:   orgToken,
		OrgID:   resolvedOrg.ID,
		OrgName: resolvedOrg.Name,
		OrgSlug: resolvedOrg.Slug,
	}

	// Persist the new cache entry while leaving the profile's own session token
	// alone: --org retargets a single command, so writing the organization
	// token as the profile's primary one would silently repoint the profile.
	if err := StoreUserCredsInKeyRing(profile.Name, &details.UserCredentials); err != nil {
		// The in-memory token is still usable; caching it is best effort.
		log.Debug().Err(err).Msg("unable to cache organization-scoped session token")
	}

	// Only this invocation runs against the organization-scoped token.
	details.UserCredentials.JTWToken = orgToken

	details.OrganizationID = resolvedOrg.ID
	details.OrganizationName = resolvedOrg.Name
	details.OrganizationSource = selectorSource
	return nil
}

// ExchangeSessionForOrganization trades a valid session token for one scoped to
// the given organization. Returns ErrOrgSwitchNeedsMFA when the organization
// requires MFA, which callers must handle interactively.
func ExchangeSessionForOrganization(sessionToken string, orgID string) (string, error) {
	httpClient, err := GetRestyClientWithCustomHeaders()
	if err != nil {
		return "", err
	}
	httpClient.SetAuthToken(sessionToken)

	selectOrgRes, err := api.CallSelectOrganization(httpClient, api.SelectOrganizationRequest{OrganizationId: orgID})
	if err != nil {
		return "", err
	}
	if selectOrgRes.MfaEnabled {
		return "", ErrOrgSwitchNeedsMFA
	}
	if selectOrgRes.Token == "" {
		return "", errors.New("the server returned an empty session token")
	}

	return selectOrgRes.Token, nil
}

func IsJWTExpired(token string) bool {
	parser := jwt.NewParser()
	claims := &jwt.RegisteredClaims{}
	_, _, err := parser.ParseUnverified(token, claims)
	if err != nil {
		return true
	}
	if claims.ExpiresAt == nil {
		return true
	}
	// 30-second buffer to avoid race between local check and subsequent API call
	return claims.ExpiresAt.Before(time.Now().Add(30 * time.Second))
}
