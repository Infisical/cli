package util

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

// Human-readable labels for where the active profile selection came from.
const (
	ProfileSourceFlag      = "--profile flag"
	ProfileSourceEnv       = INFISICAL_PROFILE_ENV_NAME + " environment variable"
	ProfileSourceDirectory = "directory scope"
	ProfileSourceDefault   = "default profile"
)

// Human-readable labels for where the organization selection came from.
const (
	OrgSourceFlag           = "--org flag"
	OrgSourceEnv            = INFISICAL_ORG_ENV_NAME + " environment variable"
	OrgSourceProfileDefault = "profile default"
)

// Profile names double as keyring keys, so keep them to the character set
// already proven safe there (emails, including plus-addressed ones, are the
// historical keys). Applies only to user-typed names; derived names (raw
// emails) are stored as-is.
var profileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._+-]*$`)

// ResolvedProfile describes which profile an invocation resolved to and why.
type ResolvedProfile struct {
	Name   string
	Source string
	// ScopeDir is the directory whose binding selected the profile. Only set
	// when Source is ProfileSourceDirectory.
	ScopeDir string
	// ShadowedName and ShadowedScopeDir record a directory binding that an
	// explicit override took precedence over. Commands report it so that a
	// binding quietly not applying is explained rather than surprising.
	ShadowedName     string
	ShadowedScopeDir string
}

func ValidateProfileName(name string) error {
	if !profileNamePattern.MatchString(name) {
		return fmt.Errorf("invalid profile name '%s': use letters, digits, and the characters @ . _ + - (must start with a letter or digit)", name)
	}
	return nil
}

// MigrateConfigProfiles synthesizes profile entries from the legacy
// LoggedInUserEmail/LoggedInUsers fields. Migrated profiles are named after
// the account email, which is also the legacy keyring key, so existing keyring
// entries keep working without being rewritten. Safe to call repeatedly.
// Returns true when the config was modified.
func MigrateConfigProfiles(configFile *models.ConfigFile) bool {
	changed := false

	// A roster/LoggedInUserEmail entry only represents a legacy session when no
	// profile covers that account yet. Entries whose account already has a
	// profile (under any name) are compat mirrors written by profile-aware CLI
	// versions, and synthesizing a profile from them would create a phantom
	// with no keyring session behind it.
	anyProfileForEmail := func(email string) bool {
		for _, profile := range configFile.Profiles {
			if profile.Email == email {
				return true
			}
		}
		return false
	}

	for _, user := range configFile.LoggedInUsers {
		if user.Email == "" || anyProfileForEmail(user.Email) {
			continue
		}
		configFile.Profiles = append(configFile.Profiles, models.Profile{
			Name:   user.Email,
			Email:  user.Email,
			Domain: user.Domain,
		})
		changed = true
	}

	if configFile.LoggedInUserEmail != "" && !anyProfileForEmail(configFile.LoggedInUserEmail) {
		configFile.Profiles = append(configFile.Profiles, models.Profile{
			Name:   configFile.LoggedInUserEmail,
			Email:  configFile.LoggedInUserEmail,
			Domain: configFile.LoggedInUserDomain,
		})
		changed = true
	}

	// Reconcile the active pointer. When an older CLI version switched users it
	// only moved LoggedInUserEmail, so a divergence between the two fields means
	// the legacy pointer is the fresher one. Prefer the profile named after the
	// email (the migrated default); otherwise any profile for that account.
	if configFile.LoggedInUserEmail != "" {
		activeIdx := findProfileIndex(configFile.Profiles, configFile.ActiveProfile)
		if activeIdx < 0 || configFile.Profiles[activeIdx].Email != configFile.LoggedInUserEmail {
			targetIdx := findProfileIndex(configFile.Profiles, configFile.LoggedInUserEmail)
			if targetIdx < 0 {
				for idx, profile := range configFile.Profiles {
					if profile.Email == configFile.LoggedInUserEmail {
						targetIdx = idx
						break
					}
				}
			}
			if targetIdx >= 0 && configFile.ActiveProfile != configFile.Profiles[targetIdx].Name {
				configFile.ActiveProfile = configFile.Profiles[targetIdx].Name
				changed = true
			}
		}
	}

	return changed
}

// GetMigratedConfigFile loads the config file and migrates legacy login state
// into profiles, persisting the migration once so later reads are stable.
func GetMigratedConfigFile() (models.ConfigFile, error) {
	configFile, err := GetConfigFile()
	if err != nil {
		return models.ConfigFile{}, err
	}

	if MigrateConfigProfiles(&configFile) && ConfigFileExists() {
		if err := WriteConfigFile(&configFile); err != nil {
			// The in-memory migration is still usable; persisting is best effort.
			log.Debug().Err(err).Msg("unable to persist profile migration")
		}
	}

	return configFile, nil
}

// GetProfileOverride returns the per-invocation profile selection (--profile
// flag or INFISICAL_PROFILE env var) and a label describing where it came from.
func GetProfileOverride() (name string, source string) {
	return config.INFISICAL_PROFILE_OVERRIDE, config.INFISICAL_PROFILE_OVERRIDE_SOURCE
}

// GetOrgOverride returns the per-invocation organization selection (--org flag
// or INFISICAL_ORG env var) and a label describing where it came from. The
// value may be an organization ID, slug, or name; it is resolved against the
// account's organizations only when it is actually needed.
func GetOrgOverride() (selector string, source string) {
	return config.INFISICAL_ORG_OVERRIDE, config.INFISICAL_ORG_OVERRIDE_SOURCE
}

// ActiveAccountEmail returns the email of the profile a command would use, for
// callers that need the account rather than the session. It prefers profile
// state over the legacy pointer, which is only published for email-named
// profiles.
func ActiveAccountEmail(configFile models.ConfigFile) string {
	if resolved := ResolveProfile(configFile); resolved.Name != "" {
		if profile, found := FindProfile(configFile, resolved.Name); found && profile.Email != "" {
			return profile.Email
		}
	}
	return configFile.LoggedInUserEmail
}

// ShellQuote renders a value safe to embed in a shell statement, using POSIX
// single-quote escaping. Profile names can be derived from an email supplied by
// the server, and pin prints them into output meant for eval, so an unescaped
// name would let a malicious response run commands.
func ShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// SanitizeDisplay strips control characters from values that came from the
// server before they reach a terminal. Organization and profile names are
// echoed on ordinary commands, and escape sequences there could forge output or
// drive terminal features.
func SanitizeDisplay(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, value)
}

// SuspendOrgOverride temporarily clears the --org/INFISICAL_ORG selection and
// returns a function that restores it. Commands that perform their own
// organization exchange use this so that session resolution does not try to
// apply the override first, which cannot prompt and therefore fails outright
// for organizations that require MFA.
func SuspendOrgOverride() func() {
	selector, source := config.INFISICAL_ORG_OVERRIDE, config.INFISICAL_ORG_OVERRIDE_SOURCE
	config.INFISICAL_ORG_OVERRIDE, config.INFISICAL_ORG_OVERRIDE_SOURCE = "", ""
	return func() {
		config.INFISICAL_ORG_OVERRIDE, config.INFISICAL_ORG_OVERRIDE_SOURCE = selector, source
	}
}

// Match tiers for an --org/INFISICAL_ORG selector, most specific first. An id
// is unique and server-assigned, a slug is unique per instance, and a name is
// neither, so they must not be treated as interchangeable: an organization the
// user also belongs to could otherwise be named after another one's id or slug
// and be selected in its place.
const (
	orgMatchNone = 0
	orgMatchName = 1
	orgMatchSlug = 2
	orgMatchID   = 3
)

// OrgMatchTier reports how strongly a selector matches an organization, using
// the tiers above. Slug and name comparisons are case-insensitive so
// `--org globex` matches an organization named "Globex".
func OrgMatchTier(selector, id, slug, name string) int {
	if selector == "" {
		return orgMatchNone
	}
	if id != "" && strings.EqualFold(selector, id) {
		return orgMatchID
	}
	if slug != "" && strings.EqualFold(selector, slug) {
		return orgMatchSlug
	}
	if name != "" && strings.EqualFold(selector, name) {
		return orgMatchName
	}
	return orgMatchNone
}

// OrgMatchesSelector reports whether an organization matches a selector at all.
// Callers choosing between several candidates must compare tiers with
// OrgMatchTier instead, so that a weaker match cannot shadow a stronger one.
func OrgMatchesSelector(selector, id, slug, name string) bool {
	return OrgMatchTier(selector, id, slug, name) != orgMatchNone
}

// ResolvedOrg is an organization selector resolved against the account.
type ResolvedOrg struct {
	ID   string
	Name string
	Slug string
	// matchName is the bare name to match selectors against. Sub-organizations
	// display as "Parent / Child" but should still match on their own name.
	matchName string
}

// ResolveOrgSelector turns an --org/INFISICAL_ORG selector (ID, slug, or name)
// into a concrete organization, searching both root organizations and
// sub-organizations. The sessionToken is only used to list organizations.
func ResolveOrgSelector(sessionToken string, selector string) (ResolvedOrg, error) {
	if selector == "" {
		return ResolvedOrg{}, errors.New("no organization specified")
	}

	httpClient, err := GetRestyClientWithCustomHeaders()
	if err != nil {
		return ResolvedOrg{}, err
	}
	httpClient.SetAuthToken(sessionToken)

	// Collect every organization first, then pick the strongest match across
	// all of them, so that ordering cannot decide the outcome.
	candidates := []ResolvedOrg{}
	if subOrgsResp, err := api.CallGetAllOrganizationsWithSubOrgs(httpClient); err == nil {
		for _, org := range subOrgsResp.Organizations {
			candidates = append(candidates, ResolvedOrg{ID: org.ID, Name: org.Name, Slug: org.Slug})
			for _, sub := range org.SubOrganizations {
				candidates = append(candidates, ResolvedOrg{ID: sub.ID, Name: fmt.Sprintf("%s / %s", org.Name, sub.Name), Slug: sub.Slug, matchName: sub.Name})
			}
		}
	}
	if len(candidates) == 0 {
		// Older instances may not expose the sub-org endpoint.
		if orgResp, err := api.CallGetAllOrganizations(httpClient); err == nil {
			for _, org := range orgResp.Organizations {
				candidates = append(candidates, ResolvedOrg{ID: org.ID, Name: org.Name})
			}
		}
	}

	best := ResolvedOrg{}
	bestTier := orgMatchNone
	ambiguous := false
	for _, candidate := range candidates {
		matchable := candidate.matchName
		if matchable == "" {
			matchable = candidate.Name
		}
		tier := OrgMatchTier(selector, candidate.ID, candidate.Slug, matchable)
		switch {
		case tier > bestTier:
			best, bestTier, ambiguous = candidate, tier, false
		case tier == bestTier && tier != orgMatchNone && candidate.ID != best.ID:
			ambiguous = true
		}
	}

	if bestTier == orgMatchNone {
		return ResolvedOrg{}, fmt.Errorf("organization '%s' not found for this account. Run [infisical org list] to see available organizations", selector)
	}
	if ambiguous {
		return ResolvedOrg{}, fmt.Errorf("organization '%s' is ambiguous: several organizations match it. Use the organization id instead, which [infisical org list] shows", selector)
	}

	return best, nil
}

// ResolveProfile determines which profile this invocation should use:
// --profile flag > INFISICAL_PROFILE env var > directory scope > global default.
func ResolveProfile(configFile models.ConfigFile) ResolvedProfile {
	override, overrideSource := GetProfileOverride()
	cwd, err := os.Getwd()
	if err != nil {
		cwd = ""
	}
	return resolveProfileWith(configFile, override, overrideSource, cwd)
}

func resolveProfileWith(configFile models.ConfigFile, override string, overrideSource string, cwd string) ResolvedProfile {
	if override != "" {
		if overrideSource == "" {
			overrideSource = ProfileSourceFlag
		}
		resolved := ResolvedProfile{Name: override, Source: overrideSource}
		// A binding for this directory still exists, it just lost. Remember it
		// so the user is told why it did not apply.
		if cwd != "" {
			if name, scopeDir, ok := lookupDirectoryProfile(configFile, cwd); ok && name != override {
				resolved.ShadowedName = name
				resolved.ShadowedScopeDir = scopeDir
			}
		}
		return resolved
	}

	if cwd != "" {
		if name, scopeDir, ok := lookupDirectoryProfile(configFile, cwd); ok {
			return ResolvedProfile{Name: name, Source: ProfileSourceDirectory, ScopeDir: scopeDir}
		}
	}

	if configFile.ActiveProfile != "" {
		return ResolvedProfile{Name: configFile.ActiveProfile, Source: ProfileSourceDefault}
	}

	// Config written by an older CLI that was never migrated (e.g. read-only
	// config directory): fall back to the legacy field, which is also the
	// profile name migration would have chosen.
	if configFile.LoggedInUserEmail != "" {
		return ResolvedProfile{Name: configFile.LoggedInUserEmail, Source: ProfileSourceDefault}
	}

	return ResolvedProfile{}
}

// lookupDirectoryProfile finds the directory binding governing cwd by walking
// from cwd up to the filesystem root; the nearest bound ancestor wins.
func lookupDirectoryProfile(configFile models.ConfigFile, cwd string) (name string, scopeDir string, found bool) {
	if len(configFile.DirectoryProfiles) == 0 {
		return "", "", false
	}

	dir := filepath.Clean(cwd)
	for {
		if profileName, ok := configFile.DirectoryProfiles[dir]; ok && profileName != "" {
			return profileName, dir, true
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", false
		}
		dir = parent
	}
}

// FindGoverningDirectoryProfile returns the binding that would apply to the
// given directory, if any.
func FindGoverningDirectoryProfile(configFile models.ConfigFile, dir string) (name string, scopeDir string, found bool) {
	return lookupDirectoryProfile(configFile, dir)
}

// SetDirectoryProfile binds a directory (and its subtree) to a profile name.
func SetDirectoryProfile(configFile *models.ConfigFile, dir string, name string) {
	if configFile.DirectoryProfiles == nil {
		configFile.DirectoryProfiles = map[string]string{}
	}
	configFile.DirectoryProfiles[filepath.Clean(dir)] = name
}

// RemoveDirectoryProfile removes an exact directory binding. Returns whether
// a binding existed.
func RemoveDirectoryProfile(configFile *models.ConfigFile, dir string) bool {
	cleaned := filepath.Clean(dir)
	if _, ok := configFile.DirectoryProfiles[cleaned]; !ok {
		return false
	}
	delete(configFile.DirectoryProfiles, cleaned)
	return true
}

func findProfileIndex(profiles []models.Profile, name string) int {
	if name == "" {
		return -1
	}
	for idx, profile := range profiles {
		if profile.Name == name {
			return idx
		}
	}
	return -1
}

func FindProfile(configFile models.ConfigFile, name string) (models.Profile, bool) {
	if idx := findProfileIndex(configFile.Profiles, name); idx >= 0 {
		return configFile.Profiles[idx], true
	}
	return models.Profile{}, false
}

// UpsertProfile inserts the profile or replaces the existing one with the same name.
func UpsertProfile(configFile *models.ConfigFile, profile models.Profile) {
	if idx := findProfileIndex(configFile.Profiles, profile.Name); idx >= 0 {
		configFile.Profiles[idx] = profile
		return
	}
	configFile.Profiles = append(configFile.Profiles, profile)
}

// SetActiveProfile marks the profile as the global default and keeps the
// legacy single-user fields in sync so older CLI versions and scripts that
// read them keep working.
func SetActiveProfile(configFile *models.ConfigFile, name string) error {
	profile, found := FindProfile(*configFile, name)
	if !found {
		return fmt.Errorf("profile '%s' does not exist", name)
	}

	configFile.ActiveProfile = name
	syncLegacyLoginFields(configFile, profile)
	return nil
}

func syncLegacyLoginFields(configFile *models.ConfigFile, profile models.Profile) {
	// Older CLI versions load the keyring entry named by LoggedInUserEmail. That
	// is only this profile's own entry when the profile is named after the
	// email; otherwise an old binary would read some other profile's token while
	// pointed at this profile's instance. Leave the legacy pointer empty in that
	// case so an old binary asks for a fresh login instead.
	if profile.Name != profile.Email {
		configFile.LoggedInUserEmail = ""
		configFile.LoggedInUserDomain = ""
		return
	}

	configFile.LoggedInUserEmail = profile.Email
	configFile.LoggedInUserDomain = profile.Domain

	if profile.Email == "" {
		return
	}

	loggedInUser := models.LoggedInUser{Email: profile.Email, Domain: profile.Domain}
	if !ConfigContainsEmail(configFile.LoggedInUsers, profile.Email) {
		configFile.LoggedInUsers = append(configFile.LoggedInUsers, loggedInUser)
		return
	}
	for idx, user := range configFile.LoggedInUsers {
		if user.Email == profile.Email {
			configFile.LoggedInUsers[idx] = loggedInUser
		}
	}
}

// RepointProfileDomain moves exactly one profile to another instance. Only the
// named profile changes, even when other profiles share its email and current
// instance, because each profile holds its own session and a session issued by
// the previous instance must not follow any of them to the new one.
//
// The organization recorded on the profile described the previous instance, so
// it is cleared. The legacy roster entry is updated only when no remaining
// profile still uses the old instance. Returns false when the profile does not
// exist or already uses that instance; the caller clears the stored session.
func RepointProfileDomain(configFile *models.ConfigFile, profileName string, newDomain string) bool {
	idx := findProfileIndex(configFile.Profiles, profileName)
	if idx < 0 {
		return false
	}

	previousDomain := configFile.Profiles[idx].Domain
	if AppendAPIEndpoint(previousDomain) == AppendAPIEndpoint(newDomain) {
		return false
	}

	email := configFile.Profiles[idx].Email
	configFile.Profiles[idx].Domain = newDomain
	configFile.Profiles[idx].OrganizationID = ""
	configFile.Profiles[idx].OrganizationName = ""
	configFile.Profiles[idx].SubOrganizationID = ""

	stillOnPreviousDomain := false
	for _, profile := range configFile.Profiles {
		if profile.Name != profileName && profile.Email == email && profile.Domain == previousDomain {
			stillOnPreviousDomain = true
			break
		}
	}
	if !stillOnPreviousDomain {
		for i, user := range configFile.LoggedInUsers {
			if user.Email == email && user.Domain == previousDomain {
				configFile.LoggedInUsers[i].Domain = newDomain
				break
			}
		}
	}

	if configFile.ActiveProfile == profileName {
		// Re-sync so the legacy pointer reflects the moved profile.
		_ = SetActiveProfile(configFile, profileName)
	}

	return true
}

// RemoveProfile deletes the profile, any directory bindings pointing at it,
// and reconciles the active pointer and legacy fields. The caller is
// responsible for deleting the keyring entry.
func RemoveProfile(configFile *models.ConfigFile, name string) bool {
	idx := findProfileIndex(configFile.Profiles, name)
	if idx < 0 {
		return false
	}

	removed := configFile.Profiles[idx]
	configFile.Profiles = append(configFile.Profiles[:idx], configFile.Profiles[idx+1:]...)

	for dir, profileName := range configFile.DirectoryProfiles {
		if profileName == name {
			delete(configFile.DirectoryProfiles, dir)
		}
	}

	// Drop the legacy roster entry when no remaining profile uses that account.
	emailStillUsed := false
	for _, profile := range configFile.Profiles {
		if profile.Email == removed.Email {
			emailStillUsed = true
			break
		}
	}
	if !emailStillUsed {
		users := configFile.LoggedInUsers[:0]
		for _, user := range configFile.LoggedInUsers {
			if user.Email != removed.Email {
				users = append(users, user)
			}
		}
		configFile.LoggedInUsers = users
	}

	if configFile.ActiveProfile == name {
		configFile.ActiveProfile = ""
		configFile.LoggedInUserEmail = ""
		configFile.LoggedInUserDomain = ""
	}

	return true
}

// DeriveProfileName picks the profile name for a login session when the user
// did not name one explicitly. Rules, in order: reuse the profile that already
// holds this account+instance+organization; adopt a pre-profile (migrated)
// entry for the same account+instance whose organization is still unknown; use
// the bare email when free; otherwise suffix with the organization so a second
// organization never overwrites the first.
func DeriveProfileName(configFile models.ConfigFile, email string, domain string, orgID string, orgName string) string {
	for _, profile := range configFile.Profiles {
		if profile.Email == email && profile.Domain == domain && profile.OrganizationID == orgID {
			return profile.Name
		}
	}
	for _, profile := range configFile.Profiles {
		if profile.Email == email && profile.Domain == domain && profile.OrganizationID == "" {
			return profile.Name
		}
	}

	if findProfileIndex(configFile.Profiles, email) < 0 {
		return email
	}

	suffix := slugifyProfileSuffix(orgName)
	if suffix == "" {
		if len(orgID) >= 8 {
			suffix = orgID[:8]
		} else {
			suffix = orgID
		}
	}
	if suffix == "" {
		suffix = "2"
	}

	base := fmt.Sprintf("%s--%s", email, suffix)
	candidate := base
	for i := 2; findProfileIndex(configFile.Profiles, candidate) >= 0; i++ {
		candidate = fmt.Sprintf("%s-%d", base, i)
	}
	return candidate
}

func slugifyProfileSuffix(value string) string {
	var builder strings.Builder
	lastWasDash := true // suppress leading dashes
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			builder.WriteRune(r)
			lastWasDash = false
		default:
			if !lastWasDash {
				builder.WriteRune('-')
				lastWasDash = true
			}
		}
	}
	return strings.TrimRight(builder.String(), "-")
}

// PersistLoginProfile stores the session credentials in the keyring under the
// profile name and records the profile in the config file. makeActive sets the
// profile as the global default; regardless of it, an already-active profile
// keeps the legacy fields in sync.
func PersistLoginProfile(profile models.Profile, userCred *models.UserCredentials, makeActive bool) error {
	// Deliberately no name validation here: derived names are raw account
	// emails (which may contain any RFC-legal character) and have always been
	// valid keyring keys. Rejecting them would block login entirely. Name
	// validation applies only where users type a name (--profile, --save-as),
	// at the command layer.
	if err := StoreUserCredsInKeyRing(profile.Name, userCred); err != nil {
		return err
	}

	configFile, err := GetMigratedConfigFile()
	if err != nil {
		return fmt.Errorf("persistLoginProfile: unable to load config file [err=%s]", err)
	}

	UpsertProfile(&configFile, profile)
	if makeActive || configFile.ActiveProfile == "" || configFile.ActiveProfile == profile.Name {
		if err := SetActiveProfile(&configFile, profile.Name); err != nil {
			return err
		}
	}

	return WriteConfigFile(&configFile)
}

// ResolveActiveProfileDetails loads the config (with an in-memory migration)
// and resolves the invocation's profile and its stored metadata. found
// reports whether the resolved name has a profile entry.
func ResolveActiveProfileDetails() (resolved ResolvedProfile, profile models.Profile, found bool) {
	configFile, err := GetConfigFile()
	if err != nil {
		return ResolvedProfile{}, models.Profile{}, false
	}
	MigrateConfigProfiles(&configFile)

	resolved = ResolveProfile(configFile)
	if resolved.Name == "" {
		return resolved, models.Profile{}, false
	}

	profile, found = FindProfile(configFile, resolved.Name)
	return resolved, profile, found
}

type userTokenOrgClaims struct {
	OrganizationID    string `json:"organizationId"`
	SubOrganizationID string `json:"subOrganizationId"`
	TokenVersionID    string `json:"tokenVersionId"`
	jwt.RegisteredClaims
}

// ParseTokenOrgClaims decodes (without verifying) the organization scope
// claims from a user session JWT. Returns empty strings when unparsable.
func ParseTokenOrgClaims(token string) (orgID string, subOrgID string) {
	claims := &userTokenOrgClaims{}
	parser := jwt.NewParser()
	if _, _, err := parser.ParseUnverified(token, claims); err != nil {
		return "", ""
	}
	return claims.OrganizationID, claims.SubOrganizationID
}

// ParseTokenSessionID decodes (without verifying) the server-side session id
// from a user session JWT. The server keys sessions by user, IP, and user
// agent, so every token the CLI holds for one account on one machine shares a
// single session id, including organization-scoped ones.
func ParseTokenSessionID(token string) string {
	claims := &userTokenOrgClaims{}
	parser := jwt.NewParser()
	if _, _, err := parser.ParseUnverified(token, claims); err != nil {
		return ""
	}
	return claims.TokenVersionID
}

// FetchOrganizationName resolves an organization's display name with the given
// session token. Best effort: returns "" on any error so callers can fall back
// to showing the ID.
func FetchOrganizationName(jwtToken string, orgID string) string {
	if orgID == "" || jwtToken == "" {
		return ""
	}

	httpClient, err := GetRestyClientWithCustomHeaders()
	if err != nil {
		return ""
	}
	httpClient.SetAuthToken(jwtToken)

	if orgResp, err := api.CallGetAllOrganizations(httpClient); err == nil {
		for _, org := range orgResp.Organizations {
			if org.ID == orgID {
				return org.Name
			}
		}
	}

	// The ID may belong to a sub-organization, which the flat list omits.
	if subOrgsResp, err := api.CallGetAllOrganizationsWithSubOrgs(httpClient); err == nil {
		for _, org := range subOrgsResp.Organizations {
			if org.ID == orgID {
				return org.Name
			}
			for _, sub := range org.SubOrganizations {
				if sub.ID == orgID {
					return fmt.Sprintf("%s / %s", org.Name, sub.Name)
				}
			}
		}
	}

	return ""
}

// OrgDisplayName resolves the human-readable organization for a session. When
// the session is scoped to a sub-organization the sub-organization is used, so
// a session inside "Acme / Research" is not reported as plain "Acme", which
// would be indistinguishable from one scoped to the root organization.
func OrgDisplayName(sessionToken string, orgID string, subOrgID string) string {
	if subOrgID != "" {
		if name := FetchOrganizationName(sessionToken, subOrgID); name != "" {
			return SanitizeDisplay(name)
		}
	}
	return SanitizeDisplay(FetchOrganizationName(sessionToken, orgID))
}

// DisplayDomain renders a stored domain (which includes the /api suffix) the
// way users typed it.
func DisplayDomain(domain string) string {
	return strings.TrimSuffix(domain, "/api")
}
