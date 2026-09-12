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

// MaxProfileNameLength bounds user-typed profile names. Names double as
// keyring keys, and platform keyrings cap the size of one entry (about 4 KB on
// macOS for key and value together), so an overlong name could make storing
// the session fail after the login itself succeeded.
const MaxProfileNameLength = 64

func ValidateProfileName(name string) error {
	if len(name) > MaxProfileNameLength {
		return fmt.Errorf("invalid profile name: %d characters is too long, use at most %d", len(name), MaxProfileNameLength)
	}
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

// orgDisplaySeparator joins a parent organization and a sub-organization in
// display names, as in "Acme / Research".
const orgDisplaySeparator = " / "

// JoinOrgDisplayName renders a sub-organization as "Parent / Child". With no
// parent the name is returned as-is.
func JoinOrgDisplayName(parent, own string) string {
	if parent == "" {
		return own
	}
	return parent + orgDisplaySeparator + own
}

// SplitOrgDisplayName is the inverse of JoinOrgDisplayName. A plain name comes
// back with an empty parent.
func SplitOrgDisplayName(display string) (parent, own string) {
	idx := strings.LastIndex(display, orgDisplaySeparator)
	if idx < 0 {
		return "", display
	}
	return display[:idx], display[idx+len(orgDisplaySeparator):]
}

// OrgMatchTier reports how strongly a selector matches an organization, using
// the tiers above. Slug and name comparisons are case-insensitive so
// `--org globex` matches an organization named "Globex". name may be a display
// name of the form "Parent / Child", in which case the sub-organization also
// matches on its own name, so `--org research` finds "Acme / Research".
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
	if name != "" {
		if strings.EqualFold(selector, name) {
			return orgMatchName
		}
		if _, own := SplitOrgDisplayName(name); own != name && strings.EqualFold(selector, own) {
			return orgMatchName
		}
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
	ID string
	// Name is the display name, "Parent / Child" for a sub-organization.
	Name string
	Slug string
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
				candidates = append(candidates, ResolvedOrg{ID: sub.ID, Name: JoinOrgDisplayName(org.Name, sub.Name), Slug: sub.Slug})
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
		tier := OrgMatchTier(selector, candidate.ID, candidate.Slug, candidate.Name)
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

// KnownOrgMatch is an organization the profile already knows about: its own
// default organization or a cached organization session.
type KnownOrgMatch struct {
	OrgID   string
	OrgName string
	OrgSlug string
	// IsProfileDefault is true when the match is the profile's own
	// organization, which needs no exchange at all.
	IsProfileDefault bool
}

// MatchKnownOrg resolves an --org/INFISICAL_ORG selector against what the
// profile already knows, so repeated use of the same organization makes no
// API calls: the profile's default organization and every cached organization
// session are compared by id, slug, and name, and the strongest match wins. A
// tie between two different organizations at the strongest tier is not a
// match, so the server-side listing, which reports the ambiguity, decides.
func MatchKnownOrg(profile models.Profile, selector string) (KnownOrgMatch, bool) {
	best := KnownOrgMatch{}
	bestTier := orgMatchNone
	ambiguous := false

	consider := func(candidate KnownOrgMatch) {
		tier := OrgMatchTier(selector, candidate.OrgID, candidate.OrgSlug, candidate.OrgName)
		switch {
		case tier > bestTier:
			best, bestTier, ambiguous = candidate, tier, false
		case tier == bestTier && tier != orgMatchNone && candidate.OrgID != best.OrgID:
			ambiguous = true
		}
	}

	if scopedID := profile.ScopedOrganizationID(); scopedID != "" {
		consider(KnownOrgMatch{OrgID: scopedID, OrgName: profile.OrganizationName, OrgSlug: profile.OrganizationSlug, IsProfileDefault: true})
	}
	for _, ref := range profile.OrgSessions {
		consider(KnownOrgMatch{OrgID: ref.OrgID, OrgName: ref.OrgName, OrgSlug: ref.OrgSlug})
	}

	if bestTier == orgMatchNone || ambiguous {
		return KnownOrgMatch{}, false
	}
	return best, true
}

// OrgSessionKeyringKey is the keyring entry holding the session token cached
// for one organization under a profile. Profile names cannot contain ':' (see
// ValidateProfileName; emails do not either), so the key cannot collide with a
// profile's own entry.
func OrgSessionKeyringKey(profileName string, orgID string) string {
	return "org-session:" + profileName + ":" + orgID
}

// RecordOrgSession adds or refreshes the index entry for a cached organization
// session on the profile, in memory.
func RecordOrgSession(profile *models.Profile, ref models.OrgSessionRef) {
	for idx := range profile.OrgSessions {
		if profile.OrgSessions[idx].OrgID == ref.OrgID {
			profile.OrgSessions[idx] = ref
			return
		}
	}
	profile.OrgSessions = append(profile.OrgSessions, ref)
}

// RemoveOrgSession drops the index entry for an organization, in memory, and
// reports whether one existed. The caller deletes the keyring entry.
func RemoveOrgSession(profile *models.Profile, orgID string) bool {
	for idx, ref := range profile.OrgSessions {
		if ref.OrgID == orgID {
			profile.OrgSessions = append(profile.OrgSessions[:idx], profile.OrgSessions[idx+1:]...)
			return true
		}
	}
	return false
}

// UpdateStoredProfile applies mutate to the named profile in the config file
// and saves it. The file is reloaded first, so only that profile changes and
// edits made by other commands in the meantime are kept.
func UpdateStoredProfile(name string, mutate func(profile *models.Profile)) error {
	configFile, err := GetMigratedConfigFile()
	if err != nil {
		return err
	}
	idx := findProfileIndex(configFile.Profiles, name)
	if idx < 0 {
		return fmt.Errorf("profile '%s' does not exist", name)
	}
	mutate(&configFile.Profiles[idx])
	if configFile.ActiveProfile == name {
		syncLegacyLoginFields(&configFile, configFile.Profiles[idx])
	}
	return WriteConfigFile(&configFile)
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
	configFile.Profiles[idx].OrganizationSlug = ""
	configFile.Profiles[idx].SubOrganizationID = ""
	configFile.Profiles[idx].OrgSessions = nil

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

// RenameProfile changes a profile's name everywhere the config refers to it:
// the entry itself, the default-profile pointer, and directory bindings. The
// legacy fields are re-synced, since they are only published for profiles
// named after their email. The caller moves the keyring entries, which are
// keyed by name.
func RenameProfile(configFile *models.ConfigFile, oldName string, newName string) error {
	if oldName == newName {
		return fmt.Errorf("profile is already named '%s'", oldName)
	}
	idx := findProfileIndex(configFile.Profiles, oldName)
	if idx < 0 {
		return fmt.Errorf("profile '%s' does not exist", oldName)
	}
	if findProfileIndex(configFile.Profiles, newName) >= 0 {
		return fmt.Errorf("profile '%s' already exists", newName)
	}

	configFile.Profiles[idx].Name = newName
	for dir, name := range configFile.DirectoryProfiles {
		if name == oldName {
			configFile.DirectoryProfiles[dir] = newName
		}
	}
	if configFile.ActiveProfile == oldName {
		return SetActiveProfile(configFile, newName)
	}
	return nil
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
// entry for the same account+instance whose organization is still unknown;
// otherwise name the profile after the account and organization, as in
// "scott@example.com--acme-x4k2", so the organization is visible without
// listing and a second organization never overwrites the first. The suffix is
// the organization slug, which is stable and already URL-safe; instances that
// report no slugs fall back to the slugified name, then to a prefix of the id.
// Only with no organization information at all is the bare email used.
//
// Names that are not the bare email leave the legacy loggedInUserEmail pointer
// unset (see syncLegacyLoginFields), so a CLI build that predates profiles
// asks for a fresh login rather than loading another profile's session.
func DeriveProfileName(configFile models.ConfigFile, email string, domain string, orgID string, orgName string, orgSlug string) string {
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

	suffix := slugifyProfileSuffix(orgSlug)
	if suffix == "" {
		suffix = slugifyProfileSuffix(orgName)
	}
	if suffix == "" {
		if len(orgID) >= 8 {
			suffix = orgID[:8]
		} else {
			suffix = orgID
		}
	}

	base := email
	if suffix != "" {
		base = fmt.Sprintf("%s--%s", email, suffix)
	}
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
	// validation applies only where users type a name (--profile, profile new,
	// profile rename), at the command layer.
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

// LoginRenewalArgs builds the arguments for re-running login to restore the
// session of the profile this invocation resolved to. An existing profile is
// signed back in to with --profile, which keeps its account, instance, and
// organization; a profile that was selected but never created (a pinned
// terminal or bound directory pointing at it) is created with --save-as, so
// the selection starts working. The instance is passed explicitly as well so
// the login never has to ask.
func LoginRenewalArgs(resolved ResolvedProfile, profile models.Profile, found bool) []string {
	args := []string{"login", "--silent"}
	if resolved.Name == "" {
		return args
	}
	if !found {
		return append(args, "--save-as", resolved.Name)
	}
	args = append(args, "--profile", resolved.Name)
	if profile.Domain != "" {
		args = append(args, "--domain", DisplayDomain(profile.Domain))
	}
	return args
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

// OrgInfo describes one organization the account can use.
type OrgInfo struct {
	ID   string
	Name string
	Slug string
	// ParentName is set for a sub-organization.
	ParentName string
}

// DisplayName renders the organization for humans, "Parent / Child" for a
// sub-organization, so a session inside "Acme / Research" is not reported as
// plain "Acme", which would be indistinguishable from the root organization.
func (o OrgInfo) DisplayName() string {
	return JoinOrgDisplayName(o.ParentName, o.Name)
}

// LookupOrganization finds an organization, root or sub, by id with the given
// session token. Best effort: found is false on any error, so callers can fall
// back to showing the id. The sub-organization aware listing is preferred
// because it carries slugs and nested organizations; instances without it fall
// back to the flat list, which has names only.
func LookupOrganization(sessionToken string, orgID string) (OrgInfo, bool) {
	if orgID == "" || sessionToken == "" {
		return OrgInfo{}, false
	}

	httpClient, err := GetRestyClientWithCustomHeaders()
	if err != nil {
		return OrgInfo{}, false
	}
	httpClient.SetAuthToken(sessionToken)

	if subOrgsResp, err := api.CallGetAllOrganizationsWithSubOrgs(httpClient); err == nil {
		for _, org := range subOrgsResp.Organizations {
			if org.ID == orgID {
				return OrgInfo{ID: org.ID, Name: org.Name, Slug: org.Slug}, true
			}
			for _, sub := range org.SubOrganizations {
				if sub.ID == orgID {
					return OrgInfo{ID: sub.ID, Name: sub.Name, Slug: sub.Slug, ParentName: org.Name}, true
				}
			}
		}
	}

	if orgResp, err := api.CallGetAllOrganizations(httpClient); err == nil {
		for _, org := range orgResp.Organizations {
			if org.ID == orgID {
				return OrgInfo{ID: org.ID, Name: org.Name}, true
			}
		}
	}

	return OrgInfo{}, false
}

// DescribeSessionOrg describes the organization a session acts in, given the
// organizationId and subOrganizationId claims of its token: the
// sub-organization when there is one, otherwise the root. Names are sanitized
// for display. When the lookup fails only the id is set, so callers can still
// show something.
func DescribeSessionOrg(sessionToken string, orgID string, subOrgID string) OrgInfo {
	scopedID := orgID
	if subOrgID != "" {
		scopedID = subOrgID
	}

	info, found := LookupOrganization(sessionToken, scopedID)
	if !found {
		return OrgInfo{ID: scopedID}
	}
	info.Name = SanitizeDisplay(info.Name)
	info.Slug = SanitizeDisplay(info.Slug)
	info.ParentName = SanitizeDisplay(info.ParentName)
	return info
}

// DisplayDomain renders a stored domain (which includes the /api suffix) the
// way users typed it.
func DisplayDomain(domain string) string {
	return strings.TrimSuffix(domain, "/api")
}
