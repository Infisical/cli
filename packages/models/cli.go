package models

import "time"

type UserCredentials struct {
	Email        string `json:"email"`
	PrivateKey   string `json:"privateKey"`
	JTWToken     string `json:"JTWToken"`
	RefreshToken string `json:"RefreshToken"`
	// OrgTokens caches session tokens for organizations other than the
	// profile's default one, keyed by organization ID. Session tokens are
	// organization-scoped, so switching organizations means exchanging the
	// token; caching the result keeps --org cheap after its first use.
	OrgTokens map[string]CachedOrgSession `json:"orgTokens,omitempty"`
}

// CachedOrgSession is a session token minted for a specific organization,
// stored alongside enough metadata to match an --org selector without calling
// the API again.
type CachedOrgSession struct {
	Token   string `json:"token"`
	OrgID   string `json:"orgId"`
	OrgName string `json:"orgName,omitempty"`
	OrgSlug string `json:"orgSlug,omitempty"`
}

// Profile is a named login session: one account on one instance. The
// organization is the profile's default (overridable per command with
// --org/INFISICAL_ORG), not part of its identity. The keyring entry holding the
// session credentials is keyed by Name; profiles migrated from the legacy
// single-session config are named after the account email so their existing
// email-keyed keyring entries keep working.
type Profile struct {
	Name   string `json:"name"`
	Email  string `json:"email"`
	Domain string `json:"domain"`
	// OrganizationID is the profile's default organization.
	OrganizationID    string `json:"organizationId,omitempty"`
	OrganizationName  string `json:"organizationName,omitempty"`
	SubOrganizationID string `json:"subOrganizationId,omitempty"`
}

// The file struct for Infisical config file
type ConfigFile struct {
	// LoggedInUserEmail, LoggedInUserDomain, and LoggedInUsers predate profiles.
	// They are kept in sync with the active profile so older CLI versions and
	// scripts that read them keep working.
	LoggedInUserEmail      string         `json:"loggedInUserEmail"`
	LoggedInUserDomain     string         `json:"LoggedInUserDomain,omitempty"`
	LoggedInUsers          []LoggedInUser `json:"loggedInUsers,omitempty"`
	VaultBackendType       string         `json:"vaultBackendType,omitempty"`
	VaultBackendPassphrase string         `json:"vaultBackendPassphrase,omitempty"`
	Domains                []string       `json:"domains,omitempty"`
	// LastIdentifiedEmail tracks the most recent email for which a PostHog
	// Identify/Alias call has been issued. It is used to ensure that telemetry
	// person records are enriched with `email` (and aliased from any anonymous
	// machine ID) exactly once per email per machine, even when the login
	// happened on an older CLI version that predates the IdentifyUser flow,
	// or when the email is changed via `infisical user switch`.
	LastIdentifiedEmail string `json:"lastIdentifiedEmail,omitempty"`

	// ActiveProfile is the global default profile used when no --profile flag,
	// INFISICAL_PROFILE env var, or directory scope selects one.
	ActiveProfile string    `json:"activeProfile,omitempty"`
	Profiles      []Profile `json:"profiles,omitempty"`
	// DirectoryProfiles maps an absolute directory path to the profile name
	// that commands run inside that directory (or any subdirectory) should use.
	DirectoryProfiles map[string]string `json:"directoryProfiles,omitempty"`
}

type LoggedInUser struct {
	Email  string `json:"email"`
	Domain string `json:"domain"`
}

type Tag struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Slug  string `json:"slug"`
	Color string `json:"color"`
}

type SingleEnvironmentVariable struct {
	Key                   string `json:"key"`
	WorkspaceId           string `json:"workspace"`
	Value                 string `json:"value"`
	Type                  string `json:"type"`
	ID                    string `json:"_id"`
	SecretPath            string `json:"secretPath"`
	Tags                  []Tag  `json:"tags"`
	Comment               string `json:"comment"`
	Etag                  string `json:"Etag"`
	SkipMultilineEncoding bool   `json:"skipMultilineEncoding"`
}

// TLDR; Why you shouldn't depend on "SkipMultilineEncoding" and instead use this method
// "SkipMultilineEncoding" generally means that the value should not be encoded as a multiline string
// But due to historic reasons this property actually does the opposite - it encodes the value as a multiline string
func (s SingleEnvironmentVariable) IsMultilineEncodingEnabled() bool {
	// Encode the value only if "skipMultilineEncoding" doesn't exist or is true
	return s.SkipMultilineEncoding
}

type PlaintextSecretResult struct {
	Secrets []SingleEnvironmentVariable
	Etag    string
}

type DynamicSecret struct {
	Id         string `json:"id"`
	DefaultTTL string `json:"defaultTTL"`
	MaxTTL     string `json:"maxTTL"`
	Type       string `json:"type"`
}

type DynamicSecretLeaseWithoutData struct {
	Lease struct {
		Id       string    `json:"id"`
		ExpireAt time.Time `json:"expireAt"`
	} `json:"lease"`
	DynamicSecret DynamicSecret `json:"dynamicSecret"`
}

type DynamicSecretLease struct {
	Lease struct {
		Id       string    `json:"id"`
		ExpireAt time.Time `json:"expireAt"`
	} `json:"lease"`
	DynamicSecret DynamicSecret `json:"dynamicSecret"`
	// this is a varying dict based on provider
	Data map[string]interface{} `json:"data"`
}

type TokenDetails struct {
	Type   string
	Token  string
	Source string
}

type SingleFolder struct {
	ID   string `json:"_id"`
	Name string `json:"name"`
}

type Workspace struct {
	ID             string `json:"_id"`
	Name           string `json:"name"`
	Plan           string `json:"plan,omitempty"`
	V              int    `json:"__v"`
	OrganizationId string `json:"orgId"`
}

type WorkspaceConfigFile struct {
	WorkspaceId                   string            `json:"workspaceId"`
	DefaultEnvironment            string            `json:"defaultEnvironment"`
	GitBranchToEnvironmentMapping map[string]string `json:"gitBranchToEnvironmentMapping"`
	DefaultSecretPath             string            `json:"defaultSecretPath,omitempty"`
	Domain                        string            `json:"domain,omitempty"`
}

type SymmetricEncryptionResult struct {
	CipherText []byte `json:"CipherText"`
	Nonce      []byte `json:"Nonce"`
	AuthTag    []byte `json:"AuthTag"`
}

type GetMultiPathSecretsParameters struct {
	Environment            string
	WorkspaceId            string
	TagSlugs               string
	SecretsPaths           []string
	IncludeImport          bool
	Recursive              bool
	ExpandSecretReferences bool
}

type GetAllSecretsParameters struct {
	Environment              string
	EnvironmentPassedViaFlag bool
	InfisicalToken           string
	UniversalAuthAccessToken string
	TagSlugs                 string
	WorkspaceId              string
	SecretsPath              string
	IncludeImport            bool
	Recursive                bool
	ExpandSecretReferences   bool
	IncludePersonalOverrides bool
}

type InjectableEnvironmentResult struct {
	Variables    []string
	ETag         string
	SecretsCount int
}

type GetAllFoldersParameters struct {
	WorkspaceId              string
	Environment              string
	FoldersPath              string
	InfisicalToken           string
	UniversalAuthAccessToken string
}

type CreateFolderParameters struct {
	FolderName     string
	WorkspaceId    string
	Environment    string
	FolderPath     string
	InfisicalToken string
}

type DeleteFolderParameters struct {
	FolderName     string
	WorkspaceId    string
	Environment    string
	FolderPath     string
	InfisicalToken string
}

type ExpandSecretsAuthentication struct {
	InfisicalToken           string
	UniversalAuthAccessToken string
}

type MachineIdentityCredentials struct {
	ClientId     string
	ClientSecret string
}

type SecretSetOperation struct {
	SecretKey       string
	SecretValue     string
	SecretOperation string
}

type BackupSecretKeyRing struct {
	ProjectID   string `json:"projectId"`
	Environment string `json:"environment"`
	SecretPath  string `json:"secretPath"`
	Secrets     []SingleEnvironmentVariable
}
