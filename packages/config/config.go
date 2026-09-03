package config

var INFISICAL_URL string
var INFISICAL_URL_MANUAL_OVERRIDE string
var INFISICAL_LOGIN_URL string

// INFISICAL_PROFILE_OVERRIDE holds the per-invocation profile selection from
// the --profile flag or the INFISICAL_PROFILE env var (flag wins). Set by the
// root command's PersistentPreRun. Empty when neither is provided.
var INFISICAL_PROFILE_OVERRIDE string
var INFISICAL_PROFILE_OVERRIDE_SOURCE string

// INFISICAL_ORG_OVERRIDE holds the per-invocation organization selection from
// the --org flag or the INFISICAL_ORG env var (flag wins). The organization is
// a field of the resolved profile, not part of its identity, so this overrides
// the profile's default organization for a single command without changing it.
var INFISICAL_ORG_OVERRIDE string
var INFISICAL_ORG_OVERRIDE_SOURCE string

// INFISICAL_DOMAIN_EXPLICITLY_SET is true when the domain came from the
// --domain flag or a domain env var. An explicit domain is honored even when
// the resolved profile has its own saved domain.
var INFISICAL_DOMAIN_EXPLICITLY_SET bool
