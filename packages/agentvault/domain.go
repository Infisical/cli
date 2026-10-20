package agentvault

import (
	"fmt"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
)

// The instance this run talks to, without the /api suffix, which is the form --domain takes.
func currentDomain() string {
	return util.DisplayDomain(config.INFISICAL_URL)
}

// A proxy's token is signed by the instance it enrolled with and is valid nowhere else. Without this, a
// restart that left out --domain sent it to the US Cloud default, and every heartbeat and resolve failed
// with "invalid signature" until someone passed --domain again.
//
// An explicit --domain or INFISICAL_DOMAIN that names another instance is refused rather than overridden,
// the same as a login profile's session: the operator asked for that instance, and the token is not sent
// somewhere it cannot be valid. A domain from .infisical.yaml does not count as explicit, so the stored
// one wins over it, as a profile's does.
//
// State enrolled before the domain was recorded has none, and is left to the usual resolution until a
// heartbeat proves which instance accepts its token.
func pinDomain(state persistedState) error {
	if state.Domain == "" {
		return nil
	}
	enrolled := util.AppendAPIEndpoint(state.Domain)
	if enrolled != config.INFISICAL_URL {
		if config.INFISICAL_DOMAIN_EXPLICITLY_SET {
			return fmt.Errorf(
				"this proxy enrolled with %s and its token is valid only there, but %s was requested with --domain or INFISICAL_DOMAIN, so nothing was sent. Drop the override to serve against %s, or enroll against %s with a new token from its Proxies page",
				state.Domain, currentDomain(), state.Domain, currentDomain())
		}
		config.INFISICAL_URL = enrolled
	}
	// Root may already have announced a domain from .infisical.yaml, so this says which one is in use.
	log.Info().Msgf("agent-vault: using %s (saved at enrollment)", state.Domain)
	return nil
}

// Whether the domain this run resolved may be recorded for state that has none: it came from --domain,
// INFISICAL_DOMAIN or the default. A .infisical.yaml usually comes with a repository, so recording its
// domain would let a file in whatever directory the proxy was once started from redirect it for good.
func domainIsRecordable() bool {
	if config.INFISICAL_DOMAIN_EXPLICITLY_SET {
		return true
	}
	// Root ignores an unusable domain in the file and falls back to the default, so that one is recordable.
	domain, valid := util.GetDomainFromFile()
	return domain == "" || !valid
}
