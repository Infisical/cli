package agentproxy

import (
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/rs/zerolog/log"
)

// Placeholder is one environment variable the agent receives in place of a real credential. Only
// substitution credentials need one; a header rewrite is applied by the broker itself, so the agent never
// sees or sends a value for it.
type Placeholder struct {
	Key   string
	Value string
}

// bundleToServices turns a resolved bundle into what the matcher and rewriter consume. The backend has
// already resolved every value under the right authority, so there is nothing to fetch here: this is a
// shape change, not a resolution step.
func bundleToServices(bundle api.AgentGatewayBrokerBundleResponse) []*resolvedService {
	services := make([]*resolvedService, 0, len(bundle.Services))

	for _, svc := range bundle.Services {
		resolved := &resolvedService{
			id:           svc.ID,
			name:         svc.Name,
			priority:     svc.Priority,
			hostPatterns: parseHostPatterns(svc.HostPattern),
			isEnabled:    svc.IsEnabled,
		}

		for _, cred := range svc.Credentials {
			// A credential the backend could not resolve is reported rather than omitted, so the reason can
			// be surfaced once instead of every request failing with no explanation. It is skipped here
			// because there is no value to apply.
			if cred.Unavailable {
				log.Warn().Msgf(
					"agent gateway: skipping credential on service %q: %s",
					svc.Name,
					unavailableReasonText(cred.UnavailableReason),
				)
				continue
			}

			var dynamic *dynamicCredentialRef
			if cred.DynamicSecretName != "" {
				dynamic = &dynamicCredentialRef{secretName: cred.DynamicSecretName, field: cred.DynamicSecretField}
			}

			resolved.credentials = append(resolved.credentials, resolvedCredential{
				secretKey:     cred.SecretKey,
				dynamic:       dynamic,
				role:          cred.Role,
				headerName:    cred.HeaderName,
				headerPrefix:  cred.HeaderPrefix,
				headerPurpose: cred.HeaderPurpose,
				placeholder:   cred.PlaceholderValue,
				surfaces:      cred.SubstitutionSurfaces,
				value:         cred.Value,
			})
		}

		services = append(services, resolved)
	}

	return services
}

// One shared extractor so the environment the CLI builds and the substitution the broker performs cannot
// disagree about which placeholder belongs to which variable.
func bundlePlaceholders(bundle api.AgentGatewayBrokerBundleResponse) []Placeholder {
	var placeholders []Placeholder
	for _, svc := range bundle.Services {
		if !svc.IsEnabled {
			continue
		}
		for _, cred := range svc.Credentials {
			if cred.Unavailable || cred.PlaceholderKey == "" || cred.PlaceholderValue == "" {
				continue
			}
			placeholders = append(placeholders, Placeholder{Key: cred.PlaceholderKey, Value: cred.PlaceholderValue})
		}
	}
	return placeholders
}

func unavailableReasonText(reason string) string {
	switch reason {
	case "configurer_lost_access":
		return "the person who configured this service can no longer read the secret it references"
	case "configurer_deleted":
		return "the person who configured this service no longer exists"
	case "secret_missing":
		return "the referenced secret no longer exists"
	case "dynamic_secret_lease_failed":
		return "the dynamic secret could not be leased"
	case "service_disabled":
		return "the service is disabled"
	default:
		return "unavailable"
	}
}
