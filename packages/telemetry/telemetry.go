package telemetry

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/denisbrodbeck/machineid"
	"github.com/posthog/posthog-go"
	"github.com/rs/zerolog/log"
)

var POSTHOG_API_KEY_FOR_CLI string

type Telemetry struct {
	isEnabled     bool
	posthogClient posthog.Client
}

type NoOpLogger struct{}

func (NoOpLogger) Logf(format string, args ...interface{}) {
	log.Debug().Msgf(format, args...)
}

func (NoOpLogger) Errorf(format string, args ...interface{}) {
	log.Debug().Msgf(format, args...)
}

func NewTelemetry(telemetryIsEnabled bool) *Telemetry {
	if POSTHOG_API_KEY_FOR_CLI != "" {
		client, _ := posthog.NewWithConfig(
			POSTHOG_API_KEY_FOR_CLI,
			posthog.Config{
				Logger: NoOpLogger{},
			},
		)

		return &Telemetry{isEnabled: telemetryIsEnabled, posthogClient: client}
	} else {
		return &Telemetry{isEnabled: false}
	}
}

func (t *Telemetry) CaptureEvent(eventName string, properties posthog.Properties) {
	userIdentity, err := t.GetDistinctId()
	if err != nil {
		return
	}

	if t.isEnabled {
		t.posthogClient.Enqueue(posthog.Capture{
			DistinctId: userIdentity,
			Event:      eventName,
			Properties: properties,
		})

		defer t.posthogClient.Close()
	}
}

// IdentifyUser sends a PostHog identify call to enrich the person record
// with user properties, and aliases the anonymous machine ID to the user's
// email so that pre-login CLI events are merged into the same person.
func (t *Telemetry) IdentifyUser(email string) {
	if !t.isEnabled || email == "" {
		return
	}

	// Identify the user with their email as the distinctId
	t.posthogClient.Enqueue(posthog.Identify{
		DistinctId: email,
		Properties: posthog.NewProperties().
			Set("email", email),
	})

	// Alias the anonymous machine ID to the user's email so that
	// any events captured before login are linked to this person
	machineId, err := machineid.ID()
	if err == nil && machineId != "" {
		anonymousId := "anonymous_cli_" + machineId
		t.posthogClient.Enqueue(posthog.Alias{
			DistinctId: email,
			Alias:      anonymousId,
		})
	}

	// Note: no Close() here — the caller is responsible for ensuring
	// CaptureEvent (which calls Close) runs after IdentifyUser to flush
	// all enqueued events (Identify, Alias, and Capture).
}

// getMachineIdentityIdFromEnv inspects the environment variables that the
// CLI uses to receive machine-identity access tokens (the same set checked
// by util.GetInfisicalToken, minus the `--token` flag which is per-command
// and not visible to the telemetry layer) and, if a machine-identity JWT
// is present, returns the `identityId` claim from its payload.
//
// The function is intentionally best-effort and silent on failure:
//   - returns "" if no token is set
//   - returns "" for service tokens (`st.` prefix), which carry no JWT
//     payload and represent the deprecated service-token auth mode
//   - returns "" if the JWT is malformed or missing the `identityId` claim
//
// The token's signature is not verified — the value is only used to derive
// a PostHog distinctId, never for authorization. The same token has already
// been (or is about to be) sent to the Infisical API where its signature is
// verified server-side.
func getMachineIdentityIdFromEnv() string {
	// Mirror the env-var precedence in util.GetInfisicalToken so that the
	// telemetry distinctId aligns with the credential the API call will
	// actually use:
	//   1. INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN
	//   2. INFISICAL_TOKEN
	//   3. TOKEN (legacy gateway env var)
	envVars := []string{
		util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME,
		util.INFISICAL_TOKEN_NAME,
		util.INFISICAL_GATEWAY_TOKEN_NAME_LEGACY,
	}

	var token string
	for _, name := range envVars {
		if v := os.Getenv(name); v != "" {
			token = v
			break
		}
	}

	if token == "" {
		return ""
	}

	// Service tokens are deprecated and not JWTs — no identityId to extract.
	if strings.HasPrefix(token, "st.") {
		return ""
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some JWT issuers pad the payload with `=`; tolerate that variant.
		payloadBytes, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}

	var claims struct {
		IdentityID string `json:"identityId"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return ""
	}

	return claims.IdentityID
}

func (t *Telemetry) GetDistinctId() (string, error) {
	var distinctId string

	machineId, err := machineid.ID()
	if err != nil {
		log.Debug().Err(err).Msg("failed to get machine ID for telemetry")
	}

	infisicalConfig, err := util.GetConfigFile()
	if err != nil {
		log.Debug().Err(err).Msg("failed to get config file for telemetry")
	}

	// Resolution priority:
	//  1. Machine-identity access token from env (matches the credential the
	//     API call will use, and aligns with the `identity-<id>` distinctId
	//     the backend already uses for MachineIdentityLogin and other
	//     identity-scoped events). This deliberately beats LoggedInUserEmail
	//     because when both are present (e.g. a developer testing CI locally),
	//     the CLI authenticates as the machine identity, not the user.
	//  2. Logged-in user email from the persisted config.
	//  3. Anonymous fallback keyed by the local machine ID.
	if identityId := getMachineIdentityIdFromEnv(); identityId != "" {
		distinctId = "identity-" + identityId
	} else if infisicalConfig.LoggedInUserEmail != "" {
		distinctId = infisicalConfig.LoggedInUserEmail
	} else if machineId != "" {
		distinctId = "anonymous_cli_" + machineId
	}

	// Only return an error if we could not resolve any distinctId.
	// Non-critical errors (e.g. machineid failure when email is available)
	// are logged above but should not prevent event capture.
	if distinctId == "" {
		return "", errors.New("unable to resolve a distinct ID for telemetry")
	}

	return distinctId, nil
}
