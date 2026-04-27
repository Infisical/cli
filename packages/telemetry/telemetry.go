package telemetry

import (
	"errors"

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
		// Lazily issue the PostHog Identify/Alias for the current logged-in
		// user before capturing the event. This catches the case where the
		// user logged in on an older CLI version that predates IdentifyUser
		// (so their PostHog person record was never enriched with `email`),
		// as well as profile switches via `infisical user switch`. The call
		// is idempotent and persists its state in the local config file.
		t.IdentifyUserIfNeeded()

		t.posthogClient.Enqueue(posthog.Capture{
			DistinctId: userIdentity,
			Event:      eventName,
			Properties: properties,
		})

		defer t.posthogClient.Close()
	}
}

// IdentifyUserIfNeeded sends a PostHog Identify call to enrich the person
// record with the user's email, and aliases the anonymous machine ID to the
// email so that pre-login CLI events are merged into the same person.
//
// The call is idempotent: it tracks the last identified email in the local
// config file (`LastIdentifiedEmail`) and skips Identify/Alias when it has
// already been issued for the current `LoggedInUserEmail`. This ensures a
// single Identify is sent per email per machine, even when:
//   - the original login happened on a CLI version that predates IdentifyUser,
//   - the user changes profiles via `infisical user switch`,
//   - subsequent CLI commands run after the original login.
//
// No Close() is performed here — the caller (typically CaptureEvent) is
// responsible for flushing the PostHog client after enqueueing.
func (t *Telemetry) IdentifyUserIfNeeded() {
	if !t.isEnabled {
		return
	}

	configFile, err := util.GetConfigFile()
	if err != nil {
		log.Debug().Err(err).Msg("IdentifyUserIfNeeded: failed to read config file")
		return
	}

	email := configFile.LoggedInUserEmail
	if email == "" || email == configFile.LastIdentifiedEmail {
		return
	}

	// Identify the user with their email as the distinctId
	t.posthogClient.Enqueue(posthog.Identify{
		DistinctId: email,
		Properties: posthog.NewProperties().
			Set("email", email),
	})

	// Alias the anonymous machine ID to the user's email so that any events
	// captured before login (or before IdentifyUser was added) are linked to
	// the same person record. PostHog only honors the first Alias for a given
	// anonymous ID, so subsequent invocations on the same machine are no-ops
	// on the server side — which is fine, the persisted LastIdentifiedEmail
	// guard prevents us from re-enqueueing them anyway.
	machineId, err := machineid.ID()
	if err == nil && machineId != "" {
		anonymousId := "anonymous_cli_" + machineId
		t.posthogClient.Enqueue(posthog.Alias{
			DistinctId: email,
			Alias:      anonymousId,
		})
	}

	// Persist that we've identified this email so we don't re-fire on the
	// next CLI invocation. A failure here is non-fatal — the worst case is
	// one extra Identify enqueue on the next run.
	configFile.LastIdentifiedEmail = email
	if err := util.WriteConfigFile(&configFile); err != nil {
		log.Debug().Err(err).Msg("IdentifyUserIfNeeded: failed to persist LastIdentifiedEmail")
	}
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

	if infisicalConfig.LoggedInUserEmail != "" {
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
