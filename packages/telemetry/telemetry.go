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
