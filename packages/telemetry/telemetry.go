package telemetry

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/denisbrodbeck/machineid"
	"github.com/posthog/posthog-go"
	"github.com/rs/zerolog/log"
)

var POSTHOG_API_KEY_FOR_CLI string

type Telemetry struct {
	isEnabled     bool
	posthogClient posthog.Client

	// Set by SetActor for commands whose credential is not in the environment.
	attachedIdentityId string
	attachedOrgId      string
}

type NoOpLogger struct{}

func (NoOpLogger) Logf(format string, args ...interface{}) {
	log.Debug().Msgf(format, args...)
}

func (NoOpLogger) Errorf(format string, args ...interface{}) {
	log.Debug().Msgf(format, args...)
}

func NewTelemetry(telemetryIsEnabled bool) *Telemetry {
	return newTelemetry(POSTHOG_API_KEY_FOR_CLI, "", telemetryIsEnabled)
}

// newTelemetry takes the endpoint so tests can point the client at a local server; empty means PostHog's.
func newTelemetry(apiKey string, endpoint string, telemetryIsEnabled bool) *Telemetry {
	if apiKey == "" {
		return &Telemetry{isEnabled: false}
	}

	client, _ := posthog.NewWithConfig(
		apiKey,
		posthog.Config{
			Endpoint: endpoint,
			Logger:   NoOpLogger{},
		},
	)

	return &Telemetry{isEnabled: telemetryIsEnabled, posthogClient: client}
}

// SetEnabled applies the opt-out once flags are parsed. A build without a PostHog key has no client, so it
// stays disabled whatever is passed.
func (t *Telemetry) SetEnabled(enabled bool) {
	t.isEnabled = enabled && t.posthogClient != nil
}

func (t *Telemetry) IsEnabled() bool {
	return t.isEnabled
}

// CaptureEventAsync sends the event without waiting on PostHog. It is for commands that go on to run something
// long-lived, whose start would otherwise wait on an unreachable PostHog. The event is lost if the process exits
// before the send completes.
func (t *Telemetry) CaptureEventAsync(eventName string, properties posthog.Properties) {
	// Everything that reads or writes the config file or this struct runs here, on the caller: these commands
	// can exit at any moment, and an exit in the middle of a config write would leave the file truncated. The
	// goroutine only talks to PostHog.
	if !t.enqueue(eventName, properties) {
		return
	}
	go t.posthogClient.Close()
}

func (t *Telemetry) CaptureEvent(eventName string, properties posthog.Properties) {
	if !t.enqueue(eventName, properties) {
		return
	}
	t.closeWithin(flushTimeout)
}

// enqueue does everything but the send, and reports whether an event was queued.
func (t *Telemetry) enqueue(eventName string, properties posthog.Properties) bool {
	// Checked first, so a run that opted out never reads the machine ID or the config file.
	if !t.isEnabled {
		return false
	}

	userIdentity, err := t.GetDistinctId()
	if err != nil {
		return false
	}

	// Lazily issue the PostHog Identify/Alias for the current logged-in
	// user before capturing the event. This catches the case where the
	// user logged in on an older CLI version that predates IdentifyUser
	// (so their PostHog person record was never enriched with `email`),
	// as well as profile switches via `infisical user switch`. The call
	// is idempotent and persists its state in the local config file.
	t.IdentifyUserIfNeeded()

	capture := posthog.Capture{
		DistinctId: userIdentity,
		Event:      eventName,
		Properties: properties,
	}

	if orgId := t.resolveOrganizationId(); orgId != "" {
		capture.Groups = posthog.NewGroups().Set("organization", orgId)
	}

	t.posthogClient.Enqueue(capture)
	return true
}

// SetActor records who the command is acting as, for commands that resolve their
// own credential and so have nothing in the environment to read.
func (t *Telemetry) SetActor(identityId, orgId string) {
	t.attachedIdentityId = identityId
	t.attachedOrgId = orgId
}

// Once an actor is set, its organization is authoritative even when empty: falling
// back to the environment would group the event under a different actor's org.
func (t *Telemetry) resolveOrganizationId() string {
	if t.attachedIdentityId != "" || t.attachedOrgId != "" {
		return t.attachedOrgId
	}
	_, orgId := machineIdentityClaimsFromEnv()
	return orgId
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

	email := util.ActiveAccountEmail(configFile)
	if email == "" || email == configFile.LastIdentifiedEmail {
		return
	}

	// Identify the user with their email as the distinctId
	if err := t.posthogClient.Enqueue(posthog.Identify{
		DistinctId: email,
		Properties: posthog.NewProperties().
			Set("email", email),
	}); err != nil {
		// If we couldn't even enqueue the Identify (closed client, malformed
		// message, etc.), don't persist LastIdentifiedEmail — otherwise the
		// guard at the top of this function would lock the user out of ever
		// being identified again. Bail out early so the next CLI invocation
		// retries naturally.
		log.Debug().Err(err).Msgf("IdentifyUserIfNeeded: failed to enqueue Identify [email=%s]", email)
		return
	}

	// Alias the anonymous machine ID to the user's email so that any events
	// captured before login (or before IdentifyUser was added) are linked to
	// the same person record. PostHog only honors the first Alias for a given
	// anonymous ID, so subsequent invocations on the same machine are no-ops
	// on the server side — which is fine, the persisted LastIdentifiedEmail
	// guard prevents us from re-enqueueing them anyway.
	//
	// We only persist LastIdentifiedEmail after both enqueues succeed; a
	// failure on Alias means the anonymous-to-email link wasn't recorded,
	// so we want the next invocation to retry it.
	machineId, err := machineid.ID()
	if err == nil && machineId != "" {
		anonymousId := "anonymous_cli_" + machineId
		if err := t.posthogClient.Enqueue(posthog.Alias{
			DistinctId: email,
			Alias:      anonymousId,
		}); err != nil {
			log.Debug().Err(err).Msgf("IdentifyUserIfNeeded: failed to enqueue Alias [email=%s] [anonymousId=%s]", email, anonymousId)
			return
		}
	}

	// Persist that we've identified this email so we don't re-fire on the
	// next CLI invocation. A failure here is non-fatal — the worst case is
	// one extra Identify enqueue on the next run.
	configFile.LastIdentifiedEmail = email
	if err := util.WriteConfigFile(&configFile); err != nil {
		log.Debug().Err(err).Msgf("IdentifyUserIfNeeded: failed to persist LastIdentifiedEmail [email=%s]", email)
	}
}

// IdentityClaimsFromToken reads the identity and organization claims out of an
// Infisical JWT. Nothing from the token itself is kept. Machine identity tokens
// name the organization `orgId`, user session tokens `organizationId`.
//
// Best-effort and silent on failure: returns empty strings for a service token
// (`st.` prefix, not a JWT) or a malformed payload. The signature is not
// verified because the values are only used for telemetry, never authorization.
func IdentityClaimsFromToken(token string) (identityId string, orgId string) {
	if token == "" || strings.HasPrefix(token, "st.") {
		return "", ""
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ""
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some JWT issuers pad the payload with `=`; tolerate that variant.
		payloadBytes, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", ""
		}
	}

	var claims struct {
		IdentityID     string `json:"identityId"`
		OrgID          string `json:"orgId"`
		OrganizationID string `json:"organizationId"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", ""
	}

	if claims.OrgID != "" {
		return claims.IdentityID, claims.OrgID
	}
	return claims.IdentityID, claims.OrganizationID
}

// machineIdentityClaimsFromEnv returns the claims from the first machine-identity
// access token set in the environment (the same set util.GetInfisicalToken checks,
// minus the `--token` flag, which is per-command and not visible here).
func machineIdentityClaimsFromEnv() (identityId string, orgId string) {
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

	for _, name := range envVars {
		if v := os.Getenv(name); v != "" {
			return IdentityClaimsFromToken(v)
		}
	}

	return "", ""
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
	//  1. Actor set by SetActor: the credential the command itself resolved, so it
	//     outranks anything on the machine. Empty for a user session token.
	//  2. Logged-in user email from the persisted config. A logged-in user
	//     takes precedence over any machine-identity token that happens to
	//     be exported in the shell, because some commands never authenticate
	//     against the backend at all (e.g. `infisical user switch`, the
	//     local-config branch of `infisical login`) and others authenticate
	//     with the user's session JWT rather than the env-token. Attributing
	//     those events to a stale `identity-<id>` would corrupt person-level
	//     analytics, while attributing them to the logged-in email is always
	//     correct.
	//  3. Machine-identity access token from env. This is the dominant case
	//     in CI / containers / Kubernetes pods, where there is no logged-in
	//     user and the only credential is `INFISICAL_TOKEN` (or the UA-scoped
	//     env var). Aligns with the `identity-<id>` distinctId the backend
	//     uses for MachineIdentityLogin and other identity-scoped events,
	//     so CLI events flow into the same person record.
	//  4. Anonymous fallback keyed by the local machine ID.
	if t.attachedIdentityId != "" {
		distinctId = "identity-" + t.attachedIdentityId
	} else if accountEmail := util.ActiveAccountEmail(infisicalConfig); accountEmail != "" {
		distinctId = accountEmail
	} else if envIdentityId, _ := machineIdentityClaimsFromEnv(); envIdentityId != "" {
		distinctId = "identity-" + envIdentityId
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

// flushTimeout caps how long a command waits for PostHog before giving up on the event. Without it, an
// unreachable PostHog holds the command for the client's full 10s timeout.
var flushTimeout = 3 * time.Second

// closeWithin sends what is queued and waits at most timeout for it. On timeout the send carries on in the
// background until the process exits.
func (t *Telemetry) closeWithin(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		t.posthogClient.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		log.Debug().Msgf("telemetry: PostHog did not respond within %s, continuing", timeout)
	}
}
