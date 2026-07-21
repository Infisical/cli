package gatewayv2

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

// webAppFrameEnvelope is the JSON envelope stored in SessionEvent.Data for a
// recorded web-app frame (mirrors the RDP frame envelope). json.Marshal
// base64-encodes the []byte payload.
type webAppFrameEnvelope struct {
	Payload   []byte `json:"payload"`   // JPEG bytes
	ElapsedNs uint64 `json:"elapsedNs"` // ns since session start, for replay ordering
}

// recFrame is one captured frame queued for recording, stamped at capture time so
// replay timing stays accurate regardless of how far behind the recorder runs.
type recFrame struct {
	data []byte
	at   time.Time
}

// webAppRecorder tees screencast frames into the same tamper-proof, encrypted,
// chunked recording pipeline that RDP/SSH use. Every emitted frame is recorded:
// the screencast is event-driven, so that's one frame per visual change.
type webAppRecorder struct {
	sessionID      string
	logger         *session.EncryptedSessionLogger
	uploader       *session.SessionUploader
	sessionStart   time.Time
	priorElapsedNs uint64
}

// newWebAppRecorder wires up the recorder for a session. Fetching credentials is
// what triggers the backend to mint the per-session recording key + upload token
// (the same trigger RDP relies on).
func newWebAppRecorder(pamConfig *pam.GatewayPAMConfig) (*webAppRecorder, error) {
	if pamConfig.CredentialsManager == nil || pamConfig.SessionUploader == nil {
		return nil, fmt.Errorf("missing credentials manager or session uploader")
	}
	if _, err := pamConfig.CredentialsManager.GetPAMSessionCredentials(pamConfig.SessionId, pamConfig.ExpiryTime); err != nil {
		return nil, fmt.Errorf("get session credentials: %w", err)
	}
	encryptionKey, err := pamConfig.CredentialsManager.GetPAMSessionEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("get encryption key: %w", err)
	}
	// Masking is skipped for the web-app channel (binary JPEG), so pass no patterns.
	logger, err := session.NewSessionLogger(pamConfig.SessionId, encryptionKey, pamConfig.ExpiryTime, pamConfig.ResourceType, nil)
	if err != nil {
		return nil, fmt.Errorf("new session logger: %w", err)
	}
	pamConfig.SessionUploader.RegisterSession(pamConfig.SessionId)

	return &webAppRecorder{
		sessionID:      pamConfig.SessionId,
		logger:         logger,
		uploader:       pamConfig.SessionUploader,
		sessionStart:   time.Now(),
		priorElapsedNs: pamConfig.SessionUploader.GetPriorElapsedNs(pamConfig.SessionId),
	}, nil
}

// record persists a single captured frame. `at` is when the frame was captured,
// used to compute the replay timestamp. Called from a single recording goroutine.
func (r *webAppRecorder) record(frame []byte, at time.Time) {
	elapsedNs := r.priorElapsedNs + uint64(at.Sub(r.sessionStart).Nanoseconds())
	envelope, err := json.Marshal(webAppFrameEnvelope{Payload: frame, ElapsedNs: elapsedNs})
	if err != nil {
		return
	}
	if err := r.logger.LogSessionEvent(session.SessionEvent{
		Timestamp:   at,
		EventType:   session.SessionEventWebApp,
		ChannelType: session.SessionChannelWebApp,
		Data:        envelope,
		ElapsedTime: float64(elapsedNs) / 1e9,
	}); err != nil {
		log.Warn().Err(err).Str("sessionId", r.sessionID).Msg("web-app: failed to record frame")
		return
	}
	r.uploader.RecordEmittedElapsedNs(r.sessionID, elapsedNs)
}

// close flushes and finalizes the recording.
func (r *webAppRecorder) close() {
	if err := r.logger.Close(); err != nil {
		log.Warn().Err(err).Str("sessionId", r.sessionID).Msg("web-app: failed to close recorder")
	}
	if err := r.uploader.CleanupPAMSession(r.sessionID, "session_end"); err != nil {
		log.Warn().Err(err).Str("sessionId", r.sessionID).Msg("web-app: failed to finalize recording")
	}
}
