package agentproxy

import (
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

const (
	// A flush per request would turn one brokered call into two, so records are buffered and sent on a timer.
	recordFlushInterval = 5 * time.Second
	// Flushed early once this many are pending, so a busy agent sends more batches rather than bigger ones.
	recordBatchSize = 50
	// The ceiling if the backend is unreachable. Oldest records are dropped rather than growing without
	// bound: a recording is worth having, and never worth an out-of-memory in the broker.
	recordBufferLimit = 2000

	recordFlushTimeout = 10 * time.Second
)

// recorder buffers the per-request records that make up a session's recording, keyed by session because one
// broker serves many and each recording belongs to exactly one of them.
type recorder struct {
	token func() string

	mu       sync.Mutex
	pending  map[string][]api.AgentGatewaySessionRequest
	dropped  map[string]int
	flushing sync.Mutex
	warnOnce sync.Once
}

func newRecorder(token func() string) *recorder {
	return &recorder{
		token:   token,
		pending: make(map[string][]api.AgentGatewaySessionRequest),
		dropped: make(map[string]int),
	}
}

// record adds one request to a session's recording and reports whether a flush is now due.
func (r *recorder) record(sessionID string, request api.AgentGatewaySessionRequest) bool {
	if r == nil || sessionID == "" {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	queue := r.pending[sessionID]
	if len(queue) >= recordBufferLimit {
		// Drop the oldest: the tail is what someone reviewing a live session is looking at.
		queue = queue[1:]
		r.dropped[sessionID]++
	}
	r.pending[sessionID] = append(queue, request)

	return len(r.pending[sessionID]) >= recordBatchSize
}

// flush sends every session's pending records. A failed batch is put back so a transient backend problem
// delays the recording rather than losing it.
func (r *recorder) flush() {
	if r == nil || r.token == nil {
		return
	}

	// One flush at a time, so a slow backend cannot have two flushes racing over the same buffer.
	if !r.flushing.TryLock() {
		return
	}
	defer r.flushing.Unlock()

	r.mu.Lock()
	if len(r.pending) == 0 {
		r.mu.Unlock()
		return
	}
	batch := r.pending
	dropped := r.dropped
	r.pending = make(map[string][]api.AgentGatewaySessionRequest)
	r.dropped = make(map[string]int)
	r.mu.Unlock()

	for sessionID, count := range dropped {
		log.Warn().Msgf(
			"agent gateway: dropped %d recorded requests for session %s because the backend was not keeping up",
			count,
			sessionID,
		)
	}

	client := resty.New().SetAuthToken(r.token()).SetTimeout(recordFlushTimeout)
	for sessionID, requests := range batch {
		if err := api.CallRecordAgentGatewaySessionRequests(client, sessionID, requests); err != nil {
			// Warn once: the usual cause is a session that has ended, which fails every attempt.
			r.warnOnce.Do(func() {
				log.Warn().Err(err).Msg("cannot record session activity, so this session's recording will be incomplete")
			})
			log.Debug().Err(err).Msgf("failed to record session requests [sessionId=%s]", sessionID)

			r.mu.Lock()
			// Re-queued at the front, since these happened before anything buffered while the flush ran.
			r.pending[sessionID] = append(requests, r.pending[sessionID]...)
			if len(r.pending[sessionID]) > recordBufferLimit {
				overflow := len(r.pending[sessionID]) - recordBufferLimit
				r.pending[sessionID] = r.pending[sessionID][overflow:]
				r.dropped[sessionID] += overflow
			}
			r.mu.Unlock()
		}
	}
}
