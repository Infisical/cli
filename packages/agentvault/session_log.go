package agentvault

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/rs/zerolog/log"
)

const (
	sessionLogFlushInterval     = 60 * time.Second
	sessionLogFlushSlack        = time.Second
	sessionLogFlushRecords      = 1000
	sessionLogMaxChunkPlaintext = 4 << 20

	sessionLogSpoolCapacity = 5000
	sessionLogTotalCapacity = 200_000

	sessionLogPendingChunks    = 10
	sessionLogTotalSealedBytes = 64 << 20

	sessionLogIdleClose = 15 * time.Minute

	sessionLogPauseBackoff = 15 * time.Minute
	sessionLogPutTimeout   = 10 * time.Second
	sessionLogFinalTimeout = 3 * time.Second
	sessionLogCloseTimeout = 5 * time.Second

	sessionLogCeilingReachedName = "AgentVaultSessionLogCeilingReached"
	sessionLogDisabledName       = "AgentVaultSessionLogDisabled"
	sessionLogClockSkewName      = "AgentVaultSessionLogClockSkew"
)

type sessionLogGrant struct {
	sessionID string
	key       []byte

	issued uint64
}

// Counts every grant the proxy is handed, so a refusal can be told apart from a key issued after it.
var sessionLogGrantsIssued atomic.Uint64

func newSessionLogGrant(sessionID string, key []byte) *sessionLogGrant {
	return &sessionLogGrant{sessionID: sessionID, key: key, issued: sessionLogGrantsIssued.Add(1)}
}

type forgottenSpool struct {
	nextSeq uint64
	dropped uint64
}

type sessionLogShipper interface {
	createChunk(ctx context.Context, final bool, sessionID string, req api.CreateAgentVaultSessionLogChunkRequest) (api.CreateAgentVaultSessionLogChunkResponse, error)
	putObject(ctx context.Context, url string, ciphertext []byte) error
}

type sessionLogRecorder struct {
	proxyID string
	shipper sessionLogShipper
	now     func() time.Time

	// close's flushAll can overlap the run loop's; unguarded, one chunk ships twice.
	flushMu sync.Mutex

	mu     sync.Mutex
	spools map[string]*sessionLogSpool

	forgotten map[string]forgottenSpool

	total         int
	sealedBytes   int
	nextSealOrder uint64

	pauseUntil time.Time

	switchedOff        bool
	switchedOffThrough uint64

	s3Down        bool
	infisicalDown bool

	clockSkewReported bool

	closed bool
	wake   chan struct{}
}

func newSessionLogRecorder(proxyID string, shipper sessionLogShipper) *sessionLogRecorder {
	return &sessionLogRecorder{
		proxyID:   proxyID,
		shipper:   shipper,
		now:       time.Now,
		spools:    make(map[string]*sessionLogSpool),
		forgotten: make(map[string]forgottenSpool),
		wake:      make(chan struct{}, 1),
	}
}

func (a *sessionLogRecorder) record(g *sessionLogGrant, rec sessionLogRecord) {
	if a == nil || g == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}

	spool, ok := a.spools[g.sessionID]
	if !ok {
		spool = newSessionLogSpool(g, a.now())
		if prior, ok := a.forgotten[g.sessionID]; ok {
			spool.nextSeq, spool.ring.dropped = prior.nextSeq, prior.dropped
			delete(a.forgotten, g.sessionID)
		}
		a.spools[g.sessionID] = spool
	}

	rec.Seq = spool.nextSeq
	spool.nextSeq++
	rec.ProxyID = a.proxyID
	rec.Ts = a.now().UTC().Format(time.RFC3339Nano)
	spool.lastRecordAt = a.now()

	if a.switchedOff {
		if g.issued <= a.switchedOffThrough {
			spool.ring.dropped++
			return
		}
		a.switchedOff = false
		log.Info().Msg("agent-vault: session logs are back on, recording again")
	}

	if !a.pauseUntil.IsZero() && a.now().Before(a.pauseUntil) {
		spool.ring.dropped++
		return
	}

	if a.total >= sessionLogTotalCapacity {
		spool.ring.dropped++
		return
	}

	if evicted := spool.ring.push(rec); !evicted {
		a.total++
	}

	if spool.ring.len() >= sessionLogFlushRecords {
		select {
		case a.wake <- struct{}{}:
		default:
		}
	}
}

func (a *sessionLogRecorder) run(stop <-chan struct{}) {
	if a == nil {
		return
	}
	ticker := time.NewTicker(sessionLogFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			a.flushAll(context.Background(), false)
		case <-a.wake:
			a.flushAll(context.Background(), false)
		}
	}
}

func (a *sessionLogRecorder) close(ctx context.Context) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()

	a.flushAll(ctx, true)

	a.mu.Lock()
	defer a.mu.Unlock()
	var lost int
	for _, spool := range a.spools {
		lost += spool.ring.len()
		for _, chunk := range spool.pending {
			lost += chunk.meta.RecordCount
		}
	}
	if lost > 0 {
		log.Warn().Int("records", lost).Msg("agent-vault: session log records were not shipped before shutdown")
	}
}

func (a *sessionLogRecorder) dueSpools(final bool, now time.Time) []*sessionLogSpool {
	a.mu.Lock()
	defer a.mu.Unlock()

	due := make([]*sessionLogSpool, 0, len(a.spools))
	for id, spool := range a.spools {
		if spool.ring.len() == 0 && len(spool.pending) == 0 {
			if !final && now.Sub(spool.lastRecordAt) > sessionLogIdleClose {
				a.forgetSpoolLocked(id, spool)
			}
			continue
		}
		// The slack absorbs ticker jitter: without it a spool stamped at one tick is a hair short of due at the next.
		if final || spool.ring.len() >= sessionLogFlushRecords || len(spool.pending) > 0 ||
			(spool.ring.len() > 0 && now.Sub(spool.lastFlushAt) >= sessionLogFlushInterval-sessionLogFlushSlack) {
			due = append(due, spool)
		}
	}
	return due
}

// Keeps the drop count too, so a spool forgotten while logging was off still reports what it lost.
func (a *sessionLogRecorder) forgetSpoolLocked(sessionID string, spool *sessionLogSpool) {
	if len(a.forgotten) >= maxSessionCacheEntries {
		a.forgotten = make(map[string]forgottenSpool)
	}
	a.forgotten[sessionID] = forgottenSpool{nextSeq: spool.nextSeq, dropped: spool.ring.dropped}
	delete(a.spools, sessionID)
}

func (a *sessionLogRecorder) holding() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.switchedOff || (!a.pauseUntil.IsZero() && a.now().Before(a.pauseUntil))
}

func (a *sessionLogRecorder) pause() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pauseUntil = a.now().Add(sessionLogPauseBackoff)
}

// Drops everything held and counts it. A key issued after the refused request went out means logging may already
// be back on, so then the refusal is stale and nothing is dropped.
func (a *sessionLogRecorder) switchOff(grantsIssuedAtSend uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if sessionLogGrantsIssued.Load() > grantsIssuedAtSend {
		return
	}

	var lost int
	for _, spool := range a.spools {
		held := spool.ring.len()
		spool.ring.drain(held)
		spool.ring.dropped += uint64(held)
		a.total -= held
		lost += held
		for _, chunk := range spool.pending {
			spool.ring.dropped += chunk.lostCount()
			a.sealedBytes -= len(chunk.ciphertext)
			lost += chunk.meta.RecordCount
		}
		spool.pending = nil
	}

	if !a.switchedOff {
		log.Warn().Int("records", lost).
			Msg("agent-vault: session logs are off for this project, dropping what was held until they are back on")
	}
	a.switchedOff = true
	a.switchedOffThrough = grantsIssuedAtSend
}

func (a *sessionLogRecorder) flushAll(ctx context.Context, final bool) {
	if a == nil {
		return
	}

	a.flushMu.Lock()
	defer a.flushMu.Unlock()

	a.mu.Lock()
	a.s3Down = false
	a.infisicalDown = false
	a.mu.Unlock()

	// One start time for every spool, so shipping the earlier ones doesn't make the later ones late for the next tick.
	started := a.now()
	for _, spool := range a.dueSpools(final, started) {
		a.flushSpool(ctx, spool, final, started)
	}
}

func (a *sessionLogRecorder) sealRing(spool *sessionLogSpool, started time.Time) {
	for {
		a.mu.Lock()
		records := spool.ring.drain(sessionLogFlushRecords)
		if len(records) == 0 {
			spool.lastFlushAt = started
			a.mu.Unlock()
			return
		}
		a.total -= len(records)
		dropped := spool.ring.takeDropped()
		now := a.now()
		a.mu.Unlock()

		groups, err := packSessionLogRecords(records)
		if err != nil {
			a.dropUnsealed(spool, len(records), dropped, err)
			continue
		}
		for i, group := range groups {
			var groupDropped uint64
			if i == 0 {
				groupDropped = dropped
			}

			chunk, err := spool.sealSlice(group.records, group.plaintext, groupDropped, now)
			if err != nil {
				a.dropUnsealed(spool, len(group.records), groupDropped, err)
				continue
			}

			a.mu.Lock()
			chunk.sealOrder = a.nextSealOrder
			a.nextSealOrder++
			spool.pending = append(spool.pending, chunk)
			a.sealedBytes += len(chunk.ciphertext)
			a.enforcePendingCapsLocked(spool)
			a.mu.Unlock()
		}
	}
}

func (a *sessionLogRecorder) dropUnsealed(spool *sessionLogSpool, records int, dropped uint64, err error) {
	a.mu.Lock()
	spool.ring.dropped += dropped + uint64(records)
	a.mu.Unlock()
	log.Error().Err(err).Str("sessionId", spool.sessionID).Int("records", records).
		Msg("agent-vault: could not seal a session log chunk, dropping those records")
}

func (a *sessionLogRecorder) enforcePendingCapsLocked(spool *sessionLogSpool) {
	for len(spool.pending) > sessionLogPendingChunks {
		a.evictOldestLocked(spool)
	}
	for a.sealedBytes > sessionLogTotalSealedBytes {
		victim := a.oldestPendingLocked()
		if victim == nil {
			return
		}
		a.evictOldestLocked(victim)
	}
}

func (a *sessionLogRecorder) oldestPendingLocked() *sessionLogSpool {
	var oldest *sessionLogSpool
	for _, spool := range a.spools {
		if len(spool.pending) == 0 {
			continue
		}
		if oldest == nil || spool.pending[0].sealOrder < oldest.pending[0].sealOrder {
			oldest = spool
		}
	}
	return oldest
}

func (a *sessionLogRecorder) evictOldestLocked(spool *sessionLogSpool) {
	oldest := spool.pending[0]
	spool.pending = spool.pending[1:]
	a.sealedBytes -= len(oldest.ciphertext)
	spool.ring.dropped += oldest.lostCount()
	log.Warn().
		Str("sessionId", spool.sessionID).
		Str("chunkId", oldest.meta.ChunkID).
		Int("records", oldest.meta.RecordCount).
		Msg("agent-vault: dropped an unshipped session log chunk, the buffer is full")
}

func (a *sessionLogRecorder) flushSpool(ctx context.Context, spool *sessionLogSpool, final bool, started time.Time) {
	a.sealRing(spool, started)
	if a.holding() {
		return
	}

	for {
		a.mu.Lock()
		if len(spool.pending) == 0 || a.s3Down || a.infisicalDown {
			a.mu.Unlock()
			return
		}
		chunk := spool.pending[0]
		a.mu.Unlock()

		if !a.shipChunk(ctx, spool, chunk, final) {
			return
		}

		a.mu.Lock()
		if len(spool.pending) > 0 && spool.pending[0] == chunk {
			spool.pending = spool.pending[1:]
			a.sealedBytes -= len(chunk.ciphertext)
		}
		a.mu.Unlock()
	}
}

func (a *sessionLogRecorder) shipChunk(ctx context.Context, spool *sessionLogSpool, chunk *sealedChunk, final bool) bool {
	if chunk.uploadURL == "" || a.now().Add(10*time.Second).After(chunk.urlExpires) {
		// Past the shutdown budget, a new row could only be written for an upload that can no longer happen.
		if ctx.Err() != nil {
			return false
		}
		grantsIssuedAtSend := sessionLogGrantsIssued.Load()
		res, err := a.shipper.createChunk(ctx, final, spool.sessionID, chunk.meta)
		if err != nil {
			return a.handleCreateFailure(spool, chunk, err, grantsIssuedAtSend)
		}
		a.mu.Lock()
		a.clockSkewReported = false
		a.mu.Unlock()
		chunk.posted = true
		chunk.uploadURL = res.UploadURL
		chunk.urlExpires = a.now().Add(time.Duration(res.ExpiresInSeconds) * time.Second)
	}

	putCtx := ctx
	if !final {
		var cancel context.CancelFunc
		putCtx, cancel = context.WithTimeout(ctx, sessionLogPutTimeout)
		defer cancel()
	}

	if err := a.shipper.putObject(putCtx, chunk.uploadURL, chunk.ciphertext); err != nil {
		chunk.uploadURL = ""
		a.mu.Lock()
		a.s3Down = true
		a.mu.Unlock()
		log.Warn().Err(err).Str("sessionId", spool.sessionID).Str("chunkId", chunk.meta.ChunkID).
			Msg("agent-vault: could not upload a session log chunk, will retry")
		return false
	}

	return true
}

func (a *sessionLogRecorder) handleCreateFailure(spool *sessionLogSpool, chunk *sealedChunk, err error, grantsIssuedAtSend uint64) bool {
	switch {
	case isProxyTokenRejected(err):
		log.Warn().Err(err).Msg("agent-vault: Infisical rejected this proxy's token, holding session logs")
		return false

	case isSessionGone(err):
		a.mu.Lock()
		lost := spool.ring.len()
		a.total -= spool.ring.len()
		for _, held := range spool.pending {
			lost += held.meta.RecordCount
			a.sealedBytes -= len(held.ciphertext)
		}
		a.forgetSpoolLocked(spool.sessionID, spool)
		delete(a.forgotten, spool.sessionID)
		a.mu.Unlock()
		log.Warn().Err(err).Str("sessionId", spool.sessionID).Int("records", lost).
			Msg("agent-vault: Infisical no longer accepts session logs for this session, dropping what was held")
		return false

	case isSessionLogErrorNamed(err, sessionLogCeilingReachedName):
		a.pause()
		log.Error().Err(err).Msg("agent-vault: session logs have reached their limit for this organization, retrying in 15m")
		return false

	case isSessionLogErrorNamed(err, sessionLogDisabledName):
		a.switchOff(grantsIssuedAtSend)
		return false

	case isSessionLogErrorNamed(err, sessionLogClockSkewName):
		a.dropRefused(spool, chunk)
		a.mu.Lock()
		reported := a.clockSkewReported
		a.clockSkewReported = true
		a.mu.Unlock()
		if !reported {
			log.Error().Err(err).Msg("agent-vault: session logs are being refused because this machine's clock is wrong; fix the clock to resume recording")
		}
		return false

	case isPoisonChunk(err):
		a.dropRefused(spool, chunk)
		log.Error().Err(err).Str("chunkId", chunk.meta.ChunkID).Int("records", chunk.meta.RecordCount).
			Msg("agent-vault: Infisical rejected a session log chunk as malformed, dropping it")
		return false

	default:
		a.mu.Lock()
		a.infisicalDown = true
		a.mu.Unlock()
		log.Warn().Err(err).Str("sessionId", spool.sessionID).
			Msg("agent-vault: could not record session logs, will retry")
		return false
	}
}

func (a *sessionLogRecorder) dropRefused(spool *sessionLogSpool, chunk *sealedChunk) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(spool.pending) > 0 && spool.pending[0] == chunk {
		spool.pending = spool.pending[1:]
		a.sealedBytes -= len(chunk.ciphertext)
		// Counted as dropped, or an agent that gets its own chunk refused could erase what it did.
		spool.ring.dropped += chunk.lostCount()
	}
}
