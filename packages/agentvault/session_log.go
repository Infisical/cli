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
)

type sessionLogGrant struct {
	sessionID string
	key       []byte

	issued uint64
}

// Resolve only hands out a grant while session logs are on. So a grant issued after a refused request went
// out means logs came back on after that request, and the refusal is stale.
var sessionLogGrantsIssued atomic.Uint64

func newSessionLogGrant(sessionID string, key []byte) *sessionLogGrant {
	return &sessionLogGrant{sessionID: sessionID, key: key, issued: sessionLogGrantsIssued.Add(1)}
}

type forgottenSpool struct {
	nextSeq     uint64
	dropped     uint64
	forgottenAt time.Time
}

type sessionLogShipper interface {
	createChunk(ctx context.Context, final bool, sessionID string, req api.CreateAgentVaultSessionLogChunkRequest) (api.CreateAgentVaultSessionLogChunkResponse, error)
	putObject(ctx context.Context, url string, ciphertext []byte) error
}

// Being off or paused also drops new records, while an outage only holds them until the next retry.
type sessionLogHold struct {
	off        bool
	offThrough uint64

	pausedUntil time.Time

	s3Down        bool
	infisicalDown bool
}

func (h *sessionLogHold) dropsRecords(now time.Time) bool {
	return h.off || now.Before(h.pausedUntil)
}

func (h *sessionLogHold) canShip(now time.Time) bool {
	return !h.dropsRecords(now) && !h.s3Down && !h.infisicalDown
}

func (h *sessionLogHold) clearOutages() {
	h.s3Down = false
	h.infisicalDown = false
}

type sessionLogRecorder struct {
	proxyID string
	shipper sessionLogShipper
	now     func() time.Time

	// close's flush can overlap the run loop's; unguarded, one chunk ships twice.
	flushMu sync.Mutex

	mu     sync.Mutex
	spools map[string]*sessionLogSpool

	forgotten map[string]forgottenSpool

	total         int
	sealedBytes   int
	nextSealOrder uint64

	hold sessionLogHold

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

func (r *sessionLogRecorder) record(g *sessionLogGrant, rec sessionLogRecord) {
	if r == nil || g == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}

	spool, ok := r.spools[g.sessionID]
	if !ok {
		spool = newSessionLogSpool(g, r.now())
		if prior, ok := r.forgotten[g.sessionID]; ok {
			spool.nextSeq, spool.ring.dropped = prior.nextSeq, prior.dropped
			delete(r.forgotten, g.sessionID)
		}
		r.spools[g.sessionID] = spool
	}

	rec.Seq = spool.nextSeq
	spool.nextSeq++
	rec.ProxyID = r.proxyID
	now := r.now()
	// Without the monotonic reading, Before and After compare wall time, which is what Ts shows.
	rec.at = now.Round(0)
	rec.Ts = rec.at.UTC().Format(time.RFC3339Nano)
	spool.lastRecordAt = now

	if r.hold.off {
		if g.issued <= r.hold.offThrough {
			spool.ring.dropped++
			return
		}
		r.hold.off = false
		log.Info().Msg("agent-vault: session logs are back on, recording again")
	}

	if now.Before(r.hold.pausedUntil) {
		spool.ring.dropped++
		return
	}

	if r.total >= sessionLogTotalCapacity {
		spool.ring.dropped++
		return
	}

	if evicted := spool.ring.push(rec); !evicted {
		r.total++
	}

	if spool.ring.len() >= sessionLogFlushRecords {
		select {
		case r.wake <- struct{}{}:
		default:
		}
	}
}

func (r *sessionLogRecorder) run(stop <-chan struct{}) {
	if r == nil {
		return
	}
	ticker := time.NewTicker(sessionLogFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			r.flush(context.Background(), flushTick)
		case <-r.wake:
			r.flush(context.Background(), flushWake)
		}
	}
}

func (r *sessionLogRecorder) close(ctx context.Context) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()

	r.flush(ctx, flushFinal)

	r.mu.Lock()
	defer r.mu.Unlock()
	var lost int
	for _, spool := range r.spools {
		lost += spool.heldRecords()
	}
	if lost > 0 {
		log.Warn().Int("records", lost).Msg("agent-vault: session log records were not shipped before shutdown")
	}
}

func (r *sessionLogRecorder) dueSpools(pass flushPass, now time.Time) []*sessionLogSpool {
	r.mu.Lock()
	defer r.mu.Unlock()

	final := pass == flushFinal
	due := make([]*sessionLogSpool, 0, len(r.spools))
	for id, spool := range r.spools {
		if pass == flushWake {
			if spool.ring.len() >= sessionLogFlushRecords {
				due = append(due, spool)
			}
			continue
		}
		if spool.ring.len() == 0 && len(spool.pending) == 0 {
			if !final && now.Sub(spool.lastRecordAt) > sessionLogIdleClose {
				r.forgetSpoolLocked(id, spool)
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
func (r *sessionLogRecorder) forgetSpoolLocked(sessionID string, spool *sessionLogSpool) {
	if len(r.forgotten) >= maxSessionCacheEntries {
		r.evictLongestForgottenLocked()
	}
	r.forgotten[sessionID] = forgottenSpool{nextSeq: spool.nextSeq, dropped: spool.ring.dropped, forgottenAt: r.now()}
	delete(r.spools, sessionID)
}

func (r *sessionLogRecorder) evictLongestForgottenLocked() {
	var oldestID string
	var oldestAt time.Time
	found := false
	for id, prior := range r.forgotten {
		if !found || prior.forgottenAt.Before(oldestAt) {
			oldestID, oldestAt, found = id, prior.forgottenAt, true
		}
	}
	delete(r.forgotten, oldestID)
}

func (r *sessionLogRecorder) pause() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hold.pausedUntil = r.now().Add(sessionLogPauseBackoff)
}

// Drops everything held and counts it, unless a grant was issued after the refused request went out, which
// makes the refusal stale (see sessionLogGrantsIssued).
func (r *sessionLogRecorder) switchOff(grantsIssuedAtSend uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sessionLogGrantsIssued.Load() > grantsIssuedAtSend {
		return
	}

	var lost int
	for _, spool := range r.spools {
		lost += r.discardAllLocked(spool, true)
	}

	if !r.hold.off {
		log.Warn().Int("records", lost).
			Msg("agent-vault: session logs are off for this project, dropping what was held until they are back on")
	}
	r.hold.off = true
	r.hold.offThrough = grantsIssuedAtSend
}

// A gone session passes countDropped false: its spool is deleted, so no later chunk could report the loss.
func (r *sessionLogRecorder) discardAllLocked(spool *sessionLogSpool, countDropped bool) (lost int) {
	lost = spool.heldRecords()

	held := spool.ring.len()
	spool.ring.drain(held)
	r.total -= held
	if countDropped {
		spool.ring.dropped += uint64(held)
	}

	for _, chunk := range spool.pending {
		r.sealedBytes -= len(chunk.ciphertext)
		if countDropped {
			spool.ring.dropped += chunk.lostCount()
		}
	}
	spool.pending = nil
	return lost
}

func (r *sessionLogRecorder) discardHeadLocked(spool *sessionLogSpool, chunk *sealedChunk, countDropped bool) bool {
	if len(spool.pending) == 0 || spool.pending[0] != chunk {
		return false
	}
	spool.popPending()
	r.sealedBytes -= len(chunk.ciphertext)
	if countDropped {
		spool.ring.dropped += chunk.lostCount()
	}
	return true
}

type flushPass int

const (
	flushTick flushPass = iota
	flushWake
	flushFinal
)

func (r *sessionLogRecorder) flush(ctx context.Context, pass flushPass) {
	if r == nil {
		return
	}

	r.flushMu.Lock()
	defer r.flushMu.Unlock()

	// A busy session wakes the loop every thousand records, so resetting here would retry a down bucket or
	// Infisical that often instead of once a minute.
	if pass != flushWake {
		r.mu.Lock()
		r.hold.clearOutages()
		r.mu.Unlock()
	}

	// One start time for every spool, so shipping the earlier ones doesn't make the later ones late for the next tick.
	started := r.now()
	for _, spool := range r.dueSpools(pass, started) {
		r.flushSpool(ctx, spool, pass, started)
	}
}

func (r *sessionLogRecorder) sealRing(spool *sessionLogSpool, started time.Time) {
	for {
		r.mu.Lock()
		records := spool.ring.drain(sessionLogFlushRecords)
		if len(records) == 0 {
			spool.lastFlushAt = started
			r.mu.Unlock()
			return
		}
		r.total -= len(records)
		dropped := spool.ring.takeDropped()
		r.mu.Unlock()

		groups, err := packSessionLogRecords(records)
		if err != nil {
			r.dropUnsealed(spool, len(records), dropped, err)
			continue
		}
		for i, group := range groups {
			var groupDropped uint64
			if i == 0 {
				groupDropped = dropped
			}

			chunk, err := spool.sealSlice(group.records, group.plaintext, groupDropped)
			if err != nil {
				r.dropUnsealed(spool, len(group.records), groupDropped, err)
				continue
			}

			r.mu.Lock()
			chunk.sealOrder = r.nextSealOrder
			r.nextSealOrder++
			spool.pending = append(spool.pending, chunk)
			r.sealedBytes += len(chunk.ciphertext)
			r.enforcePendingCapsLocked(spool)
			r.mu.Unlock()
		}
	}
}

func (r *sessionLogRecorder) dropUnsealed(spool *sessionLogSpool, records int, dropped uint64, err error) {
	r.mu.Lock()
	spool.ring.dropped += dropped + uint64(records)
	r.mu.Unlock()
	log.Error().Err(err).Str("sessionId", spool.sessionID).Int("records", records).
		Msg("agent-vault: could not seal a session log chunk, dropping those records")
}

func (r *sessionLogRecorder) enforcePendingCapsLocked(spool *sessionLogSpool) {
	for len(spool.pending) > sessionLogPendingChunks {
		r.evictOldestLocked(spool)
	}
	for r.sealedBytes > sessionLogTotalSealedBytes {
		victim := r.oldestPendingLocked()
		if victim == nil {
			return
		}
		r.evictOldestLocked(victim)
	}
}

func (r *sessionLogRecorder) oldestPendingLocked() *sessionLogSpool {
	var oldest *sessionLogSpool
	for _, spool := range r.spools {
		if len(spool.pending) == 0 {
			continue
		}
		if oldest == nil || spool.pending[0].sealOrder < oldest.pending[0].sealOrder {
			oldest = spool
		}
	}
	return oldest
}

func (r *sessionLogRecorder) evictOldestLocked(spool *sessionLogSpool) {
	oldest := spool.pending[0]
	r.discardHeadLocked(spool, oldest, true)
	log.Warn().
		Str("sessionId", spool.sessionID).
		Str("chunkId", oldest.meta.ChunkID).
		Int("records", oldest.meta.RecordCount).
		Msg("agent-vault: dropped an unshipped session log chunk, the buffer is full")
}

func (r *sessionLogRecorder) flushSpool(ctx context.Context, spool *sessionLogSpool, pass flushPass, started time.Time) {
	r.sealRing(spool, started)

	for {
		r.mu.Lock()
		if len(spool.pending) == 0 || !r.hold.canShip(r.now()) {
			r.mu.Unlock()
			return
		}
		chunk := spool.pending[0]
		r.mu.Unlock()

		if !r.shipChunk(ctx, spool, chunk, pass) {
			return
		}

		r.mu.Lock()
		r.discardHeadLocked(spool, chunk, false)
		r.mu.Unlock()
	}
}

func (r *sessionLogRecorder) shipChunk(ctx context.Context, spool *sessionLogSpool, chunk *sealedChunk, pass flushPass) bool {
	final := pass == flushFinal
	if chunk.uploadURL == "" || r.now().Add(10*time.Second).After(chunk.urlExpires) {
		// Past the shutdown budget, a new row could only be written for an upload that can no longer happen.
		if ctx.Err() != nil {
			return false
		}
		grantsIssuedAtSend := sessionLogGrantsIssued.Load()
		res, err := r.shipper.createChunk(ctx, final, spool.sessionID, chunk.meta)
		if err != nil {
			return r.handleCreateFailure(spool, chunk, err, grantsIssuedAtSend)
		}
		r.mu.Lock()
		r.clockSkewReported = false
		r.mu.Unlock()
		chunk.posted = true
		chunk.uploadURL = res.UploadURL
		chunk.urlExpires = r.now().Add(time.Duration(res.ExpiresInSeconds) * time.Second)
	}

	putCtx := ctx
	if !final {
		var cancel context.CancelFunc
		putCtx, cancel = context.WithTimeout(ctx, sessionLogPutTimeout)
		defer cancel()
	}

	if err := r.shipper.putObject(putCtx, chunk.uploadURL, chunk.ciphertext); err != nil {
		chunk.uploadURL = ""
		r.mu.Lock()
		r.hold.s3Down = true
		r.mu.Unlock()
		log.Warn().Err(err).Str("sessionId", spool.sessionID).Str("chunkId", chunk.meta.ChunkID).
			Msg("agent-vault: could not upload a session log chunk, will retry")
		return false
	}

	return true
}

func (r *sessionLogRecorder) handleCreateFailure(spool *sessionLogSpool, chunk *sealedChunk, err error, grantsIssuedAtSend uint64) bool {
	switch classifyChunkError(err) {
	case chunkTokenRejected:
		log.Warn().Err(err).Msg("agent-vault: Infisical rejected this proxy's token, holding session logs")

	case chunkSessionGone:
		r.mu.Lock()
		lost := r.discardAllLocked(spool, false)
		delete(r.spools, spool.sessionID)
		r.mu.Unlock()
		log.Warn().Err(err).Str("sessionId", spool.sessionID).Int("records", lost).
			Msg("agent-vault: Infisical no longer accepts session logs for this session, dropping what was held")

	case chunkOrgFull:
		r.pause()
		log.Error().Err(err).Msg("agent-vault: session logs have reached their limit for this organization, retrying in 15m")

	case chunkLoggingOff:
		r.switchOff(grantsIssuedAtSend)

	case chunkClockSkew:
		r.dropRefused(spool, chunk)
		r.mu.Lock()
		reported := r.clockSkewReported
		r.clockSkewReported = true
		r.mu.Unlock()
		if !reported {
			log.Error().Err(err).Msg("agent-vault: session logs are being refused because this machine's clock is wrong; fix the clock to resume recording")
		}

	case chunkRefused:
		r.dropRefused(spool, chunk)
		log.Error().Err(err).Str("chunkId", chunk.meta.ChunkID).Int("records", chunk.meta.RecordCount).
			Msg("agent-vault: Infisical refused a session log chunk, dropping it")

	case chunkRetry:
		r.mu.Lock()
		r.hold.infisicalDown = true
		r.mu.Unlock()
		log.Warn().Err(err).Str("sessionId", spool.sessionID).
			Msg("agent-vault: could not record session logs, will retry")
	}
	return false
}

func (r *sessionLogRecorder) dropRefused(spool *sessionLogSpool, chunk *sealedChunk) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Counted as dropped, or an agent that gets its own chunk refused could erase what it did.
	r.discardHeadLocked(spool, chunk, true)
}
