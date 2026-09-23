package agentvault

import (
	"context"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/rs/zerolog/log"
)

const (
	// The cost knob is this interval, not traffic volume: one flush is one S3 PUT. At 60s a session running
	// flat out costs about 1,440 PUTs a day; flushing every 5s would be twelve times the bill for the same
	// records.
	activityFlushInterval = 60 * time.Second
	// The server refuses a chunk over this, so the ring is drained in slices of at most this many.
	activityFlushRecords = 1000

	// Five missed flushes of headroom per session before the oldest records start being overwritten.
	activitySpoolCapacity = 5000
	// A fuse across every session on this proxy, roughly 60 MB of records.
	activityTotalCapacity = 200_000

	// Sealed chunks kept per spool while shipping fails. One chunk seals per tick during an outage, so this
	// is about ten minutes of Infisical or S3 being unreachable before a busy session loses its oldest
	// sealed chunk. Deliberate for a preview with no disk persistence: raise this rather than the interval.
	activityPendingChunks = 10
	// A second fuse, on sealed ciphertext rather than record count, across every spool.
	activityTotalSealedBytes = 64 << 20

	// Longer than sessionInactiveTTL, so a session evicted from the cache still gets its final flush.
	activityIdleClose = 15 * time.Minute

	activityPauseBackoff = 15 * time.Minute
	activityPutTimeout   = 10 * time.Second
	activityFinalTimeout = 3 * time.Second

	// Read off APIError.Name. Defined by the backend in agent-vault-activity-constants.ts.
	activityCeilingReachedName = "AgentVaultActivityCeilingReached"
	activityDisabledName       = "AgentVaultActivityDisabled"
)

// activityGrant is what resolve hands back when logging is on for a session. A nil grant means "do not
// record", which is the whole of the disabled path.
type activityGrant struct {
	sessionID string
	projectID string
	key       []byte
}

// activityShipper is the seam the tests replace. Two calls, because delivery is two steps: Infisical
// writes the index row and returns a presigned URL, then the bytes go straight to the customer's bucket.
type activityShipper interface {
	createChunk(final bool, sessionID string, req api.CreateAgentVaultActivityChunkRequest) (api.CreateAgentVaultActivityChunkResponse, error)
	putObject(ctx context.Context, url string, ciphertext []byte) error
}

type activityLog struct {
	proxyID string
	shipper activityShipper
	now     func() time.Time

	// Held for the whole of flushAll. Shutdown calls it from a second goroutine while the run loop may
	// still be inside one, and the two would otherwise ship the same chunk twice and race on its fields.
	flushMu sync.Mutex

	mu     sync.Mutex
	spools map[string]*activitySpool

	// A session's sequence numbers have to keep climbing across the spool being forgotten and rebuilt,
	// or one proxy emits two records with the same (proxyId, seq) for one session. Cleared wholesale
	// when it grows, the way the session cache handles its own refusal map.
	seqBySession map[string]uint64

	total         int
	sealedBytes   int
	nextSealOrder uint64

	// Proxy-wide, because both reasons are proxy-wide: the ceiling is per organization and the switch is
	// per project, and this proxy serves one project.
	pauseUntil  time.Time
	pauseReason string

	// Reset at the top of every flushAll. Once either side has failed once in a tick, the remaining spools
	// seal but skip both calls, so a hundred spools against a blocked egress or an unreachable control
	// plane cost one timeout rather than a hundred.
	s3Down        bool
	infisicalDown bool

	closed bool
	wake   chan struct{}
}

func newActivityLog(proxyID string, shipper activityShipper) *activityLog {
	return &activityLog{
		proxyID:      proxyID,
		shipper:      shipper,
		now:          time.Now,
		spools:       make(map[string]*activitySpool),
		seqBySession: make(map[string]uint64),
		wake:         make(chan struct{}, 1),
	}
}

// record is the entire hot-path cost: one append under a mutex. No I/O, no crypto.
//
// Nil-safe on both the receiver and the grant, so a bare &proxyServer{} test fixture and a session whose
// logging is off both cost a single comparison.
func (a *activityLog) record(g *activityGrant, rec activityRecord) {
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
		spool = newActivitySpool(g, a.now())
		spool.nextSeq = a.seqBySession[g.sessionID]
		a.spools[g.sessionID] = spool
	}

	// A sequence number is consumed even while paused or full, so the gap is counted rather than silent
	// and a chunk's firstSeq reveals exactly how many records are missing before it.
	rec.Seq = spool.nextSeq
	spool.nextSeq++
	rec.ProxyID = a.proxyID
	rec.Ts = a.now().UTC().Format(time.RFC3339Nano)
	spool.lastRecordAt = a.now()

	if !a.pauseUntil.IsZero() && a.now().Before(a.pauseUntil) {
		spool.ring.dropped++
		return
	}

	if a.total >= activityTotalCapacity {
		// The newest is dropped rather than the oldest: at the proxy-wide fuse the ring's own eviction is
		// already running, and dropping the newest keeps one bounded behaviour rather than two.
		spool.ring.dropped++
		return
	}

	if evicted := spool.ring.push(rec); !evicted {
		a.total++
	}

	if spool.ring.len() >= activityFlushRecords {
		select {
		case a.wake <- struct{}{}:
		default:
		}
	}
}

// run is a single loop, so a flush can never overlap itself and no same-session guard is needed.
func (a *activityLog) run(stop <-chan struct{}) {
	if a == nil {
		return
	}
	ticker := time.NewTicker(activityFlushInterval)
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

// close stops recording and makes one last attempt to ship everything buffered, within the deadline on ctx.
func (a *activityLog) close(ctx context.Context) {
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
		log.Warn().Int("records", lost).Msg("agent-vault: activity records were not shipped before shutdown")
	}
}

// dueSpools picks what to flush and forgets idle spools, under the lock. Flushing then happens off it.
func (a *activityLog) dueSpools(final bool) []*activitySpool {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	due := make([]*activitySpool, 0, len(a.spools))
	for id, spool := range a.spools {
		if spool.ring.len() == 0 && len(spool.pending) == 0 {
			// A spool is independent of the session cache: eviction there just means record() stops
			// arriving, and this is what eventually forgets it.
			if !final && now.Sub(spool.lastRecordAt) > activityIdleClose {
				a.forgetSpoolLocked(id, spool)
			}
			continue
		}
		if final || spool.ring.len() >= activityFlushRecords || len(spool.pending) > 0 ||
			(spool.ring.len() > 0 && now.Sub(spool.lastFlushAt) >= activityFlushInterval) {
			due = append(due, spool)
		}
	}
	return due
}

// forgetSpoolLocked drops a spool but keeps where its sequence numbers had reached.
func (a *activityLog) forgetSpoolLocked(sessionID string, spool *activitySpool) {
	if len(a.seqBySession) >= maxSessionCacheEntries {
		a.seqBySession = make(map[string]uint64)
	}
	a.seqBySession[sessionID] = spool.nextSeq
	delete(a.spools, sessionID)
}

func (a *activityLog) paused() (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pauseUntil.IsZero() || !a.now().Before(a.pauseUntil) {
		return false, ""
	}
	return true, a.pauseReason
}

func (a *activityLog) pause(reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pauseUntil = a.now().Add(activityPauseBackoff)
	a.pauseReason = reason
}

func (a *activityLog) flushAll(ctx context.Context, final bool) {
	if a == nil {
		return
	}

	// One goroutine in flushAll at a time: the run loop and shutdown both call it.
	a.flushMu.Lock()
	defer a.flushMu.Unlock()

	a.mu.Lock()
	a.s3Down = false
	a.infisicalDown = false
	a.mu.Unlock()

	for _, spool := range a.dueSpools(final) {
		// Sequential and off the lock. At one chunk per session per minute and ~100ms per PUT, a hundred
		// sessions finish well inside a 60s tick, and one loop means no same-session overlap to guard.
		a.flushSpool(ctx, spool, final)
	}
}

// sealRing drains the ring into sealed chunks, in slices the server will accept.
//
// The marshal and the AES pass run off the lock. They are only milliseconds, but it is the same lock
// every proxied request takes to append a record, so holding it across them would stall the request path.
func (a *activityLog) sealRing(spool *activitySpool) {
	for {
		a.mu.Lock()
		records := spool.ring.drain(activityFlushRecords)
		if len(records) == 0 {
			spool.lastFlushAt = a.now()
			a.mu.Unlock()
			return
		}
		a.total -= len(records)
		// droppedCount rides the first slice only, so one gap is reported once.
		dropped := spool.ring.takeDropped()
		now := a.now()
		a.mu.Unlock()

		chunk, err := spool.sealSlice(a.proxyID, records, dropped, now)
		if err != nil {
			a.mu.Lock()
			// These records are gone, so they join the gap rather than vanishing from the count with it.
			spool.ring.dropped += dropped + uint64(len(records))
			a.mu.Unlock()
			log.Error().Err(err).Str("sessionId", spool.sessionID).Int("records", len(records)).
				Msg("agent-vault: could not seal an activity chunk, dropping those records")
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

// enforcePendingCapsLocked runs on every append, because the caps are a property of `pending` rather than
// a branch of the ceiling handler. Both evict the oldest sealed chunk and count what it held as dropped.
//
// The byte cap is proxy-wide, so it evicts the oldest chunk on the proxy wherever it sits, a session's only
// chunk included. Sparing every session its last chunk let an outage hold one per session with no bound.
func (a *activityLog) enforcePendingCapsLocked(spool *activitySpool) {
	for len(spool.pending) > activityPendingChunks {
		a.evictOldestLocked(spool)
	}
	for a.sealedBytes > activityTotalSealedBytes {
		victim := a.oldestPendingLocked()
		if victim == nil {
			// Unreachable while sealedBytes counts only pending chunks. Guarded anyway: this runs under the
			// lock every proxied request takes to record.
			return
		}
		a.evictOldestLocked(victim)
	}
}

// oldestPendingLocked scans every spool, which is fine: it only runs once the proxy is over its byte cap.
func (a *activityLog) oldestPendingLocked() *activitySpool {
	var oldest *activitySpool
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

func (a *activityLog) evictOldestLocked(spool *activitySpool) {
	oldest := spool.pending[0]
	spool.pending = spool.pending[1:]
	a.sealedBytes -= len(oldest.ciphertext)
	spool.ring.dropped += oldest.lostCount()
	log.Warn().
		Str("sessionId", spool.sessionID).
		Str("chunkId", oldest.meta.ChunkID).
		Int("records", oldest.meta.RecordCount).
		Msg("agent-vault: dropped an unshipped activity chunk, the buffer is full")
}

func (a *activityLog) flushSpool(ctx context.Context, spool *activitySpool, final bool) {
	if paused, reason := a.paused(); paused {
		// Seal once at pause onset so the ring does not overflow while waiting, then hold everything: ops
		// may raise the ceiling within the window, and the chunks are still shippable when it lifts.
		a.sealRing(spool)
		_ = reason
		return
	}

	a.sealRing(spool)

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

// shipChunk delivers one chunk. It returns false when this spool's loop should stop for the tick.
func (a *activityLog) shipChunk(ctx context.Context, spool *activitySpool, chunk *sealedChunk, final bool) bool {
	if chunk.uploadURL == "" || a.now().Add(10*time.Second).After(chunk.urlExpires) {
		res, err := a.shipper.createChunk(final, spool.sessionID, chunk.meta)
		if err != nil {
			return a.handleCreateFailure(spool, chunk, err)
		}
		chunk.posted = true
		chunk.uploadURL = res.UploadURL
		chunk.urlExpires = a.now().Add(time.Duration(res.ExpiresInSeconds) * time.Second)
	}

	putCtx := ctx
	if !final {
		var cancel context.CancelFunc
		putCtx, cancel = context.WithTimeout(ctx, activityPutTimeout)
		defer cancel()
	}

	if err := a.shipper.putObject(putCtx, chunk.uploadURL, chunk.ciphertext); err != nil {
		// The row already exists, so re-POSTing the same chunk id replays idempotently and yields a fresh
		// url. Clearing it is what makes the next tick do that.
		chunk.uploadURL = ""
		a.mu.Lock()
		a.s3Down = true
		a.mu.Unlock()
		log.Warn().Err(err).Str("sessionId", spool.sessionID).Str("chunkId", chunk.meta.ChunkID).
			Msg("agent-vault: could not upload an activity chunk, will retry")
		return false
	}

	return true
}

func (a *activityLog) handleCreateFailure(spool *activitySpool, chunk *sealedChunk, err error) bool {
	switch {
	case isProxyTokenRejected(err):
		// The poll loop exits within two heartbeats. Keep everything until it does.
		log.Warn().Err(err).Msg("agent-vault: Infisical rejected this proxy's token, holding activity")
		return false

	case isSessionGone(err):
		a.mu.Lock()
		a.total -= spool.ring.len()
		for _, held := range spool.pending {
			a.sealedBytes -= len(held.ciphertext)
		}
		// The session is gone for good, so its sequence numbers are not worth remembering.
		a.forgetSpoolLocked(spool.sessionID, spool)
		delete(a.seqBySession, spool.sessionID)
		a.mu.Unlock()
		log.Debug().Str("sessionId", spool.sessionID).Msg("agent-vault: session gone, dropping its activity")
		return false

	case isActivityErrorNamed(err, activityCeilingReachedName):
		a.pause(activityCeilingReachedName)
		// An error, not a warning: recording has stopped for the whole organization until Infisical acts.
		log.Error().Err(err).Msg("agent-vault: activity logging has reached its limit for this organization, retrying in 15m")
		return false

	case isActivityErrorNamed(err, activityDisabledName):
		a.pause(activityDisabledName)
		log.Warn().Msg("agent-vault: activity logging is switched off for this project, pausing for 15m")
		return false

	case isPoisonChunk(err):
		// The server will never accept this chunk, so retrying costs the whole spool.
		a.mu.Lock()
		if len(spool.pending) > 0 && spool.pending[0] == chunk {
			spool.pending = spool.pending[1:]
			a.sealedBytes -= len(chunk.ciphertext)
		}
		a.mu.Unlock()
		log.Error().Err(err).Str("chunkId", chunk.meta.ChunkID).
			Msg("agent-vault: Infisical rejected an activity chunk as malformed, dropping it")
		return false

	default:
		// A timeout, a 5xx or a 429. Whatever it is, the rest of this tick will meet it too.
		a.mu.Lock()
		a.infisicalDown = true
		a.mu.Unlock()
		log.Warn().Err(err).Str("sessionId", spool.sessionID).
			Msg("agent-vault: could not record activity, will retry")
		return false
	}
}
