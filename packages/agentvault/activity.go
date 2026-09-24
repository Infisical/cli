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
	activityFlushInterval     = 60 * time.Second
	activityFlushRecords      = 1000
	activityMaxChunkPlaintext = 4 << 20

	activitySpoolCapacity = 5000
	activityTotalCapacity = 200_000

	activityPendingChunks    = 10
	activityTotalSealedBytes = 64 << 20

	activityIdleClose = 15 * time.Minute

	activityPauseBackoff = 15 * time.Minute
	activityPutTimeout   = 10 * time.Second
	activityFinalTimeout = 3 * time.Second
	activityCloseTimeout = 5 * time.Second

	activityCeilingReachedName = "AgentVaultActivityCeilingReached"
	activityDisabledName       = "AgentVaultActivityDisabled"
	activityClockSkewName      = "AgentVaultActivityClockSkew"
)

type activityGrant struct {
	sessionID string
	projectID string
	key       []byte

	issued uint64
}

// Counts every grant the proxy is handed, so a refusal can be told apart from a key issued after it.
var activityGrantsIssued atomic.Uint64

func newActivityGrant(sessionID, projectID string, key []byte) *activityGrant {
	return &activityGrant{sessionID: sessionID, projectID: projectID, key: key, issued: activityGrantsIssued.Add(1)}
}

type forgottenSpool struct {
	nextSeq uint64
	dropped uint64
}

type activityShipper interface {
	createChunk(final bool, sessionID string, req api.CreateAgentVaultActivityChunkRequest) (api.CreateAgentVaultActivityChunkResponse, error)
	putObject(ctx context.Context, url string, ciphertext []byte) error
}

type activityLog struct {
	proxyID string
	shipper activityShipper
	now     func() time.Time

	// close's flushAll can overlap the run loop's; unguarded, one chunk ships twice.
	flushMu sync.Mutex

	mu     sync.Mutex
	spools map[string]*activitySpool

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

	uploads         uint64
	uploadsReported uint64

	closed bool
	wake   chan struct{}
}

func newActivityLog(proxyID string, shipper activityShipper) *activityLog {
	return &activityLog{
		proxyID:   proxyID,
		shipper:   shipper,
		now:       time.Now,
		spools:    make(map[string]*activitySpool),
		forgotten: make(map[string]forgottenSpool),
		wake:      make(chan struct{}, 1),
	}
}

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
		log.Info().Msg("agent-vault: activity logging is back on, recording again")
	}

	if !a.pauseUntil.IsZero() && a.now().Before(a.pauseUntil) {
		spool.ring.dropped++
		return
	}

	if a.total >= activityTotalCapacity {
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

func (a *activityLog) dueSpools(final bool) []*activitySpool {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	due := make([]*activitySpool, 0, len(a.spools))
	for id, spool := range a.spools {
		if spool.ring.len() == 0 && len(spool.pending) == 0 {
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

// Keeps the drop count too, so a spool forgotten while logging was off still reports what it lost.
func (a *activityLog) forgetSpoolLocked(sessionID string, spool *activitySpool) {
	if len(a.forgotten) >= maxSessionCacheEntries {
		a.forgotten = make(map[string]forgottenSpool)
	}
	a.forgotten[sessionID] = forgottenSpool{nextSeq: spool.nextSeq, dropped: spool.ring.dropped}
	delete(a.spools, sessionID)
}

func (a *activityLog) holding() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.switchedOff || (!a.pauseUntil.IsZero() && a.now().Before(a.pauseUntil))
}

func (a *activityLog) pause() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pauseUntil = a.now().Add(activityPauseBackoff)
}

// Drops everything held and counts it. A key issued after the refused request went out means logging may already
// be back on, so then the refusal is stale and nothing is dropped.
func (a *activityLog) switchOff(grantsIssuedAtSend uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if activityGrantsIssued.Load() > grantsIssuedAtSend {
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
			Msg("agent-vault: activity logging is switched off for this project, dropping what was held until it is back on")
	}
	a.switchedOff = true
	a.switchedOffThrough = grantsIssuedAtSend
}

func (a *activityLog) flushAll(ctx context.Context, final bool) {
	if a == nil {
		return
	}

	a.flushMu.Lock()
	defer a.flushMu.Unlock()

	a.mu.Lock()
	a.s3Down = false
	a.infisicalDown = false
	a.mu.Unlock()

	for _, spool := range a.dueSpools(final) {
		a.flushSpool(ctx, spool, final)
	}
}

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
		dropped := spool.ring.takeDropped()
		now := a.now()
		a.mu.Unlock()

		groups, err := packActivityRecords(records)
		if err != nil {
			a.dropUnsealed(spool, len(records), dropped, err)
			continue
		}
		for i, group := range groups {
			var groupDropped uint64
			if i == 0 {
				groupDropped = dropped
			}

			chunk, err := spool.sealSlice(a.proxyID, group.records, group.plaintext, groupDropped, now)
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

func (a *activityLog) dropUnsealed(spool *activitySpool, records int, dropped uint64, err error) {
	a.mu.Lock()
	spool.ring.dropped += dropped + uint64(records)
	a.mu.Unlock()
	log.Error().Err(err).Str("sessionId", spool.sessionID).Int("records", records).
		Msg("agent-vault: could not seal an activity chunk, dropping those records")
}

func (a *activityLog) enforcePendingCapsLocked(spool *activitySpool) {
	for len(spool.pending) > activityPendingChunks {
		a.evictOldestLocked(spool)
	}
	for a.sealedBytes > activityTotalSealedBytes {
		victim := a.oldestPendingLocked()
		if victim == nil {
			return
		}
		a.evictOldestLocked(victim)
	}
}

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
	a.sealRing(spool)
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
		a.uploads++
		a.mu.Unlock()
	}
}

// What the next heartbeat reports. It is acknowledged only once Infisical has answered, so a heartbeat that
// fails reports the same uploads again.
func (a *activityLog) uploadReport() (snapshot uint64, uploaded bool) {
	if a == nil {
		return 0, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.uploads, a.uploads > a.uploadsReported
}

func (a *activityLog) ackUploadReport(snapshot uint64) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.uploadsReported = max(a.uploadsReported, snapshot)
}

func (a *activityLog) shipChunk(ctx context.Context, spool *activitySpool, chunk *sealedChunk, final bool) bool {
	if chunk.uploadURL == "" || a.now().Add(10*time.Second).After(chunk.urlExpires) {
		grantsIssuedAtSend := activityGrantsIssued.Load()
		res, err := a.shipper.createChunk(final, spool.sessionID, chunk.meta)
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
		putCtx, cancel = context.WithTimeout(ctx, activityPutTimeout)
		defer cancel()
	}

	if err := a.shipper.putObject(putCtx, chunk.uploadURL, chunk.ciphertext); err != nil {
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

func (a *activityLog) handleCreateFailure(spool *activitySpool, chunk *sealedChunk, err error, grantsIssuedAtSend uint64) bool {
	switch {
	case isProxyTokenRejected(err):
		log.Warn().Err(err).Msg("agent-vault: Infisical rejected this proxy's token, holding activity")
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
			Msg("agent-vault: Infisical no longer accepts activity for this session, dropping what was held")
		return false

	case isActivityErrorNamed(err, activityCeilingReachedName):
		a.pause()
		log.Error().Err(err).Msg("agent-vault: activity logging has reached its limit for this organization, retrying in 15m")
		return false

	case isActivityErrorNamed(err, activityDisabledName):
		a.switchOff(grantsIssuedAtSend)
		return false

	case isActivityErrorNamed(err, activityClockSkewName):
		a.dropRefused(spool, chunk)
		a.mu.Lock()
		reported := a.clockSkewReported
		a.clockSkewReported = true
		a.mu.Unlock()
		if !reported {
			log.Error().Err(err).Msg("agent-vault: activity is being refused because this machine's clock is wrong; fix the clock to resume recording")
		}
		return false

	case isPoisonChunk(err):
		a.dropRefused(spool, chunk)
		log.Error().Err(err).Str("chunkId", chunk.meta.ChunkID).Int("records", chunk.meta.RecordCount).
			Msg("agent-vault: Infisical rejected an activity chunk as malformed, dropping it")
		return false

	default:
		a.mu.Lock()
		a.infisicalDown = true
		a.mu.Unlock()
		log.Warn().Err(err).Str("sessionId", spool.sessionID).
			Msg("agent-vault: could not record activity, will retry")
		return false
	}
}

func (a *activityLog) dropRefused(spool *activitySpool, chunk *sealedChunk) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(spool.pending) > 0 && spool.pending[0] == chunk {
		spool.pending = spool.pending[1:]
		a.sealedBytes -= len(chunk.ciphertext)
		// Counted as dropped, or an agent that gets its own chunk refused could erase what it did.
		spool.ring.dropped += chunk.lostCount()
	}
}
