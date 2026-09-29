package agentvault

import (
	"container/list"
	"context"
	"sort"
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

	sessionLogSpoolCapacity     = 5000                   // one session's ring; full: overwrite the oldest line, count it
	sessionLogTotalCapacity     = 200_000                // all rings together; full: drop new lines, count them
	sessionLogPendingChunks     = 10                     // one session's sealed chunks; full: drop the oldest, count it
	sessionLogTotalSealedBytes  = 64 << 20               // all sealed chunks; full: drop the oldest chunk of any session
	sessionLogForgottenCapacity = maxSessionCacheEntries // idle sessions remembered; full: forget the one forgotten longest

	sessionLogIdleClose = 15 * time.Minute

	sessionLogPauseBackoff    = 15 * time.Minute
	sessionLogPutTimeout      = 10 * time.Second
	sessionLogFinalTimeout    = 3 * time.Second
	sessionLogCloseTimeout    = 5 * time.Second
	sessionLogUploadURLMargin = 10 * time.Second // get a fresh link if the current one expires within this

	sessionLogShipParallelism = 8 // chunks sent at once, one per session, like refreshParallelism
)

type sessionLogGrant struct {
	sessionID string
	key       []byte

	issued uint64
}

// Resolve only hands out a grant while session logs are on. So a grant issued after a refused request went
// out means logs came back on after that request, and the refusal is stale.
var sessionLogGrantsIssued atomic.Uint64

func grantIssuedSince(snapshot uint64) bool { return sessionLogGrantsIssued.Load() > snapshot }

func newSessionLogGrant(sessionID string, key []byte) *sessionLogGrant {
	return &sessionLogGrant{sessionID: sessionID, key: key, issued: sessionLogGrantsIssued.Add(1)}
}

type forgottenSpool struct {
	nextSeq         uint64
	unreportedDrops uint64
}

// Idle sessions in the order they were forgotten, so a full list drops the oldest without a scan.
type forgottenSpools struct {
	capacity int
	order    *list.List // of forgottenEntry, oldest first
	byID     map[string]*list.Element
}

type forgottenEntry struct {
	sessionID string
	spool     forgottenSpool
}

func newForgottenSpools(capacity int) *forgottenSpools {
	return &forgottenSpools{capacity: capacity, order: list.New(), byID: make(map[string]*list.Element)}
}

func (f *forgottenSpools) remember(sessionID string, spool forgottenSpool) {
	f.drop(sessionID)
	if f.order.Len() >= f.capacity {
		f.drop(f.order.Front().Value.(forgottenEntry).sessionID)
	}
	f.byID[sessionID] = f.order.PushBack(forgottenEntry{sessionID: sessionID, spool: spool})
}

func (f *forgottenSpools) take(sessionID string) (forgottenSpool, bool) {
	el, ok := f.byID[sessionID]
	if !ok {
		return forgottenSpool{}, false
	}
	f.drop(sessionID)
	return el.Value.(forgottenEntry).spool, true
}

func (f *forgottenSpools) drop(sessionID string) {
	if el, ok := f.byID[sessionID]; ok {
		f.order.Remove(el)
		delete(f.byID, sessionID)
	}
}

func (f *forgottenSpools) len() int { return f.order.Len() }

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

type flushPass int

const (
	flushTick flushPass = iota
	flushWake
	flushFinal
)

// record() appends each request to its session's ring. A flush seals the ring into encrypted chunks and
// queues them on the spool. Each queued chunk then gets its index row (createChunk) and is uploaded to S3
// (putObject). When Infisical refuses a chunk, handleCreateFailure classifies the refusal and handles it.
type sessionLogRecorder struct {
	proxyID string
	shipper sessionLogShipper
	now     func() time.Time
	wake    chan struct{}

	// flushMu makes flush passes take turns, so close() and the run loop never ship one chunk twice.
	flushMu sync.Mutex

	// mu guards everything below, and each queued chunk's upload fields.
	mu     sync.Mutex
	spools map[string]*sessionLogSpool

	forgotten *forgottenSpools

	unsealedRecords int
	sealedBytes     int
	nextSealOrder   uint64

	hold sessionLogHold

	clockSkewReported bool

	closed bool
}

func newSessionLogRecorder(proxyID string, shipper sessionLogShipper) *sessionLogRecorder {
	return &sessionLogRecorder{
		proxyID:   proxyID,
		shipper:   shipper,
		now:       time.Now,
		spools:    make(map[string]*sessionLogSpool),
		forgotten: newForgottenSpools(sessionLogForgottenCapacity),
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
		if prior, ok := r.forgotten.take(g.sessionID); ok {
			spool.nextSeq, spool.ring.unreportedDrops = prior.nextSeq, prior.unreportedDrops
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

	if !r.admitLocked(g, now) {
		spool.ring.unreportedDrops++
		return
	}

	if evicted := spool.ring.push(rec); !evicted {
		r.unsealedRecords++
	}

	if spool.ring.len() >= sessionLogFlushRecords {
		select {
		case r.wake <- struct{}{}:
		default:
		}
	}
}

// Also switches recording back on when a grant issued after logs went off arrives.
func (r *sessionLogRecorder) admitLocked(g *sessionLogGrant, now time.Time) bool {
	if r.hold.off {
		if g.issued <= r.hold.offThrough {
			return false
		}
		r.hold.off = false
		log.Info().Msg("agent-vault: session logs are back on, recording again")
	}
	if now.Before(r.hold.pausedUntil) {
		return false
	}
	if r.unsealedRecords >= sessionLogTotalCapacity {
		return false
	}
	return true
}

func (r *sessionLogRecorder) run(stop <-chan struct{}) {
	if r == nil {
		return
	}
	// Cancelled on stop, so a pass in flight ends at once and close() can start the final flush.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-stop
		cancel()
	}()

	ticker := time.NewTicker(sessionLogFlushInterval)
	defer ticker.Stop()

	for {
		// Checked on its own first: select picks at random among ready cases, so a due tick could win over stop.
		select {
		case <-stop:
			return
		default:
		}
		select {
		case <-stop:
			return
		case <-ticker.C:
			r.flush(ctx, flushTick)
		case <-r.wake:
			r.flush(ctx, flushWake)
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
	if pass == flushTick {
		r.mu.Lock()
		r.forgetIdleSpoolsLocked(started)
		r.mu.Unlock()
	}
	due := r.dueSpools(pass, started)
	// Only what each ring held at the start, so requests arriving mid-pass wait for the next wake or tick instead
	// of going out one tiny chunk per round and keeping the pass open.
	unsealed := r.startSealing(due, started)

	// Sealed a round at a time, between rounds, so a healthy pass never holds more than one round against the
	// byte cap, and evicting for it never hits a chunk in flight.
	stopped := make(map[*sessionLogSpool]bool)
	for ctx.Err() == nil {
		r.sealNextRound(due, stopped, unsealed)
		batch := r.nextShipments(due, stopped)
		if len(batch) == 0 {
			break
		}
		r.applyShipments(ctx, r.sendShipments(ctx, batch, pass), stopped)
	}

	// Only a failed or cancelled round leaves any: they wait sealed, where the byte cap drops the oldest first.
	for _, spool := range due {
		for unsealed[spool] > 0 && r.sealNext(spool, unsealed) {
		}
	}
}

func (r *sessionLogRecorder) forgetIdleSpoolsLocked(now time.Time) {
	for id, spool := range r.spools {
		if spool.ring.len() == 0 && len(spool.pending) == 0 && now.Sub(spool.lastRecordAt) > sessionLogIdleClose {
			r.forgetSpoolLocked(id, spool)
		}
	}
}

// Keeps the drop count too, so a spool forgotten while logging was off still reports what it lost.
func (r *sessionLogRecorder) forgetSpoolLocked(sessionID string, spool *sessionLogSpool) {
	r.forgotten.remember(sessionID, forgottenSpool{nextSeq: spool.nextSeq, unreportedDrops: spool.ring.unreportedDrops})
	delete(r.spools, sessionID)
}

func (r *sessionLogRecorder) dueSpools(pass flushPass, now time.Time) []*sessionLogSpool {
	r.mu.Lock()
	defer r.mu.Unlock()

	due := make([]*sessionLogSpool, 0, len(r.spools))
	for _, spool := range r.spools {
		if r.isDueLocked(spool, pass, now) {
			due = append(due, spool)
		}
	}
	return due
}

func (r *sessionLogRecorder) isDueLocked(spool *sessionLogSpool, pass flushPass, now time.Time) bool {
	if pass == flushWake {
		return spool.ring.len() >= sessionLogFlushRecords
	}
	if spool.ring.len() == 0 && len(spool.pending) == 0 {
		return false
	}
	if pass == flushFinal {
		return true
	}
	if spool.ring.len() >= sessionLogFlushRecords {
		return true
	}
	if len(spool.pending) > 0 {
		return true
	}
	// The slack absorbs ticker jitter: without it a spool stamped at one tick is a hair short of due at the next.
	return now.Sub(spool.lastFlushAt) >= sessionLogFlushInterval-sessionLogFlushSlack
}

// How many records each due ring holds as the pass starts, which is all the pass seals. The spools count as
// flushed now, so the next tick is a full interval away however long the pass takes.
func (r *sessionLogRecorder) startSealing(due []*sessionLogSpool, started time.Time) map[*sessionLogSpool]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	unsealed := make(map[*sessionLogSpool]int, len(due))
	for _, spool := range due {
		unsealed[spool] = spool.ring.len()
		spool.lastFlushAt = started
	}
	return unsealed
}

// The next slice of up to sessionLogShipParallelism sessions, sealed only where nothing is queued, so each
// session has a chunk for the round that is about to ship.
func (r *sessionLogRecorder) sealNextRound(due []*sessionLogSpool, stopped map[*sessionLogSpool]bool, unsealed map[*sessionLogSpool]int) {
	ready := 0
	for _, spool := range due {
		if ready == sessionLogShipParallelism {
			return
		}
		if stopped[spool] {
			continue
		}
		r.mu.Lock()
		queued := len(spool.pending) > 0
		r.mu.Unlock()
		if !queued && unsealed[spool] > 0 {
			r.sealNext(spool, unsealed)
			r.mu.Lock()
			queued = len(spool.pending) > 0
			r.mu.Unlock()
		}
		if queued {
			ready++
		}
	}
}

// Seals the next slice of what the pass took on for this spool. False once the ring has none of it left, which
// happens early only if session logs were switched off mid-pass and the ring was discarded.
func (r *sessionLogRecorder) sealNext(spool *sessionLogSpool, unsealed map[*sessionLogSpool]int) bool {
	r.mu.Lock()
	records := spool.ring.drain(min(unsealed[spool], sessionLogFlushRecords))
	if len(records) == 0 {
		unsealed[spool] = 0
		r.mu.Unlock()
		return false
	}
	unsealed[spool] -= len(records)
	r.unsealedRecords -= len(records)
	dropped := spool.ring.takeUnreportedDrops()
	r.mu.Unlock()

	groups, err := packSessionLogRecords(records)
	if err != nil {
		r.dropUnsealed(spool, len(records), dropped, err)
		return true
	}
	for i, group := range groups {
		var groupDropped uint64
		// Only the first chunk of a split batch carries the drop count, so drops aren't reported twice.
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
	return true
}

func (r *sessionLogRecorder) dropUnsealed(spool *sessionLogSpool, records int, dropped uint64, err error) {
	r.mu.Lock()
	spool.ring.unreportedDrops += dropped + uint64(records)
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

// One chunk picked for a round, with the upload link it held when picked.
type shipment struct {
	spool      *sessionLogSpool
	chunk      *sealedChunk
	uploadURL  string
	urlExpires time.Time
}

// What the network said about one shipment. Only applyShipments turns it into state.
type shipmentResult struct {
	shipment

	skipped bool

	posted             bool
	postedURL          string
	postedExpires      time.Time
	grantsIssuedAtSend uint64
	createErr          error

	putErr error
}

func (res shipmentResult) shipped() bool {
	return !res.skipped && res.createErr == nil && res.putErr == nil
}

// The next chunk of up to sessionLogShipParallelism sessions. A session that failed this pass is left for the next.
func (r *sessionLogRecorder) nextShipments(due []*sessionLogSpool, stopped map[*sessionLogSpool]bool) []shipment {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.hold.canShip(r.now()) {
		return nil
	}

	batch := make([]shipment, 0, sessionLogShipParallelism)
	for _, spool := range due {
		if stopped[spool] || len(spool.pending) == 0 {
			continue
		}
		chunk := spool.pending[0]
		batch = append(batch, shipment{spool: spool, chunk: chunk, uploadURL: chunk.uploadURL, urlExpires: chunk.urlExpires})
		if len(batch) == sessionLogShipParallelism {
			break
		}
	}
	return batch
}

// Network only: the recorder's state is never touched here, so the rest of it stays single-threaded.
func (r *sessionLogRecorder) sendShipments(ctx context.Context, batch []shipment, pass flushPass) []shipmentResult {
	results := make([]shipmentResult, len(batch))
	var wg sync.WaitGroup
	for i, next := range batch {
		wg.Add(1)
		go func(i int, next shipment) {
			defer wg.Done()
			results[i] = r.sendShipment(ctx, next, pass)
		}(i, next)
	}
	wg.Wait()
	return results
}

func (r *sessionLogRecorder) sendShipment(ctx context.Context, next shipment, pass flushPass) shipmentResult {
	res := shipmentResult{shipment: next}
	final := pass == flushFinal

	uploadURL := next.uploadURL
	if uploadURL == "" || r.now().Add(sessionLogUploadURLMargin).After(next.urlExpires) {
		// Past the shutdown budget, a new row could only be written for an upload that can no longer happen.
		if ctx.Err() != nil {
			res.skipped = true
			return res
		}
		res.grantsIssuedAtSend = sessionLogGrantsIssued.Load()
		created, err := r.shipper.createChunk(ctx, final, next.spool.sessionID, next.chunk.meta)
		if err != nil {
			res.createErr = err
			return res
		}
		res.posted = true
		res.postedURL = created.UploadURL
		res.postedExpires = r.now().Add(time.Duration(created.ExpiresInSeconds) * time.Second)
		uploadURL = created.UploadURL
	}

	putCtx := ctx
	if !final {
		var cancel context.CancelFunc
		putCtx, cancel = context.WithTimeout(ctx, sessionLogPutTimeout)
		defer cancel()
	}
	res.putErr = r.shipper.putObject(putCtx, uploadURL, next.chunk.ciphertext)
	return res
}

func (r *sessionLogRecorder) applyShipments(ctx context.Context, results []shipmentResult, stopped map[*sessionLogSpool]bool) {
	// Rows first, then successes, then failures: a refusal can switch logging off and discard every queue,
	// and a chunk that already has its row, or has landed, must not be counted as dropped by that.
	r.mu.Lock()
	for _, res := range results {
		if res.posted {
			r.clockSkewReported = false
			res.chunk.state = chunkPosted
			res.chunk.uploadURL = res.postedURL
			res.chunk.urlExpires = res.postedExpires
		}
	}
	r.mu.Unlock()
	sort.SliceStable(results, func(i, j int) bool { return results[i].shipped() && !results[j].shipped() })

	for _, res := range results {
		if res.shipped() {
			r.mu.Lock()
			r.discardHeadLocked(res.spool, res.chunk, false)
			r.mu.Unlock()
			continue
		}
		stopped[res.spool] = true

		switch {
		case res.skipped:
		case res.createErr != nil && ctx.Err() != nil:
			// Cancelled by shutdown: the chunk stays queued for the final flush, which is no outage to report.
			r.mu.Lock()
			r.hold.infisicalDown = true
			r.mu.Unlock()
		case res.createErr != nil:
			r.handleCreateFailure(res.spool, res.chunk, res.createErr, res.grantsIssuedAtSend)
		default:
			r.mu.Lock()
			res.chunk.uploadURL = ""
			r.hold.s3Down = true
			r.mu.Unlock()
			if ctx.Err() == nil {
				log.Warn().Err(res.putErr).Str("sessionId", res.spool.sessionID).Str("chunkId", res.chunk.meta.ChunkID).
					Msg("agent-vault: could not upload a session log chunk, will retry")
			}
		}
	}
}

func (r *sessionLogRecorder) handleCreateFailure(spool *sessionLogSpool, chunk *sealedChunk, err error, grantsIssuedAtSend uint64) {
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
}

// Drops everything held and counts it, unless a grant was issued after the refused request went out, which
// makes the refusal stale (see sessionLogGrantsIssued).
func (r *sessionLogRecorder) switchOff(grantsIssuedAtSend uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if grantIssuedSince(grantsIssuedAtSend) {
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

func (r *sessionLogRecorder) pause() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hold.pausedUntil = r.now().Add(sessionLogPauseBackoff)
}

func (r *sessionLogRecorder) dropRefused(spool *sessionLogSpool, chunk *sealedChunk) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Counted as dropped, or an agent that gets its own chunk refused could erase what it did.
	r.discardHeadLocked(spool, chunk, true)
}

// A gone session passes countDropped false: its spool is deleted, so no later chunk could report the loss.
func (r *sessionLogRecorder) discardAllLocked(spool *sessionLogSpool, countDropped bool) (lost int) {
	lost = spool.heldRecords()

	held := spool.ring.len()
	spool.ring.drain(held)
	r.unsealedRecords -= held
	if countDropped {
		spool.ring.unreportedDrops += uint64(held)
	}

	for _, chunk := range spool.pending {
		r.sealedBytes -= len(chunk.ciphertext)
		if countDropped {
			spool.ring.unreportedDrops += chunk.lostCount()
		}
	}
	spool.pending = nil
	return lost
}

func (r *sessionLogRecorder) discardHeadLocked(spool *sessionLogSpool, chunk *sealedChunk, countDropped bool) {
	if len(spool.pending) == 0 || spool.pending[0] != chunk {
		return
	}
	spool.popPending()
	r.sealedBytes -= len(chunk.ciphertext)
	if countDropped {
		spool.ring.unreportedDrops += chunk.lostCount()
	}
}
