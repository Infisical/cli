package agentvault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
)

type shipperCall struct {
	kind      string
	sessionID string
	chunkID   string
	url       string
	bytes     int
	records   int
	iv        string
	dropped   uint64
	body      []byte
	final     bool
}

type scriptedResult struct {
	url string
	err error
}

type fakeShipper struct {
	mu sync.Mutex

	calls []shipperCall

	postResults []scriptedResult
	putResults  []error

	postDefault scriptedResult
	putDefault  error

	nextURL int
}

func (f *fakeShipper) createChunk(_ context.Context, final bool, sessionID string, req api.CreateAgentVaultSessionLogChunkRequest) (api.CreateAgentVaultSessionLogChunkResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, shipperCall{kind: "post", sessionID: sessionID, chunkID: req.ChunkID, bytes: req.CiphertextBytes, records: req.RecordCount, iv: req.IV, dropped: req.DroppedCount, final: final})

	result := f.postDefault
	if len(f.postResults) > 0 {
		result = f.postResults[0]
		f.postResults = f.postResults[1:]
	}
	if result.err != nil {
		return api.CreateAgentVaultSessionLogChunkResponse{}, result.err
	}
	url := result.url
	if url == "" {
		f.nextURL++
		url = fmt.Sprintf("https://bucket.example/put/%d", f.nextURL)
	}
	return api.CreateAgentVaultSessionLogChunkResponse{UploadURL: url, ExpiresInSeconds: 300}, nil
}

func (f *fakeShipper) putObject(_ context.Context, url string, ciphertext []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, shipperCall{kind: "put", url: url, bytes: len(ciphertext), body: append([]byte(nil), ciphertext...)})

	if len(f.putResults) > 0 {
		err := f.putResults[0]
		f.putResults = f.putResults[1:]
		return err
	}
	return f.putDefault
}

func (f *fakeShipper) kinds() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	for i, call := range f.calls {
		out[i] = call.kind
	}
	return out
}

func (f *fakeShipper) posts() []shipperCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []shipperCall
	for _, call := range f.calls {
		if call.kind == "post" {
			out = append(out, call)
		}
	}
	return out
}

func (f *fakeShipper) puts() []shipperCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []shipperCall
	for _, call := range f.calls {
		if call.kind == "put" {
			out = append(out, call)
		}
	}
	return out
}

func apiErr(status int, name string) error {
	return &api.APIError{StatusCode: status, Name: name, Operation: "CallCreateAgentVaultSessionLogChunk"}
}

func testGrant(sessionID string) *sessionLogGrant {
	return newSessionLogGrant(sessionID, make([]byte, 32))
}

func newTestLog(shipper sessionLogShipper) (log *sessionLogRecorder, advance func(time.Duration), tick func()) {
	log = newSessionLogRecorder("proxy-1", shipper)
	now := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	log.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance = func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}
	tick = func() {
		advance(sessionLogFlushInterval)
		log.flush(context.Background(), flushTick)
	}
	return log, advance, tick
}

func aRecord(host string) sessionLogRecord {
	return sessionLogRecord{Method: "GET", Host: host, Port: "443", Path: "/zen", Status: 200, Decision: decisionPassthrough}
}

func TestRecordingIsANoOpWithoutALogOrAGrant(t *testing.T) {
	var nilLog *sessionLogRecorder
	nilLog.record(testGrant("s1"), aRecord("api.github.com"))

	log, _, _ := newTestLog(&fakeShipper{})
	log.record(nil, aRecord("api.github.com"))
	if len(log.spools) != 0 {
		t.Fatal("a nil grant created a spool; logging-off must cost nothing")
	}
}

func TestTheRingDropsTheOldestAndCountsIt(t *testing.T) {
	ring := newSessionLogRing(3)
	for i := 0; i < 5; i++ {
		ring.push(sessionLogRecord{Seq: uint64(i)})
	}

	if ring.len() != 3 {
		t.Fatalf("ring holds %d, capacity is 3", ring.len())
	}
	if ring.dropped != 2 {
		t.Fatalf("ring counted %d drops, expected 2", ring.dropped)
	}

	drained := ring.drain(10)
	if len(drained) != 3 || drained[0].Seq != 2 || drained[2].Seq != 4 {
		t.Fatalf("expected the three newest records 2,3,4; got %+v", drained)
	}
}

func TestTheRingAllocatesOnlyWhatItHolds(t *testing.T) {
	ring := newSessionLogRing(sessionLogSpoolCapacity)
	ring.push(sessionLogRecord{Seq: 0})

	if got := cap(ring.buf); got > sessionLogRingInitialSize {
		t.Fatalf("one record reserved room for %d, expected at most %d", got, sessionLogRingInitialSize)
	}

	ring.drain(10)
	if ring.buf != nil {
		t.Fatal("a drained ring kept its buffer; an idle session should hold nothing")
	}
}

func TestTheRingKeepsItsOrderWhileItGrowsPastAWrap(t *testing.T) {
	ring := newSessionLogRing(sessionLogSpoolCapacity)
	var next uint64
	push := func(n int) {
		for i := 0; i < n; i++ {
			ring.push(sessionLogRecord{Seq: next})
			next++
		}
	}

	push(sessionLogRingInitialSize)
	ring.drain(10)
	push(sessionLogRingInitialSize * 3)

	drained := ring.drain(sessionLogSpoolCapacity)
	if len(drained) != sessionLogRingInitialSize*4-10 {
		t.Fatalf("drained %d records, expected %d", len(drained), sessionLogRingInitialSize*4-10)
	}
	for i, rec := range drained {
		if rec.Seq != uint64(10+i) {
			t.Fatalf("record %d has seq %d, expected %d; growth reordered the ring", i, rec.Seq, 10+i)
		}
	}
	if ring.dropped != 0 {
		t.Fatalf("growth counted %d drops; nothing was over capacity", ring.dropped)
	}
}

func TestTheRingDrainsInSlicesTheServerAccepts(t *testing.T) {
	ring := newSessionLogRing(sessionLogSpoolCapacity)
	for i := 0; i < 2500; i++ {
		ring.push(sessionLogRecord{Seq: uint64(i)})
	}

	var slices int
	for ring.len() > 0 {
		got := ring.drain(sessionLogFlushRecords)
		if len(got) > sessionLogFlushRecords {
			t.Fatalf("a slice held %d records, the server's limit is %d", len(got), sessionLogFlushRecords)
		}
		slices++
	}
	if slices != 3 {
		t.Fatalf("2500 records drained in %d slices, expected 3", slices)
	}
}

func TestTheDropCountIsReportedOnceAndRidesTheFirstChunk(t *testing.T) {
	shipper := &fakeShipper{}
	log, _, _ := newTestLog(shipper)
	grant := testGrant("s1")

	for i := 0; i < sessionLogSpoolCapacity+50; i++ {
		log.record(grant, aRecord("api.github.com"))
	}
	log.flush(context.Background(), flushFinal)

	posts := shipper.posts()
	if len(posts) == 0 {
		t.Fatal("nothing was shipped")
	}
	if log.spools["s1"].ring.dropped != 0 {
		t.Fatal("the drop count was not reset after being reported")
	}
}

func TestASequenceNumberIsConsumedEvenWhenARecordIsDropped(t *testing.T) {
	log, _, _ := newTestLog(&fakeShipper{})
	grant := testGrant("s1")

	for i := 0; i < sessionLogSpoolCapacity+10; i++ {
		log.record(grant, aRecord("api.github.com"))
	}

	if got := log.spools["s1"].nextSeq; got != uint64(sessionLogSpoolCapacity+10) {
		t.Fatalf("nextSeq is %d after %d records; drops must still consume a number", got, sessionLogSpoolCapacity+10)
	}
}

func TestTheProxyWideFuseDropsTheNewest(t *testing.T) {
	log, _, _ := newTestLog(&fakeShipper{})

	for i := 0; i < sessionLogTotalCapacity/sessionLogSpoolCapacity+2; i++ {
		grant := testGrant(fmt.Sprintf("s%d", i))
		for j := 0; j < sessionLogSpoolCapacity; j++ {
			log.record(grant, aRecord("api.github.com"))
		}
	}

	if log.total > sessionLogTotalCapacity {
		t.Fatalf("the proxy holds %d records, past the %d fuse", log.total, sessionLogTotalCapacity)
	}
}

func TestAChunkIsPostedBeforeItIsUploaded(t *testing.T) {
	shipper := &fakeShipper{}
	log, _, _ := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	log.flush(context.Background(), flushFinal)

	if got := shipper.kinds(); len(got) != 2 || got[0] != "post" || got[1] != "put" {
		t.Fatalf("call order was %v, expected post then put", got)
	}
	if posts := shipper.posts(); posts[0].sessionID != "s1" {
		t.Fatalf("posted under session %q", posts[0].sessionID)
	}
	if puts := shipper.puts(); puts[0].bytes != shipper.posts()[0].bytes {
		t.Fatalf("uploaded %d bytes after declaring %d", puts[0].bytes, shipper.posts()[0].bytes)
	}
}

func TestAFailedUploadRePostsTheSameChunkID(t *testing.T) {
	shipper := &fakeShipper{putResults: []error{errors.New("connection reset")}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()
	tick()

	posts := shipper.posts()
	if len(posts) != 2 {
		t.Fatalf("expected the chunk to be re-posted, saw %d posts", len(posts))
	}
	if posts[0].chunkID != posts[1].chunkID {
		t.Fatalf("re-post used a different chunk id: %q then %q", posts[0].chunkID, posts[1].chunkID)
	}
	if len(shipper.puts()) != 2 {
		t.Fatalf("expected a second upload attempt, saw %d", len(shipper.puts()))
	}
}

func TestASessionThatIsGoneIsDropped(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(http.StatusNotFound, infisicalNotFoundName)}}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	if _, ok := log.spools["s1"]; ok {
		t.Fatal("the spool survived a session the server no longer knows")
	}

	tick()
	if len(shipper.posts()) != 1 {
		t.Fatal("the dropped spool was retried")
	}
}

func TestA404ThatIsNotInfisicalsNotFoundIsRetried(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(http.StatusNotFound, "")}}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	spool, ok := log.spools["s1"]
	if !ok {
		t.Fatal("an unnamed 404 dropped the whole session")
	}
	if len(spool.pending) != 1 || spool.ring.dropped != 0 {
		t.Fatalf("the chunk was not kept for a retry (pending %d, dropped %d)", len(spool.pending), spool.ring.dropped)
	}

	tick()
	if len(shipper.puts()) != 1 {
		t.Fatal("the chunk was not shipped once the route answered again")
	}
}

func TestARejectedProxyTokenKeepsEverything(t *testing.T) {
	shipper := &fakeShipper{postDefault: scriptedResult{err: apiErr(http.StatusUnauthorized, proxyTokenRejectedName)}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	spool, ok := log.spools["s1"]
	if !ok {
		t.Fatal("the spool was dropped on a rejected proxy token")
	}
	if len(spool.pending) != 1 {
		t.Fatalf("the sealed chunk was not kept, pending holds %d", len(spool.pending))
	}
}

func TestTheCeilingPausesTheWholeProxyAndLiftsAfterTheBackoff(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(400, sessionLogCeilingReachedName)}}}
	log, advance, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	if !log.hold.dropsRecords(log.now()) || log.hold.off {
		t.Fatal("expected a ceiling pause")
	}

	log.record(testGrant("s2"), aRecord("api.github.com"))
	tick()
	if len(shipper.posts()) != 1 {
		t.Fatalf("a second session posted while paused; the pause is proxy-wide")
	}

	advance(sessionLogPauseBackoff + time.Second)
	log.flush(context.Background(), flushTick)
	if len(shipper.posts()) < 2 {
		t.Fatal("nothing was retried after the pause lifted")
	}
}

func TestBeingSwitchedOffDropsWhatWasHeldAndCountsIt(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(400, sessionLogDisabledName)}}}
	log, _, tick := newTestLog(shipper)
	grant := testGrant("s1")

	log.record(grant, aRecord("api.github.com"))
	log.record(grant, aRecord("api.github.com"))
	tick()

	spool := log.spools["s1"]
	if !log.hold.off || len(spool.pending) != 0 || spool.ring.len() != 0 {
		t.Fatalf("switched off=%v, pending=%d, ring=%d; expected everything held to be dropped",
			log.hold.off, len(spool.pending), spool.ring.len())
	}
	if spool.ring.dropped != 2 {
		t.Fatalf("%d records were counted as dropped, expected 2", spool.ring.dropped)
	}
	if log.total != 0 || log.sealedBytes != 0 {
		t.Fatalf("totals not restored: records=%d sealed bytes=%d", log.total, log.sealedBytes)
	}

	log.record(grant, aRecord("api.github.com"))
	tick()
	if len(shipper.posts()) != 1 {
		t.Fatal("the proxy kept sending while logging was switched off")
	}
	if spool.ring.dropped != 3 {
		t.Fatalf("a record made with the old key was not counted as dropped, got %d", spool.ring.dropped)
	}
}

func TestAKeyIssuedAfterTheSwitchOffResumesRecordingAtOnce(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(400, sessionLogDisabledName)}}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	log.record(testGrant("s1"), aRecord("api.github.com"))
	if log.hold.off {
		t.Fatal("a key issued after the refusal did not end the switch-off")
	}
	tick()

	posts := shipper.posts()
	if len(posts) != 2 || len(shipper.puts()) != 1 {
		t.Fatalf("posts=%d uploads=%d, expected the new record to ship", len(posts), len(shipper.puts()))
	}
	if posts[1].dropped != 1 {
		t.Fatalf("the chunk after the switch-off carried %d dropped, expected 1", posts[1].dropped)
	}
}

func TestARefusalRacingANewKeyDropsNothing(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(400, sessionLogDisabledName)}}}
	log, _, _ := newTestLog(shipper)
	grant := testGrant("s1")

	log.record(grant, aRecord("api.github.com"))
	log.switchOff(sessionLogGrantsIssued.Load() - 1)

	if log.hold.off || log.spools["s1"].ring.len() != 1 {
		t.Fatal("a refusal sent before a newer key was issued still dropped what was held")
	}
}

func TestDropsAreStillReportedAfterAnIdleSpoolIsForgotten(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(400, sessionLogDisabledName)}}}
	log, advance, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	advance(sessionLogIdleClose + time.Minute)
	log.flush(context.Background(), flushTick)
	if _, ok := log.spools["s1"]; ok {
		t.Fatal("the idle spool was not forgotten, so this test proves nothing")
	}

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	posts := shipper.posts()
	if len(posts) != 2 || posts[1].dropped != 1 {
		t.Fatalf("posts were %+v, expected the drop to survive the spool being forgotten", posts)
	}
}

func TestRecordsArePausedAsCountedGapsNotSilentLosses(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(400, sessionLogCeilingReachedName)}}}
	log, _, tick := newTestLog(shipper)
	grant := testGrant("s1")

	log.record(grant, aRecord("api.github.com"))
	tick()

	before := log.spools["s1"].ring.dropped
	for i := 0; i < 5; i++ {
		log.record(grant, aRecord("api.github.com"))
	}
	if got := log.spools["s1"].ring.dropped - before; got != 5 {
		t.Fatalf("%d records were counted as dropped while paused, expected 5", got)
	}
}

func TestAPoisonChunkIsDroppedAndTheRestShip(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(http.StatusUnprocessableEntity, "")}}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	if len(log.spools["s1"].pending) != 0 {
		t.Fatal("a chunk the server called malformed was kept; it would block the spool behind it")
	}

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()
	if len(shipper.puts()) != 1 {
		t.Fatalf("the next chunk did not ship after a poison one, %d uploads", len(shipper.puts()))
	}
}

func TestARefusedChunkIsCountedOnTheNextOne(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(http.StatusUnprocessableEntity, "")}}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()
	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	posts := shipper.posts()
	if len(posts) != 2 || posts[1].dropped != 1 {
		t.Fatalf("posts were %+v, expected the second to carry one dropped record", posts)
	}
}

func TestAClockSkewRefusalIsDroppedCountedAndLoggedOnce(t *testing.T) {
	skew := scriptedResult{err: apiErr(http.StatusBadRequest, sessionLogClockSkewName)}
	shipper := &fakeShipper{postResults: []scriptedResult{skew, skew}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()
	if len(log.spools["s1"].pending) != 0 {
		t.Fatal("a chunk refused for clock skew was kept")
	}
	if !log.clockSkewReported {
		t.Fatal("the first clock skew refusal was not reported")
	}

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()
	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	posts := shipper.posts()
	if len(posts) != 3 || posts[2].dropped != 2 {
		t.Fatalf("posts were %+v, expected the third to carry both refused records", posts)
	}
	if log.clockSkewReported {
		t.Fatal("an accepted chunk did not end the clock skew episode")
	}
}

func TestAFlushTooBigForOneChunkIsSplitBySize(t *testing.T) {
	shipper := &fakeShipper{postDefault: scriptedResult{err: errors.New("infisical unreachable")}}
	log, _, tick := newTestLog(shipper)
	grant := testGrant("s1")

	for i := 0; i < sessionLogFlushRecords; i++ {
		rec := aRecord("api.github.com")
		rec.Path = truncatePath("/" + strings.Repeat("&", maxLoggedPathLen))
		log.record(grant, rec)
	}
	tick()

	const gcmTag = 16
	pending := log.spools["s1"].pending
	if len(pending) < 2 {
		t.Fatalf("a ~12 MB flush sealed into %d chunk(s); it must be split", len(pending))
	}
	var next uint64
	var total int
	for i, chunk := range pending {
		if chunk.meta.CiphertextBytes-gcmTag > sessionLogMaxChunkPlaintext {
			t.Fatalf("chunk %d holds %d bytes of plaintext, over %d", i, chunk.meta.CiphertextBytes-gcmTag, sessionLogMaxChunkPlaintext)
		}
		if chunk.meta.FirstSeq != next {
			t.Fatalf("chunk %d starts at seq %d, expected %d; a record was lost or reordered", i, chunk.meta.FirstSeq, next)
		}
		next = chunk.meta.LastSeq + 1
		total += chunk.meta.RecordCount
	}
	if total != sessionLogFlushRecords {
		t.Fatalf("the chunks hold %d records, expected %d", total, sessionLogFlushRecords)
	}
}

func TestARateLimitIsRetriedRatherThanTreatedAsPoison(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(http.StatusTooManyRequests, "")}}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	if len(log.spools["s1"].pending) != 1 {
		t.Fatal("a 429 discarded the chunk; it means later, not never")
	}

	tick()
	if len(shipper.puts()) != 1 {
		t.Fatal("the chunk did not ship on the retry")
	}
}

func TestThePendingCapEvictsTheOldestAndCountsIt(t *testing.T) {
	shipper := &fakeShipper{postDefault: scriptedResult{err: errors.New("infisical unreachable")}}
	log, _, tick := newTestLog(shipper)
	grant := testGrant("s1")

	for i := 0; i < sessionLogPendingChunks+3; i++ {
		log.record(grant, aRecord("api.github.com"))
		tick()
	}

	spool := log.spools["s1"]
	if len(spool.pending) > sessionLogPendingChunks {
		t.Fatalf("pending holds %d chunks, the cap is %d", len(spool.pending), sessionLogPendingChunks)
	}
	if spool.ring.dropped == 0 {
		t.Fatal("evicted chunks were not counted as dropped records")
	}
}

func TestTheByteCapEvictsTheOldestChunkOnTheProxy(t *testing.T) {
	log, _, _ := newTestLog(&fakeShipper{})

	blob := make([]byte, 12<<20)
	add := func(sessionID string, order uint64, posted bool, carried uint64) *sessionLogSpool {
		spool, ok := log.spools[sessionID]
		if !ok {
			spool = newSessionLogSpool(testGrant(sessionID), log.now())
			log.spools[sessionID] = spool
		}
		spool.pending = append(spool.pending, &sealedChunk{
			meta:       api.CreateAgentVaultSessionLogChunkRequest{ChunkID: fmt.Sprintf("c%d", order), RecordCount: 100, DroppedCount: carried},
			ciphertext: blob,
			sealOrder:  order,
			posted:     posted,
		})
		log.sealedBytes += len(blob)
		return spool
	}

	log.mu.Lock()
	add("oldest", 0, false, 7)
	add("posted", 1, true, 3)
	var newest *sessionLogSpool
	for i := 2; i < 7; i++ {
		newest = add(fmt.Sprintf("s%d", i), uint64(i), false, 0)
	}
	log.enforcePendingCapsLocked(newest)
	log.mu.Unlock()

	if log.sealedBytes > sessionLogTotalSealedBytes {
		t.Fatalf("the proxy holds %d sealed bytes, past the %d cap", log.sealedBytes, sessionLogTotalSealedBytes)
	}
	if got := len(log.spools["oldest"].pending) + len(log.spools["posted"].pending); got != 0 {
		t.Fatalf("the two oldest chunks were not evicted, %d remain", got)
	}
	for i := 2; i < 7; i++ {
		if len(log.spools[fmt.Sprintf("s%d", i)].pending) != 1 {
			t.Fatalf("s%d lost its chunk; only the oldest should go", i)
		}
	}
	if got := log.spools["oldest"].ring.dropped; got != 107 {
		t.Fatalf("the unposted chunk counted %d dropped, expected 107", got)
	}
	if got := log.spools["posted"].ring.dropped; got != 0 {
		t.Fatalf("the posted chunk counted %d dropped, expected 0", got)
	}
}

func TestTheTickBreakerStopsHammeringADeadBucket(t *testing.T) {
	shipper := &fakeShipper{putDefault: errors.New("i/o timeout")}
	log, _, tick := newTestLog(shipper)

	for i := 0; i < 5; i++ {
		log.record(testGrant(fmt.Sprintf("s%d", i)), aRecord("api.github.com"))
	}
	tick()

	if got := len(shipper.puts()); got != 1 {
		t.Fatalf("%d uploads were attempted in one tick after the first failed", got)
	}
	if got := len(shipper.posts()); got != 1 {
		t.Fatalf("%d rows were written for objects that could not be uploaded", got)
	}
	for i := 0; i < 5; i++ {
		if len(log.spools[fmt.Sprintf("s%d", i)].pending) == 0 {
			t.Fatalf("spool s%d sealed nothing during the outage", i)
		}
	}
}

func TestReachingTheSliceSizeWakesTheLoopOnce(t *testing.T) {
	log, _, _ := newTestLog(&fakeShipper{})
	grant := testGrant("s1")

	for i := 0; i < sessionLogFlushRecords*2; i++ {
		log.record(grant, aRecord("api.github.com"))
	}

	if len(log.wake) != 1 {
		t.Fatalf("the wake channel holds %d, expected exactly one pending wake-up", len(log.wake))
	}
}

func TestAnIdleSpoolIsForgotten(t *testing.T) {
	shipper := &fakeShipper{}
	log, advance, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	advance(sessionLogIdleClose + time.Minute)
	log.flush(context.Background(), flushTick)

	if _, ok := log.spools["s1"]; ok {
		t.Fatal("an idle spool was kept; a long-lived proxy would grow without bound")
	}
}

func TestIdleCloseOutlastsTheSessionCacheTTL(t *testing.T) {
	if sessionLogIdleClose <= sessionInactiveTTL {
		t.Fatalf("idle close (%s) must outlast the session cache TTL (%s)", sessionLogIdleClose, sessionInactiveTTL)
	}
}

func TestCloseFlushesAndThenStopsRecording(t *testing.T) {
	shipper := &fakeShipper{}
	log, _, _ := newTestLog(shipper)
	grant := testGrant("s1")

	log.record(grant, aRecord("api.github.com"))
	log.close(context.Background())

	if len(shipper.puts()) != 1 {
		t.Fatalf("shutdown shipped %d chunks, expected the buffered one", len(shipper.puts()))
	}
	if !shipper.posts()[0].final {
		t.Fatal("the shutdown flush did not use the short-deadline client")
	}

	log.record(grant, aRecord("api.github.com"))
	log.flush(context.Background(), flushFinal)
	if len(shipper.puts()) != 1 {
		t.Fatal("a record was accepted after close")
	}
}

func TestABlockedHostIsStillRecorded(t *testing.T) {
	shipper := &fakeShipper{}
	log, _, _ := newTestLog(shipper)

	log.record(testGrant("s1"), sessionLogRecord{
		Method: "POST", Host: "evil.example", Port: "443", Path: "/collect", Status: 403, Decision: decisionBlocked,
	})
	log.flush(context.Background(), flushFinal)

	if len(shipper.puts()) != 1 {
		t.Fatal("a blocked request was not recorded")
	}
	spool := log.spools["s1"]
	if spool == nil {
		t.Fatal("no spool was created for a blocked request")
	}
}

func TestOneSpoolPerSession(t *testing.T) {
	log, _, _ := newTestLog(&fakeShipper{})

	log.record(testGrant("s1"), aRecord("api.github.com"))
	log.record(testGrant("s2"), aRecord("api.github.com"))
	log.record(testGrant("s1"), aRecord("api.anthropic.com"))

	if len(log.spools) != 2 {
		t.Fatalf("%d spools for two sessions", len(log.spools))
	}
	if log.spools["s1"].ring.len() != 2 {
		t.Fatalf("session one holds %d records, expected 2", log.spools["s1"].ring.len())
	}
}

func TestEveryRecordCarriesTheProxyAndATimestamp(t *testing.T) {
	log, _, _ := newTestLog(&fakeShipper{})
	log.record(testGrant("s1"), aRecord("api.github.com"))

	got := log.spools["s1"].ring.drain(1)[0]
	if got.ProxyID != "proxy-1" {
		t.Fatalf("record names proxy %q", got.ProxyID)
	}
	if _, err := time.Parse(time.RFC3339Nano, got.Ts); err != nil {
		t.Fatalf("timestamp %q is not RFC3339Nano: %v", got.Ts, err)
	}
	if got.Seq != 0 {
		t.Fatalf("the first record has seq %d, expected 0", got.Seq)
	}
}

func TestSequenceNumbersSurviveASpoolBeingForgotten(t *testing.T) {
	shipper := &fakeShipper{}
	log, advance, tick := newTestLog(shipper)
	grant := testGrant("s1")

	log.record(grant, aRecord("api.github.com"))
	log.record(grant, aRecord("api.github.com"))
	tick()

	advance(sessionLogIdleClose + time.Minute)
	log.flush(context.Background(), flushTick)
	if _, ok := log.spools["s1"]; ok {
		t.Fatal("the idle spool was not forgotten, so this test proves nothing")
	}

	log.record(grant, aRecord("api.github.com"))
	got := log.spools["s1"].ring.drain(1)[0]
	if got.Seq != 2 {
		t.Fatalf("seq restarted at %d after the spool was rebuilt, expected it to continue at 2", got.Seq)
	}
}

func TestAFullForgottenListDropsOnlyTheLongestForgottenSession(t *testing.T) {
	log, _, _ := newTestLog(&fakeShipper{})
	now := log.now()
	log.forgotten["oldest"] = forgottenSpool{nextSeq: 1, forgottenAt: now.Add(-2 * time.Hour)}
	for i := 1; i < maxSessionCacheEntries; i++ {
		log.forgotten[fmt.Sprintf("s%d", i)] = forgottenSpool{nextSeq: 1, forgottenAt: now.Add(-time.Hour)}
	}

	spool := newSessionLogSpool(testGrant("newest"), now)
	log.spools["newest"] = spool
	log.mu.Lock()
	log.forgetSpoolLocked("newest", spool)
	log.mu.Unlock()

	if len(log.forgotten) != maxSessionCacheEntries {
		t.Fatalf("the forgotten list holds %d sessions, want the cap of %d", len(log.forgotten), maxSessionCacheEntries)
	}
	if _, ok := log.forgotten["oldest"]; ok {
		t.Fatal("the longest forgotten session was kept")
	}
	if _, ok := log.forgotten["s1"]; !ok {
		t.Fatal("a more recently forgotten session was evicted too")
	}
	if _, ok := log.forgotten["newest"]; !ok {
		t.Fatal("the session just forgotten was not kept")
	}
}

func TestASessionThatIsGoneDoesNotReserveItsSequenceNumbers(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(http.StatusNotFound, infisicalNotFoundName)}}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	if _, ok := log.forgotten["s1"]; ok {
		t.Fatal("a session the server has forgotten is still holding a sequence number")
	}
}

func TestRecordsLostToASealFailureAreStillCounted(t *testing.T) {
	shipper := &fakeShipper{}
	log, _, tick := newTestLog(shipper)

	grant := &sessionLogGrant{sessionID: "s1", key: make([]byte, 7)}
	for i := 0; i < 3; i++ {
		log.record(grant, aRecord("api.github.com"))
	}
	tick()

	spool := log.spools["s1"]
	if spool == nil {
		t.Fatal("the spool disappeared")
	}
	if spool.ring.dropped != 3 {
		t.Fatalf("%d records were counted as dropped after a seal failure, expected 3", spool.ring.dropped)
	}
	if len(shipper.posts()) != 0 {
		t.Fatal("a chunk was shipped despite the seal failing")
	}
}

func TestAnUnreachableControlPlaneStopsTheTickAfterOneTimeout(t *testing.T) {
	shipper := &fakeShipper{postDefault: scriptedResult{err: errors.New("i/o timeout")}}
	log, _, tick := newTestLog(shipper)

	for i := 0; i < 5; i++ {
		log.record(testGrant(fmt.Sprintf("s%d", i)), aRecord("api.github.com"))
	}
	tick()

	if got := len(shipper.posts()); got != 1 {
		t.Fatalf("%d chunk POSTs were attempted in one tick after the first timed out", got)
	}
	for i := 0; i < 5; i++ {
		if len(log.spools[fmt.Sprintf("s%d", i)].pending) == 0 {
			t.Fatalf("spool s%d sealed nothing during the outage", i)
		}
	}
}

func TestShutdownPastItsBudgetStartsNoNewChunk(t *testing.T) {
	shipper := &fakeShipper{}
	log, _, _ := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	spent, cancel := context.WithCancel(context.Background())
	cancel()
	log.close(spent)

	if len(shipper.posts()) != 0 {
		t.Fatal("a chunk was posted after the shutdown budget ran out, leaving a row that can never be uploaded")
	}
}

type slowPutShipper struct {
	*fakeShipper
	advance func(time.Duration)
}

func (s *slowPutShipper) putObject(ctx context.Context, url string, ciphertext []byte) error {
	s.advance(2 * time.Second)
	return s.fakeShipper.putObject(ctx, url, ciphertext)
}

func TestEverySessionShipsOnEveryTickWhileEarlierOnesTakeTimeToUpload(t *testing.T) {
	shipper := &slowPutShipper{fakeShipper: &fakeShipper{}}
	log, advance, _ := newTestLog(shipper)
	shipper.advance = advance

	tickAt := log.now()
	for i := 1; i <= 3; i++ {
		log.record(testGrant("s1"), aRecord("api.github.com"))
		log.record(testGrant("s2"), aRecord("api.github.com"))
		tickAt = tickAt.Add(sessionLogFlushInterval)
		advance(tickAt.Sub(log.now()))
		log.flush(context.Background(), flushTick)

		if got := len(shipper.puts()); got != 2*i {
			t.Fatalf("after tick %d there were %d uploads; every session should ship on every tick", i, got)
		}
	}
}

func TestASessionShipsAtATickThatLandsJustShortOfAMinute(t *testing.T) {
	shipper := &fakeShipper{}
	log, advance, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()
	log.record(testGrant("s1"), aRecord("api.github.com"))
	advance(sessionLogFlushInterval - 10*time.Millisecond)
	log.flush(context.Background(), flushTick)

	if got := len(shipper.puts()); got != 2 {
		t.Fatalf("there were %d uploads; a tick a few milliseconds early skipped the session", got)
	}
}

func TestASessionDoesNotShipAgainHalfwayToTheNextTick(t *testing.T) {
	shipper := &fakeShipper{}
	log, advance, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()
	log.record(testGrant("s1"), aRecord("api.github.com"))
	advance(sessionLogFlushInterval / 2)
	log.flush(context.Background(), flushTick)

	if got := len(shipper.puts()); got != 1 {
		t.Fatalf("there were %d uploads; a session shipped twice within one interval", got)
	}
}

func TestEveryWayAChunkLeavesReleasesWhatItHeld(t *testing.T) {
	for _, outcome := range []struct {
		name string
		post scriptedResult
	}{
		{"uploaded", scriptedResult{}},
		{"refused as bad", scriptedResult{err: apiErr(http.StatusUnprocessableEntity, "")}},
		{"session gone", scriptedResult{err: apiErr(http.StatusNotFound, infisicalNotFoundName)}},
	} {
		shipper := &fakeShipper{postResults: []scriptedResult{outcome.post}}
		log, _, tick := newTestLog(shipper)

		log.record(testGrant("s1"), aRecord("api.github.com"))
		tick()

		if log.total != 0 || log.sealedBytes != 0 {
			t.Fatalf("%s: the proxy still counts %d records and %d sealed bytes; the pending cap would fill and stop recording",
				outcome.name, log.total, log.sealedBytes)
		}
	}
}

func TestServerErrorsAreRetriedAndBadChunksAreDropped(t *testing.T) {
	for _, tc := range []struct {
		status int
		kept   bool
	}{
		{http.StatusInternalServerError, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusTooManyRequests, true},
		{http.StatusRequestTimeout, true},
		{http.StatusNotFound, true},
		{http.StatusUnprocessableEntity, false},
		{http.StatusConflict, false},
	} {
		shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(tc.status, "")}}}
		log, _, tick := newTestLog(shipper)

		log.record(testGrant("s1"), aRecord("api.github.com"))
		tick()

		spool := log.spools["s1"]
		if tc.kept {
			if len(spool.pending) != 1 || !log.hold.infisicalDown {
				t.Fatalf("%d: the chunk was not kept for a retry (pending %d, infisicalDown %v)", tc.status, len(spool.pending), log.hold.infisicalDown)
			}
			continue
		}
		if len(spool.pending) != 0 || spool.ring.dropped != 1 {
			t.Fatalf("%d: a refused chunk was not dropped and counted (pending %d, dropped %d)", tc.status, len(spool.pending), spool.ring.dropped)
		}
	}
}

func TestTheRecorderShipsNoChunkOverTheServersRecordLimit(t *testing.T) {
	shipper := &fakeShipper{}
	log, _, _ := newTestLog(shipper)

	for i := 0; i < 2500; i++ {
		log.record(testGrant("s1"), aRecord("api.github.com"))
	}
	log.flush(context.Background(), flushFinal)

	posts := shipper.posts()
	if len(posts) != 3 {
		t.Fatalf("2500 records shipped as %d chunks, expected 3", len(posts))
	}
	total := 0
	for _, post := range posts {
		if post.records > sessionLogFlushRecords {
			t.Fatalf("a chunk carried %d records; the server refuses more than %d", post.records, sessionLogFlushRecords)
		}
		total += post.records
	}
	if total != 2500 {
		t.Fatalf("the chunks carried %d records, expected 2500", total)
	}
}

type blockingShipper struct {
	fakeShipper
	entered chan struct{}
	release chan struct{}
	again   chan struct{}
	once    sync.Once
	posted  int
}

func (b *blockingShipper) createChunk(ctx context.Context, final bool, sessionID string, req api.CreateAgentVaultSessionLogChunkRequest) (api.CreateAgentVaultSessionLogChunkResponse, error) {
	b.mu.Lock()
	b.posted++
	first := b.posted == 1
	b.mu.Unlock()
	if first {
		close(b.entered)
		<-b.release
	} else {
		b.once.Do(func() { close(b.again) })
	}
	return b.fakeShipper.createChunk(ctx, final, sessionID, req)
}

func TestShutdownWaitsForAFlushInProgressSoNoChunkShipsTwice(t *testing.T) {
	shipper := &blockingShipper{entered: make(chan struct{}), release: make(chan struct{}), again: make(chan struct{})}
	log, advance, _ := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	advance(sessionLogFlushInterval)

	tickDone := make(chan struct{})
	go func() {
		defer close(tickDone)
		log.flush(context.Background(), flushTick)
	}()
	<-shipper.entered

	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		log.close(context.Background())
	}()

	select {
	case <-shipper.again:
		close(shipper.release)
		t.Fatal("shutdown posted a chunk while the run loop was still shipping it")
	case <-time.After(200 * time.Millisecond):
	}

	close(shipper.release)
	<-tickDone
	<-closeDone

	seen := map[string]int{}
	for _, post := range shipper.posts() {
		seen[post.chunkID]++
	}
	for chunkID, n := range seen {
		if n != 1 {
			t.Fatalf("chunk %s was posted %d times", chunkID, n)
		}
	}
	if len(seen) != 1 || len(shipper.puts()) != 1 {
		t.Fatalf("one record shipped as %d chunks and %d uploads, expected 1 of each", len(seen), len(shipper.puts()))
	}
}

func TestAChunkSpansItsEarliestAndLatestRecordWhenTheClockSteps(t *testing.T) {
	log, advance, _ := newTestLog(&fakeShipper{})
	grant := testGrant("s1")

	advance(100 * time.Millisecond)
	log.record(grant, aRecord("api.github.com"))
	advance(-100 * time.Millisecond)
	log.record(grant, aRecord("api.github.com"))
	advance(50 * time.Millisecond)
	log.record(grant, aRecord("api.github.com"))

	spool := log.spools["s1"]
	chunk, err := spool.sealSlice(spool.ring.drain(3), []byte("[]"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if chunk.meta.StartedAt != "2026-09-16T10:00:00Z" || chunk.meta.EndedAt != "2026-09-16T10:00:00.1Z" {
		t.Fatalf("the chunk spans %s to %s, expected the earliest and latest record", chunk.meta.StartedAt, chunk.meta.EndedAt)
	}
	if chunk.meta.FirstSeq != 0 || chunk.meta.LastSeq != 2 {
		t.Fatalf("the chunk spans seq %d to %d, expected the first and last record", chunk.meta.FirstSeq, chunk.meta.LastSeq)
	}
}

func TestAWakeDoesNotResetTheBreakers(t *testing.T) {
	shipper := &fakeShipper{putDefault: errors.New("bucket down")}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()
	if !log.hold.s3Down {
		t.Fatal("a failed upload did not trip the breaker, so this test proves nothing")
	}
	putsAfterTick := len(shipper.puts())

	for i := 0; i < sessionLogFlushRecords; i++ {
		log.record(testGrant("s1"), aRecord("api.github.com"))
	}
	log.flush(context.Background(), flushWake)

	if !log.hold.s3Down {
		t.Fatal("a wake reset the breaker")
	}
	if got := len(shipper.puts()); got != putsAfterTick {
		t.Fatalf("a wake retried the bucket %d times while it was down", got-putsAfterTick)
	}

	tick()
	if got := len(shipper.puts()); got == putsAfterTick {
		t.Fatal("the next tick did not retry the bucket")
	}
}

func TestAWakeShipsOnlyFullRings(t *testing.T) {
	shipper := &fakeShipper{}
	log, advance, _ := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	for i := 0; i < sessionLogFlushRecords; i++ {
		log.record(testGrant("s2"), aRecord("api.github.com"))
	}
	advance(sessionLogFlushInterval)
	log.flush(context.Background(), flushWake)

	posts := shipper.posts()
	if len(posts) != 1 || posts[0].sessionID != "s2" {
		t.Fatalf("a wake shipped %d chunks, expected only the full ring of s2", len(posts))
	}
	if got := log.spools["s1"].ring.len(); got != 1 {
		t.Fatalf("s1 holds %d records after the wake, expected it to wait for the tick", got)
	}
}
