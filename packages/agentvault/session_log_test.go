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

	delay time.Duration
}

func (f *fakeShipper) createChunk(_ context.Context, final bool, sessionID string, req api.CreateAgentVaultSessionLogChunkRequest) (api.CreateAgentVaultSessionLogChunkResponse, error) {
	time.Sleep(f.delay)
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, shipperCall{kind: "post", sessionID: sessionID, chunkID: req.ChunkID, bytes: req.CiphertextBytes, records: req.RecordCount, final: final})

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
	time.Sleep(f.delay)
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
	if ring.unreportedDrops != 2 {
		t.Fatalf("ring counted %d drops, expected 2", ring.unreportedDrops)
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
	if ring.unreportedDrops != 0 {
		t.Fatalf("growth counted %d drops; nothing was over capacity", ring.unreportedDrops)
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

func TestTheDropCountIsLoggedOnceAtTheNextSeal(t *testing.T) {
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
	if log.spools["s1"].ring.unreportedDrops != 0 {
		t.Fatal("the drop count was not reset after being logged")
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

func TestTheProxyWideFuseDropsTheNewestAndCountsThem(t *testing.T) {
	log, _, _ := newTestLog(&fakeShipper{})

	sessions := sessionLogTotalCapacity/sessionLogSpoolCapacity + 2
	for i := 0; i < sessions; i++ {
		grant := testGrant(fmt.Sprintf("s%d", i))
		for j := 0; j < sessionLogSpoolCapacity; j++ {
			log.record(grant, aRecord("api.github.com"))
		}
	}

	if log.unsealedRecords > sessionLogTotalCapacity {
		t.Fatalf("the proxy holds %d records, past the %d fuse", log.unsealedRecords, sessionLogTotalCapacity)
	}
	var counted uint64
	for _, spool := range log.spools {
		counted += spool.ring.unreportedDrops
	}
	if want := uint64(sessions*sessionLogSpoolCapacity - sessionLogTotalCapacity); counted != want {
		t.Fatalf("the fuse counted %d dropped requests, expected %d; nothing else reports them", counted, want)
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
	if len(spool.pending) != 1 || spool.ring.unreportedDrops != 0 {
		t.Fatalf("the chunk was not kept for a retry (pending %d, dropped %d)", len(spool.pending), spool.ring.unreportedDrops)
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

func TestBeingSwitchedOffDropsWhatWasHeld(t *testing.T) {
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
	if log.unsealedRecords != 0 || log.sealedBytes != 0 {
		t.Fatalf("totals not restored: records=%d sealed bytes=%d", log.unsealedRecords, log.sealedBytes)
	}

	log.record(grant, aRecord("api.github.com"))
	tick()
	if len(shipper.posts()) != 1 {
		t.Fatal("the proxy kept sending while logging was switched off")
	}
	if spool.ring.len() != 0 {
		t.Fatal("a record made with the old key was kept while logging was switched off")
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

func TestAClockSkewRefusalIsDroppedAndLoggedOnce(t *testing.T) {
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
	if len(posts) != 3 {
		t.Fatalf("posts were %+v, expected all three chunks to be sent", posts)
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

	const overhead = sessionLogIVBytes + 16
	pending := log.spools["s1"].pending
	if len(pending) < 2 {
		t.Fatalf("a ~12 MB flush sealed into %d chunk(s); it must be split", len(pending))
	}
	var total int
	for i, chunk := range pending {
		if chunk.meta.CiphertextBytes-overhead > sessionLogMaxChunkPlaintext {
			t.Fatalf("chunk %d holds %d bytes of plaintext, over %d", i, chunk.meta.CiphertextBytes-overhead, sessionLogMaxChunkPlaintext)
		}
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

func TestThePendingCapEvictsTheOldest(t *testing.T) {
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
}

func TestTheByteCapEvictsTheOldestChunkOnTheProxy(t *testing.T) {
	log, _, _ := newTestLog(&fakeShipper{})

	blob := make([]byte, 12<<20)
	add := func(sessionID string, order uint64) *sessionLogSpool {
		spool, ok := log.spools[sessionID]
		if !ok {
			spool = newSessionLogSpool(testGrant(sessionID), log.now())
			log.spools[sessionID] = spool
		}
		spool.pending = append(spool.pending, &sealedChunk{
			meta:       api.CreateAgentVaultSessionLogChunkRequest{ChunkID: fmt.Sprintf("c%d", order), RecordCount: 100},
			ciphertext: blob,
			sealOrder:  order,
		})
		log.sealedBytes += len(blob)
		return spool
	}

	log.mu.Lock()
	add("oldest", 0)
	add("posted", 1)
	var newest *sessionLogSpool
	for i := 2; i < 7; i++ {
		newest = add(fmt.Sprintf("s%d", i), uint64(i))
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
}

func TestTheTickBreakerStopsHammeringADeadBucket(t *testing.T) {
	shipper := &fakeShipper{putDefault: errors.New("i/o timeout")}
	log, _, tick := newTestLog(shipper)

	sessions := 2*sessionLogShipParallelism + 1
	for i := 0; i < sessions; i++ {
		log.record(testGrant(fmt.Sprintf("s%d", i)), aRecord("api.github.com"))
	}
	tick()

	// One round goes out at once; the breaker has to stop the rounds after it.
	if got := len(shipper.puts()); got != sessionLogShipParallelism {
		t.Fatalf("%d uploads were attempted in one tick, want one round of %d", got, sessionLogShipParallelism)
	}
	if got := len(shipper.posts()); got != sessionLogShipParallelism {
		t.Fatalf("%d rows were written for objects that could not be uploaded, want one round of %d", got, sessionLogShipParallelism)
	}
	for i := 0; i < sessions; i++ {
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
	log.forgotten.remember("oldest", forgottenSpool{nextSeq: 1})
	for i := 1; i < sessionLogForgottenCapacity; i++ {
		log.forgotten.remember(fmt.Sprintf("s%d", i), forgottenSpool{nextSeq: 1})
	}

	spool := newSessionLogSpool(testGrant("newest"), now)
	log.spools["newest"] = spool
	log.mu.Lock()
	log.forgetSpoolLocked("newest", spool)
	log.mu.Unlock()

	if log.forgotten.len() != sessionLogForgottenCapacity {
		t.Fatalf("the forgotten list holds %d sessions, want the cap of %d", log.forgotten.len(), sessionLogForgottenCapacity)
	}
	if _, ok := log.forgotten.byID["oldest"]; ok {
		t.Fatal("the longest forgotten session was kept")
	}
	if _, ok := log.forgotten.byID["s1"]; !ok {
		t.Fatal("a more recently forgotten session was evicted too")
	}
	if _, ok := log.forgotten.byID["newest"]; !ok {
		t.Fatal("the session just forgotten was not kept")
	}
}

func TestASessionThatIsGoneDoesNotReserveItsSequenceNumbers(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(http.StatusNotFound, infisicalNotFoundName)}}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	if _, ok := log.forgotten.byID["s1"]; ok {
		t.Fatal("a session the server has forgotten is still holding a sequence number")
	}
}

func TestRecordsLostToASealFailureAreNotShipped(t *testing.T) {
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
	if spool.ring.len() != 0 || len(spool.pending) != 0 {
		t.Fatalf("records that failed to seal were kept (ring %d, pending %d)", spool.ring.len(), len(spool.pending))
	}
	if len(shipper.posts()) != 0 {
		t.Fatal("a chunk was shipped despite the seal failing")
	}
}

func TestAnUnreachableControlPlaneStopsTheTickAfterOneTimeout(t *testing.T) {
	shipper := &fakeShipper{postDefault: scriptedResult{err: errors.New("i/o timeout")}}
	log, _, tick := newTestLog(shipper)

	sessions := 2*sessionLogShipParallelism + 1
	for i := 0; i < sessions; i++ {
		log.record(testGrant(fmt.Sprintf("s%d", i)), aRecord("api.github.com"))
	}
	tick()

	if got := len(shipper.posts()); got != sessionLogShipParallelism {
		t.Fatalf("%d chunk POSTs were attempted in one tick, want one round of %d", got, sessionLogShipParallelism)
	}
	for i := 0; i < sessions; i++ {
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

		if log.unsealedRecords != 0 || log.sealedBytes != 0 {
			t.Fatalf("%s: the proxy still counts %d records and %d sealed bytes; the pending cap would fill and stop recording",
				outcome.name, log.unsealedRecords, log.sealedBytes)
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
		{http.StatusUnauthorized, true},
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
		if len(spool.pending) != 0 {
			t.Fatalf("%d: a refused chunk was not dropped (pending %d)", tc.status, len(spool.pending))
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
	chunk, err := spool.sealSlice(spool.ring.drain(3), []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if chunk.meta.StartedAt != "2026-09-16T10:00:00Z" || chunk.meta.EndedAt != "2026-09-16T10:00:00.1Z" {
		t.Fatalf("the chunk spans %s to %s, expected the earliest and latest record", chunk.meta.StartedAt, chunk.meta.EndedAt)
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

func TestAPassShipsSessionsInParallel(t *testing.T) {
	shipper := &fakeShipper{delay: 100 * time.Millisecond}
	log, _, tick := newTestLog(shipper)

	for i := 0; i < sessionLogShipParallelism; i++ {
		log.record(testGrant(fmt.Sprintf("s%d", i)), aRecord("api.github.com"))
	}
	started := time.Now()
	tick()
	took := time.Since(started)

	if got := len(shipper.puts()); got != sessionLogShipParallelism {
		t.Fatalf("%d chunks were uploaded, want %d", got, sessionLogShipParallelism)
	}
	// In series this is 16 calls of 100ms; one round is two.
	if took > 800*time.Millisecond {
		t.Fatalf("shipping %d sessions took %s, which is serial; want about one round trip", sessionLogShipParallelism, took)
	}
}

type observingShipper struct {
	*fakeShipper
	onPost func()
}

func (o *observingShipper) createChunk(ctx context.Context, final bool, sessionID string, req api.CreateAgentVaultSessionLogChunkRequest) (api.CreateAgentVaultSessionLogChunkResponse, error) {
	o.onPost()
	return o.fakeShipper.createChunk(ctx, final, sessionID, req)
}

// Sealing every busy session before the first upload could pass the byte cap and evict chunks while the
// bucket is fine, so a healthy pass holds no more than the round it is shipping.
func TestAHealthyPassSealsOnlyTheRoundItShips(t *testing.T) {
	var log *sessionLogRecorder
	var mostQueued int
	shipper := &observingShipper{fakeShipper: &fakeShipper{}, onPost: func() {
		log.mu.Lock()
		defer log.mu.Unlock()
		queued := 0
		for _, spool := range log.spools {
			queued += len(spool.pending)
		}
		mostQueued = max(mostQueued, queued)
	}}
	log, _, tick := newTestLog(shipper)

	sessions := 3 * sessionLogShipParallelism
	for i := 0; i < sessions; i++ {
		grant := testGrant(fmt.Sprintf("s%d", i))
		for j := 0; j < 2*sessionLogFlushRecords; j++ {
			log.record(grant, aRecord("api.github.com"))
		}
	}
	tick()

	if mostQueued > sessionLogShipParallelism {
		t.Fatalf("%d chunks were sealed while a round was shipping, want at most one round of %d", mostQueued, sessionLogShipParallelism)
	}
	if got, want := len(shipper.puts()), 2*sessions; got != want {
		t.Fatalf("%d chunks were uploaded, want %d", got, want)
	}
	for id, spool := range log.spools {
		if spool.heldRecords() != 0 || spool.ring.unreportedDrops != 0 {
			t.Fatalf("spool %s still holds %d records and %d drops after a healthy pass", id, spool.heldRecords(), spool.ring.unreportedDrops)
		}
	}
}

// Resealing whatever arrived since the last round would ship a busy session one request per round, and never end
// the pass while its agent keeps working.
func TestRequestsArrivingDuringAPassWaitForTheNext(t *testing.T) {
	var log *sessionLogRecorder
	grant := testGrant("s1")
	shipper := &observingShipper{fakeShipper: &fakeShipper{}, onPost: func() {
		log.record(grant, aRecord("api.github.com"))
	}}
	log, _, tick := newTestLog(shipper)

	for i := 0; i < 10; i++ {
		log.record(grant, aRecord("api.github.com"))
	}
	tick()

	posts := shipper.posts()
	if len(posts) != 1 || posts[0].records != 10 {
		t.Fatalf("the pass sent %d chunks, want one with the 10 records it started with", len(posts))
	}
	if got := log.spools["s1"].ring.len(); got != 1 {
		t.Fatalf("the ring holds %d records, want the 1 that arrived during the upload", got)
	}
}

func TestAWakeShipsWhatArrivedDuringThePassBeforeIt(t *testing.T) {
	var log *sessionLogRecorder
	var once sync.Once
	grant := testGrant("s1")
	shipper := &observingShipper{fakeShipper: &fakeShipper{}, onPost: func() {
		once.Do(func() {
			for i := 0; i < sessionLogFlushRecords; i++ {
				log.record(grant, aRecord("api.github.com"))
			}
		})
	}}
	log, _, tick := newTestLog(shipper)

	for i := 0; i < sessionLogFlushRecords; i++ {
		log.record(grant, aRecord("api.github.com"))
	}
	<-log.wake
	tick()
	if got := len(shipper.puts()); got != 1 {
		t.Fatalf("the tick uploaded %d chunks, want only the one it started with", got)
	}
	if len(log.wake) != 1 {
		t.Fatal("the records that arrived during the upload didn't queue a wake")
	}

	<-log.wake
	log.flush(context.Background(), flushWake)
	if got := len(shipper.puts()); got != 2 {
		t.Fatalf("%d chunks were uploaded after the wake, want 2", got)
	}
	if held := log.spools["s1"].heldRecords(); held != 0 {
		t.Fatalf("the spool still holds %d records after the wake", held)
	}
}

func TestStopWinsOverAReadyWake(t *testing.T) {
	shipper := &fakeShipper{}
	log, _, _ := newTestLog(shipper)
	grant := testGrant("s1")
	for i := 0; i < sessionLogFlushRecords; i++ {
		log.record(grant, aRecord("api.github.com"))
	}

	stop := make(chan struct{})
	close(stop)
	log.run(stop)

	if got := len(shipper.posts()); got != 0 {
		t.Fatalf("a pass started after stop: %d chunks were posted", got)
	}
}

type passBlockingShipper struct {
	fakeShipper
	entered chan struct{}
}

func (b *passBlockingShipper) createChunk(ctx context.Context, final bool, sessionID string, req api.CreateAgentVaultSessionLogChunkRequest) (api.CreateAgentVaultSessionLogChunkResponse, error) {
	if !final {
		close(b.entered)
		<-ctx.Done()
		return api.CreateAgentVaultSessionLogChunkResponse{}, ctx.Err()
	}
	return b.fakeShipper.createChunk(ctx, final, sessionID, req)
}

func TestStopCancelsAPassInFlightSoTheFinalFlushShipsIt(t *testing.T) {
	shipper := &passBlockingShipper{entered: make(chan struct{})}
	log, _, _ := newTestLog(shipper)
	grant := testGrant("s1")
	for i := 0; i < sessionLogFlushRecords; i++ {
		log.record(grant, aRecord("api.github.com"))
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		log.run(stop)
		close(done)
	}()
	<-shipper.entered
	close(stop)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the pass in flight was not cancelled by stop")
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionLogCloseTimeout)
	defer cancel()
	log.close(ctx)
	if got := len(shipper.puts()); got != 1 {
		t.Fatalf("the final flush uploaded %d chunks, want the one the cancelled pass left", got)
	}
}

func TestATokenErrorHoldsTheChunk(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(http.StatusForbidden, sessionLogTokenErrorName)}}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	spool := log.spools["s1"]
	if len(spool.pending) != 1 || spool.ring.unreportedDrops != 0 {
		t.Fatalf("a TokenError dropped the chunk (pending %d, dropped %d); it should be held until the proxy logs in again", len(spool.pending), spool.ring.unreportedDrops)
	}
}

// Stalls chosen calls until their context ends, the way a request that never returns does, and slows others.
type stallingShipper struct {
	*fakeShipper
	mu        sync.Mutex
	posts     int
	putsSeen  int
	stallPost func(n int) bool
	stallPut  func(n int) bool
	slowPut   func(n int) time.Duration
}

func (s *stallingShipper) createChunk(ctx context.Context, final bool, sessionID string, req api.CreateAgentVaultSessionLogChunkRequest) (api.CreateAgentVaultSessionLogChunkResponse, error) {
	s.mu.Lock()
	s.posts++
	n := s.posts
	s.mu.Unlock()
	if s.stallPost != nil && s.stallPost(n) {
		<-ctx.Done()
		return api.CreateAgentVaultSessionLogChunkResponse{}, ctx.Err()
	}
	return s.fakeShipper.createChunk(ctx, final, sessionID, req)
}

func (s *stallingShipper) putObject(ctx context.Context, url string, ciphertext []byte) error {
	s.mu.Lock()
	s.putsSeen++
	n := s.putsSeen
	s.mu.Unlock()
	if s.stallPut != nil && s.stallPut(n) {
		<-ctx.Done()
		return ctx.Err()
	}
	if s.slowPut != nil {
		time.Sleep(s.slowPut(n))
	}
	return s.fakeShipper.putObject(ctx, url, ciphertext)
}

// Shipping at shutdown in rounds of eight let one stuck request hold the rest past the close budget.
func TestOneStuckRequestAtShutdownDoesNotHoldBackTheOtherSessions(t *testing.T) {
	const sessions = 60
	cases := []struct {
		name    string
		shipper func() *stallingShipper
	}{
		{"an upload that never returns", func() *stallingShipper {
			return &stallingShipper{fakeShipper: &fakeShipper{}, stallPut: func(n int) bool { return n == 1 }}
		}},
		{"a row request that never returns", func() *stallingShipper {
			return &stallingShipper{fakeShipper: &fakeShipper{}, stallPost: func(n int) bool { return n == 1 }}
		}},
		{"one upload in eight taking a while", func() *stallingShipper {
			return &stallingShipper{fakeShipper: &fakeShipper{}, slowPut: func(n int) time.Duration {
				if n%8 == 0 {
					return 300 * time.Millisecond
				}
				return 0
			}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shipper := tc.shipper()
			log, _, _ := newTestLog(shipper)
			for i := 0; i < sessions; i++ {
				log.record(testGrant(fmt.Sprintf("s%d", i)), aRecord("api.github.com"))
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			log.close(ctx)

			held := 0
			for _, spool := range log.spools {
				if spool.heldRecords() > 0 {
					held++
				}
			}
			stuck := 0
			if shipper.stallPut != nil || shipper.stallPost != nil {
				stuck = 1
			}
			if held != stuck {
				t.Fatalf("%d sessions were left unshipped at shutdown, want only the %d with the stuck request", held, stuck)
			}
		})
	}
}
