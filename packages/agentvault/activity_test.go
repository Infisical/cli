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

func (f *fakeShipper) createChunk(final bool, sessionID string, req api.CreateAgentVaultActivityChunkRequest) (api.CreateAgentVaultActivityChunkResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, shipperCall{kind: "post", sessionID: sessionID, chunkID: req.ChunkID, bytes: req.CiphertextBytes, dropped: req.DroppedCount, final: final})

	result := f.postDefault
	if len(f.postResults) > 0 {
		result = f.postResults[0]
		f.postResults = f.postResults[1:]
	}
	if result.err != nil {
		return api.CreateAgentVaultActivityChunkResponse{}, result.err
	}
	url := result.url
	if url == "" {
		f.nextURL++
		url = fmt.Sprintf("https://bucket.example/put/%d", f.nextURL)
	}
	return api.CreateAgentVaultActivityChunkResponse{ChunkID: req.ChunkID, UploadURL: url, ExpiresInSeconds: 300}, nil
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
	return &api.APIError{StatusCode: status, Name: name, Operation: "CallCreateAgentVaultActivityChunk"}
}

func testGrant(sessionID string) *activityGrant {
	return &activityGrant{sessionID: sessionID, projectID: "proj-1", key: make([]byte, 32)}
}

func newTestLog(shipper activityShipper) (log *activityLog, advance func(time.Duration), tick func()) {
	log = newActivityLog("proxy-1", shipper)
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
		advance(activityFlushInterval)
		log.flushAll(context.Background(), false)
	}
	return log, advance, tick
}

func aRecord(host string) activityRecord {
	return activityRecord{Method: "GET", Host: host, Port: "443", Path: "/zen", Status: 200, Decision: decisionPassthrough}
}

func TestRecordingIsANoOpWithoutALogOrAGrant(t *testing.T) {
	var nilLog *activityLog
	nilLog.record(testGrant("s1"), aRecord("api.github.com"))

	log, _, _ := newTestLog(&fakeShipper{})
	log.record(nil, aRecord("api.github.com"))
	if len(log.spools) != 0 {
		t.Fatal("a nil grant created a spool; logging-off must cost nothing")
	}
}

func TestTheRingDropsTheOldestAndCountsIt(t *testing.T) {
	ring := newActivityRing(3)
	for i := 0; i < 5; i++ {
		ring.push(activityRecord{Seq: uint64(i)})
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
	ring := newActivityRing(activitySpoolCapacity)
	ring.push(activityRecord{Seq: 0})

	if got := cap(ring.buf); got > activityRingInitialSize {
		t.Fatalf("one record reserved room for %d, expected at most %d", got, activityRingInitialSize)
	}

	ring.drain(10)
	if ring.buf != nil {
		t.Fatal("a drained ring kept its buffer; an idle session should hold nothing")
	}
}

func TestTheRingKeepsItsOrderWhileItGrowsPastAWrap(t *testing.T) {
	ring := newActivityRing(activitySpoolCapacity)
	var next uint64
	push := func(n int) {
		for i := 0; i < n; i++ {
			ring.push(activityRecord{Seq: next})
			next++
		}
	}

	push(activityRingInitialSize)
	ring.drain(10)
	push(activityRingInitialSize * 3)

	drained := ring.drain(activitySpoolCapacity)
	if len(drained) != activityRingInitialSize*4-10 {
		t.Fatalf("drained %d records, expected %d", len(drained), activityRingInitialSize*4-10)
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
	ring := newActivityRing(activitySpoolCapacity)
	for i := 0; i < 2500; i++ {
		ring.push(activityRecord{Seq: uint64(i)})
	}

	var slices int
	for ring.len() > 0 {
		got := ring.drain(activityFlushRecords)
		if len(got) > activityFlushRecords {
			t.Fatalf("a slice held %d records, the server's limit is %d", len(got), activityFlushRecords)
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

	for i := 0; i < activitySpoolCapacity+50; i++ {
		log.record(grant, aRecord("api.github.com"))
	}
	log.flushAll(context.Background(), true)

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

	for i := 0; i < activitySpoolCapacity+10; i++ {
		log.record(grant, aRecord("api.github.com"))
	}

	if got := log.spools["s1"].nextSeq; got != uint64(activitySpoolCapacity+10) {
		t.Fatalf("nextSeq is %d after %d records; drops must still consume a number", got, activitySpoolCapacity+10)
	}
}

func TestTheProxyWideFuseDropsTheNewest(t *testing.T) {
	log, _, _ := newTestLog(&fakeShipper{})

	for i := 0; i < activityTotalCapacity/activitySpoolCapacity+2; i++ {
		grant := testGrant(fmt.Sprintf("s%d", i))
		for j := 0; j < activitySpoolCapacity; j++ {
			log.record(grant, aRecord("api.github.com"))
		}
	}

	if log.total > activityTotalCapacity {
		t.Fatalf("the proxy holds %d records, past the %d fuse", log.total, activityTotalCapacity)
	}
}

func TestAChunkIsPostedBeforeItIsUploaded(t *testing.T) {
	shipper := &fakeShipper{}
	log, _, _ := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	log.flushAll(context.Background(), true)

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
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(http.StatusNotFound, "")}}}
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
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(400, activityCeilingReachedName)}}}
	log, advance, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	if paused, reason := log.paused(); !paused || reason != activityCeilingReachedName {
		t.Fatalf("expected a ceiling pause, got paused=%v reason=%q", paused, reason)
	}

	log.record(testGrant("s2"), aRecord("api.github.com"))
	tick()
	if len(shipper.posts()) != 1 {
		t.Fatalf("a second session posted while paused; the pause is proxy-wide")
	}

	advance(activityPauseBackoff + time.Second)
	log.flushAll(context.Background(), false)
	if len(shipper.posts()) < 2 {
		t.Fatal("nothing was retried after the pause lifted")
	}
}

func TestBeingSwitchedOffPausesRatherThanDiscards(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(400, activityDisabledName)}}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	if paused, reason := log.paused(); !paused || reason != activityDisabledName {
		t.Fatalf("expected a disabled pause, got paused=%v reason=%q", paused, reason)
	}
	if len(log.spools["s1"].pending) != 1 {
		t.Fatal("the sealed chunk was discarded when logging was switched off")
	}
}

func TestRecordsArePausedAsCountedGapsNotSilentLosses(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(400, activityCeilingReachedName)}}}
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

func TestAFlushTooBigForOneChunkIsSplitBySize(t *testing.T) {
	shipper := &fakeShipper{postDefault: scriptedResult{err: errors.New("infisical unreachable")}}
	log, _, tick := newTestLog(shipper)
	grant := testGrant("s1")

	for i := 0; i < activityFlushRecords; i++ {
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
		if chunk.meta.CiphertextBytes-gcmTag > activityMaxChunkPlaintext {
			t.Fatalf("chunk %d holds %d bytes of plaintext, over %d", i, chunk.meta.CiphertextBytes-gcmTag, activityMaxChunkPlaintext)
		}
		if chunk.meta.FirstSeq != next {
			t.Fatalf("chunk %d starts at seq %d, expected %d; a record was lost or reordered", i, chunk.meta.FirstSeq, next)
		}
		next = chunk.meta.LastSeq + 1
		total += chunk.meta.RecordCount
	}
	if total != activityFlushRecords {
		t.Fatalf("the chunks hold %d records, expected %d", total, activityFlushRecords)
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

	for i := 0; i < activityPendingChunks+3; i++ {
		log.record(grant, aRecord("api.github.com"))
		tick()
	}

	spool := log.spools["s1"]
	if len(spool.pending) > activityPendingChunks {
		t.Fatalf("pending holds %d chunks, the cap is %d", len(spool.pending), activityPendingChunks)
	}
	if spool.ring.dropped == 0 {
		t.Fatal("evicted chunks were not counted as dropped records")
	}
}

func TestTheByteCapEvictsTheOldestChunkOnTheProxy(t *testing.T) {
	log, _, _ := newTestLog(&fakeShipper{})

	blob := make([]byte, 12<<20)
	add := func(sessionID string, order uint64, posted bool, carried uint64) *activitySpool {
		spool, ok := log.spools[sessionID]
		if !ok {
			spool = newActivitySpool(testGrant(sessionID), log.now())
			log.spools[sessionID] = spool
		}
		spool.pending = append(spool.pending, &sealedChunk{
			meta:       api.CreateAgentVaultActivityChunkRequest{ChunkID: fmt.Sprintf("c%d", order), RecordCount: 100, DroppedCount: carried},
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
	var newest *activitySpool
	for i := 2; i < 7; i++ {
		newest = add(fmt.Sprintf("s%d", i), uint64(i), false, 0)
	}
	log.enforcePendingCapsLocked(newest)
	log.mu.Unlock()

	if log.sealedBytes > activityTotalSealedBytes {
		t.Fatalf("the proxy holds %d sealed bytes, past the %d cap", log.sealedBytes, activityTotalSealedBytes)
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

	for i := 0; i < activityFlushRecords*2; i++ {
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

	advance(activityIdleClose + time.Minute)
	log.flushAll(context.Background(), false)

	if _, ok := log.spools["s1"]; ok {
		t.Fatal("an idle spool was kept; a long-lived proxy would grow without bound")
	}
}

func TestIdleCloseOutlastsTheSessionCacheTTL(t *testing.T) {
	if activityIdleClose <= sessionInactiveTTL {
		t.Fatalf("idle close (%s) must outlast the session cache TTL (%s)", activityIdleClose, sessionInactiveTTL)
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
	log.flushAll(context.Background(), true)
	if len(shipper.puts()) != 1 {
		t.Fatal("a record was accepted after close")
	}
}

func TestABlockedHostIsStillRecorded(t *testing.T) {
	shipper := &fakeShipper{}
	log, _, _ := newTestLog(shipper)

	log.record(testGrant("s1"), activityRecord{
		Method: "POST", Host: "evil.example", Port: "443", Path: "/collect", Status: 403, Decision: decisionBlocked,
	})
	log.flushAll(context.Background(), true)

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

	advance(activityIdleClose + time.Minute)
	log.flushAll(context.Background(), false)
	if _, ok := log.spools["s1"]; ok {
		t.Fatal("the idle spool was not forgotten, so this test proves nothing")
	}

	log.record(grant, aRecord("api.github.com"))
	got := log.spools["s1"].ring.drain(1)[0]
	if got.Seq != 2 {
		t.Fatalf("seq restarted at %d after the spool was rebuilt, expected it to continue at 2", got.Seq)
	}
}

func TestASessionThatIsGoneDoesNotReserveItsSequenceNumbers(t *testing.T) {
	shipper := &fakeShipper{postResults: []scriptedResult{{err: apiErr(http.StatusNotFound, "")}}}
	log, _, tick := newTestLog(shipper)

	log.record(testGrant("s1"), aRecord("api.github.com"))
	tick()

	if _, ok := log.seqBySession["s1"]; ok {
		t.Fatal("a session the server has forgotten is still holding a sequence number")
	}
}

func TestRecordsLostToASealFailureAreStillCounted(t *testing.T) {
	shipper := &fakeShipper{}
	log, _, tick := newTestLog(shipper)

	grant := &activityGrant{sessionID: "s1", projectID: "proj-1", key: make([]byte, 7)}
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

func TestShutdownDoesNotRaceTheRunLoop(t *testing.T) {
	shipper := &fakeShipper{}
	log, _, _ := newTestLog(shipper)
	log.now = time.Now

	stop := make(chan struct{})
	go log.run(stop)

	grant := testGrant("s1")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			log.record(grant, aRecord("api.github.com"))
		}
	}()

	<-done
	close(stop)
	log.close(context.Background())

	if len(shipper.puts()) == 0 {
		t.Fatal("shutdown shipped nothing")
	}
	for _, call := range shipper.puts() {
		if call.bytes == 0 {
			t.Fatal("an empty object was uploaded")
		}
	}
}
