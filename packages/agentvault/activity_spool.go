package agentvault

import (
	"encoding/json"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
)

// activityRecord is one request that reached forwardHTTP. Metadata only: no headers, because a request
// header carries the injected credential, and no bodies, because LLM traffic is orders of magnitude
// larger than this. The path never carries a query string, which the proxy gets for free by building it
// from r.URL.EscapedPath().
type activityRecord struct {
	Ts           string  `json:"ts"`
	Seq          uint64  `json:"seq"`
	ProxyID      string  `json:"proxyId"`
	Method       string  `json:"method"`
	Host         string  `json:"host"`
	Port         string  `json:"port"`
	Path         string  `json:"path"`
	Status       int     `json:"status"`
	Decision     string  `json:"decision"`
	Service      *string `json:"service"`
	AccessBundle *string `json:"accessBundle"`
}

// The first allocation a ring makes. A session that sends a handful of requests a minute never needs more.
const activityRingInitialSize = 64

// activityRing is a bounded FIFO that overwrites its oldest entry when full and counts what it lost, so a
// burst costs the oldest records rather than the newest and the gap is visible in the timeline.
//
// It grows to capacity only as records arrive and lets go of its buffer once drained. Reserving capacity up
// front cost every session about 700 KB from its first request, so a proxy serving a few hundred mostly
// idle sessions held hundreds of megabytes of empty slots.
type activityRing struct {
	buf      []activityRecord
	capacity int
	head     int
	n        int
	dropped  uint64
}

func newActivityRing(capacity int) activityRing {
	return activityRing{capacity: capacity}
}

func (r *activityRing) len() int { return r.n }

func (r *activityRing) push(rec activityRecord) (evicted bool) {
	if r.capacity == 0 {
		r.dropped++
		return true
	}
	if r.n == len(r.buf) && len(r.buf) < r.capacity {
		r.grow()
	}
	if r.n == r.capacity {
		r.buf[r.head] = rec
		r.head = (r.head + 1) % len(r.buf)
		r.dropped++
		return true
	}
	r.buf[(r.head+r.n)%len(r.buf)] = rec
	r.n++
	return false
}

// grow doubles the buffer, up to capacity, and unwraps it so the oldest record sits at index 0.
func (r *activityRing) grow() {
	size := max(activityRingInitialSize, 2*len(r.buf))
	size = min(size, r.capacity)
	next := make([]activityRecord, size)
	for i := 0; i < r.n; i++ {
		next[i] = r.buf[(r.head+i)%len(r.buf)]
	}
	r.buf = next
	r.head = 0
}

// drain removes up to max records, oldest first. The caller seals one chunk per call and loops until the
// ring is empty, which is what keeps a chunk inside the server's recordCount limit even when a slow tick
// let the ring grow past it.
func (r *activityRing) drain(max int) []activityRecord {
	if r.n == 0 || max <= 0 {
		return nil
	}
	if max > r.n {
		max = r.n
	}
	out := make([]activityRecord, max)
	for i := 0; i < max; i++ {
		out[i] = r.buf[(r.head+i)%len(r.buf)]
	}
	r.head = (r.head + max) % len(r.buf)
	r.n -= max
	if r.n == 0 {
		// Released between flushes, so a session that went quiet holds nothing until it speaks again.
		r.buf = nil
		r.head = 0
	}
	return out
}

// takeDropped hands the running drop count to the next chunk and resets it, so each gap is reported once.
func (r *activityRing) takeDropped() uint64 {
	dropped := r.dropped
	r.dropped = 0
	return dropped
}

// sealedChunk is ciphertext waiting for its two-step delivery: POST the metadata to Infisical for a
// presigned URL, then PUT the bytes to the customer's bucket.
type sealedChunk struct {
	meta       api.CreateAgentVaultActivityChunkRequest
	ciphertext []byte
	// Empty until a POST succeeds, and cleared again on any PUT failure so the next tick re-POSTs the same
	// chunk id and the server replays it idempotently.
	uploadURL  string
	urlExpires time.Time

	// Proxy-wide, so the byte cap can find the oldest chunk across every session.
	sealOrder uint64
	// Set once Infisical has written the row. Never cleared: a re-POST replays the same row.
	posted bool
}

// lostCount is what a chunk that will never be uploaded adds to its session's gap. Once the POST succeeded
// the row exists, and it already reports both halves: the viewer shows its records as a batch it cannot
// read, and its drop count from the row itself. Counting either again would report one loss twice.
func (c *sealedChunk) lostCount() uint64 {
	if c.posted {
		return 0
	}
	return c.meta.DroppedCount + uint64(c.meta.RecordCount)
}

// activitySpool is one session's buffer on this proxy. proxyID is constant for the process, so it lives on
// the log rather than here.
type activitySpool struct {
	sessionID string
	projectID string
	key       []byte

	ring    activityRing
	nextSeq uint64

	pending []*sealedChunk

	lastRecordAt time.Time
	lastFlushAt  time.Time
}

func newActivitySpool(g *activityGrant, now time.Time) *activitySpool {
	return &activitySpool{
		sessionID:    g.sessionID,
		projectID:    g.projectID,
		key:          g.key,
		ring:         newActivityRing(activitySpoolCapacity),
		lastRecordAt: now,
		lastFlushAt:  now,
	}
}

type activityGroup struct {
	records   []activityRecord
	plaintext []byte
}

// packActivityRecords splits one drained slice into chunks the server takes by size as well as by count.
// Nearly every flush fits whole and is marshalled once. The rest are marshalled per record and packed, which
// yields exactly what marshalling each group as a slice would: '[', the records joined by ',', then ']'.
func packActivityRecords(records []activityRecord) ([]activityGroup, error) {
	whole, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}
	if len(whole) <= activityMaxChunkPlaintext {
		return []activityGroup{{records: records, plaintext: whole}}, nil
	}

	var groups []activityGroup
	var buf []byte
	start := 0
	for i, rec := range records {
		part, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		// One byte for the separator before it and one for the closing bracket. A record too big to share a
		// chunk still gets one of its own rather than being split.
		if len(buf) > 0 && len(buf)+1+len(part)+1 > activityMaxChunkPlaintext {
			groups = append(groups, activityGroup{records: records[start:i], plaintext: append(buf, ']')})
			buf, start = nil, i
		}
		if len(buf) == 0 {
			buf = append(buf, '[')
		} else {
			buf = append(buf, ',')
		}
		buf = append(buf, part...)
	}
	groups = append(groups, activityGroup{records: records[start:], plaintext: append(buf, ']')})
	return groups, nil
}

// sealSlice turns one group of records, already marshalled, into a sealed chunk ready to ship.
func (s *activitySpool) sealSlice(proxyID string, records []activityRecord, plaintext []byte, dropped uint64, now time.Time) (*sealedChunk, error) {
	chunkID := newActivityChunkID(now)
	aad := buildActivityAAD(s.projectID, s.sessionID, proxyID, chunkID)
	ciphertext, iv, err := sealActivity(s.key, plaintext, aad)
	if err != nil {
		return nil, err
	}

	first, last := records[0], records[len(records)-1]
	return &sealedChunk{
		meta: api.CreateAgentVaultActivityChunkRequest{
			ChunkID:         chunkID,
			StartedAt:       first.Ts,
			EndedAt:         last.Ts,
			FirstSeq:        first.Seq,
			LastSeq:         last.Seq,
			RecordCount:     len(records),
			DroppedCount:    dropped,
			CiphertextBytes: len(ciphertext),
			IV:              encodeActivityIV(iv),
		},
		ciphertext: ciphertext,
	}, nil
}
