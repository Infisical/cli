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

// activityRing is a bounded FIFO that overwrites its oldest entry when full and counts what it lost, so a
// burst costs the oldest records rather than the newest and the gap is visible in the timeline.
type activityRing struct {
	buf     []activityRecord
	head    int
	n       int
	dropped uint64
}

func newActivityRing(capacity int) activityRing {
	return activityRing{buf: make([]activityRecord, capacity)}
}

func (r *activityRing) len() int { return r.n }

func (r *activityRing) push(rec activityRecord) (evicted bool) {
	capacity := len(r.buf)
	if capacity == 0 {
		r.dropped++
		return true
	}
	if r.n == capacity {
		r.buf[r.head] = rec
		r.head = (r.head + 1) % capacity
		r.dropped++
		return true
	}
	r.buf[(r.head+r.n)%capacity] = rec
	r.n++
	return false
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

// sealSlice turns one slice of records into a sealed chunk ready to ship.
func (s *activitySpool) sealSlice(proxyID string, records []activityRecord, dropped uint64, now time.Time) (*sealedChunk, error) {
	plaintext, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}

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
