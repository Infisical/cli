package agentvault

import (
	"encoding/json"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
)

// Never add headers, bodies or the query string: they can carry the injected credential.
type sessionLogRecord struct {
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

	at time.Time
}

const sessionLogRingInitialSize = 64

type sessionLogRing struct {
	buf      []sessionLogRecord
	capacity int
	head     int
	n        int

	unreportedDrops uint64
}

func newSessionLogRing(capacity int) sessionLogRing {
	return sessionLogRing{capacity: capacity}
}

func (r *sessionLogRing) len() int { return r.n }

func (r *sessionLogRing) push(rec sessionLogRecord) (evicted bool) {
	if r.n == len(r.buf) && len(r.buf) < r.capacity {
		r.grow()
	}
	if r.n == r.capacity {
		r.buf[r.head] = rec
		r.head = (r.head + 1) % len(r.buf)
		r.unreportedDrops++
		return true
	}
	r.buf[(r.head+r.n)%len(r.buf)] = rec
	r.n++
	return false
}

func (r *sessionLogRing) grow() {
	size := max(sessionLogRingInitialSize, 2*len(r.buf))
	size = min(size, r.capacity)
	next := make([]sessionLogRecord, size)
	for i := 0; i < r.n; i++ {
		next[i] = r.buf[(r.head+i)%len(r.buf)]
	}
	r.buf = next
	r.head = 0
}

func (r *sessionLogRing) drain(max int) []sessionLogRecord {
	if r.n == 0 || max <= 0 {
		return nil
	}
	if max > r.n {
		max = r.n
	}
	out := make([]sessionLogRecord, max)
	for i := 0; i < max; i++ {
		out[i] = r.buf[(r.head+i)%len(r.buf)]
	}
	r.head = (r.head + max) % len(r.buf)
	r.n -= max
	if r.n == 0 {
		r.buf = nil
		r.head = 0
	}
	return out
}

func (r *sessionLogRing) takeUnreportedDrops() uint64 {
	dropped := r.unreportedDrops
	r.unreportedDrops = 0
	return dropped
}

type sealedChunk struct {
	meta       api.CreateAgentVaultSessionLogChunkRequest
	ciphertext []byte
	records    int
	sealOrder  uint64

	// uploadURL and urlExpires are guarded by the recorder's mu.
	uploadURL  string
	urlExpires time.Time
}

type sessionLogSpool struct {
	sessionID string
	key       []byte

	ring    sessionLogRing
	nextSeq uint64

	pending []*sealedChunk

	lastRecordAt time.Time
	lastFlushAt  time.Time
}

func (s *sessionLogSpool) popPending() *sealedChunk {
	chunk := s.pending[0]
	s.pending[0] = nil
	s.pending = s.pending[1:]
	if len(s.pending) == 0 {
		s.pending = nil
	}
	return chunk
}

func (s *sessionLogSpool) heldRecords() int {
	held := s.ring.len()
	for _, chunk := range s.pending {
		held += chunk.records
	}
	return held
}

func newSessionLogSpool(g *sessionLogGrant, now time.Time) *sessionLogSpool {
	return &sessionLogSpool{
		sessionID:    g.sessionID,
		key:          g.key,
		ring:         newSessionLogRing(sessionLogSpoolCapacity),
		lastRecordAt: now,
		lastFlushAt:  now,
	}
}

type sessionLogGroup struct {
	records   []sessionLogRecord
	plaintext []byte
}

func packSessionLogRecords(records []sessionLogRecord) ([]sessionLogGroup, error) {
	if spansAtMost(records, sessionLogMaxChunkSpan) {
		whole, err := json.Marshal(records)
		if err != nil {
			return nil, err
		}
		if len(whole) <= sessionLogMaxChunkPlaintext {
			return []sessionLogGroup{{records: records, plaintext: whole}}, nil
		}
	}

	var groups []sessionLogGroup
	var buf []byte
	var earliest, latest time.Time
	start := 0
	for i, rec := range records {
		part, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if len(buf) > 0 {
			tooBig := len(buf)+1+len(part)+1 > sessionLogMaxChunkPlaintext
			// Min and max rather than first and last, because the wall clock can step.
			tooLong := maxTime(latest, rec.at).Sub(minTime(earliest, rec.at)) > sessionLogMaxChunkSpan
			if tooBig || tooLong {
				groups = append(groups, sessionLogGroup{records: records[start:i], plaintext: append(buf, ']')})
				buf, start = nil, i
			}
		}
		if len(buf) == 0 {
			earliest, latest = rec.at, rec.at
			buf = append(buf, '[')
		} else {
			earliest, latest = minTime(earliest, rec.at), maxTime(latest, rec.at)
			buf = append(buf, ',')
		}
		buf = append(buf, part...)
	}
	groups = append(groups, sessionLogGroup{records: records[start:], plaintext: append(buf, ']')})
	return groups, nil
}

func spansAtMost(records []sessionLogRecord, span time.Duration) bool {
	if len(records) == 0 {
		return true
	}
	earliest, latest := records[0].at, records[0].at
	for _, rec := range records[1:] {
		earliest, latest = minTime(earliest, rec.at), maxTime(latest, rec.at)
	}
	return latest.Sub(earliest) <= span
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func (s *sessionLogSpool) sealSlice(records []sessionLogRecord, plaintext []byte) (*sealedChunk, error) {
	// The wall clock can step, so the last record is not always the latest.
	latest := records[0]
	for _, rec := range records[1:] {
		if rec.at.After(latest.at) {
			latest = rec
		}
	}

	chunkID, err := newSessionLogChunkID(latest.at)
	if err != nil {
		return nil, err
	}
	aad := buildSessionLogAAD(s.sessionID, chunkID)
	ciphertext, err := sealSessionLog(s.key, plaintext, aad)
	if err != nil {
		return nil, err
	}

	return &sealedChunk{
		meta: api.CreateAgentVaultSessionLogChunkRequest{
			ChunkID:          chunkID,
			EndedAt:          latest.Ts,
			CiphertextBytes:  len(ciphertext),
			CiphertextSha256: infisicalCiphertextSha256(ciphertext),
		},
		ciphertext: ciphertext,
		records:    len(records),
	}, nil
}
