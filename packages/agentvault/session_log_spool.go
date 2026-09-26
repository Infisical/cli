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
}

const sessionLogRingInitialSize = 64

type sessionLogRing struct {
	buf      []sessionLogRecord
	capacity int
	head     int
	n        int
	dropped  uint64
}

func newSessionLogRing(capacity int) sessionLogRing {
	return sessionLogRing{capacity: capacity}
}

func (r *sessionLogRing) len() int { return r.n }

func (r *sessionLogRing) push(rec sessionLogRecord) (evicted bool) {
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

func (r *sessionLogRing) takeDropped() uint64 {
	dropped := r.dropped
	r.dropped = 0
	return dropped
}

type sealedChunk struct {
	meta       api.CreateAgentVaultSessionLogChunkRequest
	ciphertext []byte
	uploadURL  string
	urlExpires time.Time

	sealOrder uint64
	posted    bool
}

// A posted chunk's row already reports its records and drops, so counting them here would double-report.
func (c *sealedChunk) lostCount() uint64 {
	if c.posted {
		return 0
	}
	return c.meta.DroppedCount + uint64(c.meta.RecordCount)
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
	whole, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}
	if len(whole) <= sessionLogMaxChunkPlaintext {
		return []sessionLogGroup{{records: records, plaintext: whole}}, nil
	}

	var groups []sessionLogGroup
	var buf []byte
	start := 0
	for i, rec := range records {
		part, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if len(buf) > 0 && len(buf)+1+len(part)+1 > sessionLogMaxChunkPlaintext {
			groups = append(groups, sessionLogGroup{records: records[start:i], plaintext: append(buf, ']')})
			buf, start = nil, i
		}
		if len(buf) == 0 {
			buf = append(buf, '[')
		} else {
			buf = append(buf, ',')
		}
		buf = append(buf, part...)
	}
	groups = append(groups, sessionLogGroup{records: records[start:], plaintext: append(buf, ']')})
	return groups, nil
}

func (s *sessionLogSpool) sealSlice(records []sessionLogRecord, plaintext []byte, dropped uint64) (*sealedChunk, error) {
	chunkID, err := newSessionLogChunkID()
	if err != nil {
		return nil, err
	}
	aad := buildSessionLogAAD(s.sessionID, chunkID)
	ciphertext, iv, err := sealSessionLog(s.key, plaintext, aad)
	if err != nil {
		return nil, err
	}

	first, last := records[0], records[len(records)-1]
	return &sealedChunk{
		meta: api.CreateAgentVaultSessionLogChunkRequest{
			ChunkID:          chunkID,
			StartedAt:        first.Ts,
			EndedAt:          last.Ts,
			FirstSeq:         first.Seq,
			LastSeq:          last.Seq,
			RecordCount:      len(records),
			DroppedCount:     dropped,
			CiphertextBytes:  len(ciphertext),
			IV:               encodeSessionLogIV(iv),
			CiphertextSha256: sessionLogCiphertextSHA256(ciphertext),
		},
		ciphertext: ciphertext,
	}, nil
}
