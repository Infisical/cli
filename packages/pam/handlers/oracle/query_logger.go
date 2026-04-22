package oracle

import (
	"bytes"
	"encoding/binary"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

// TTC function-call opcodes of interest for query logging. These match what a real
// Oracle server receives during a client's query lifecycle — see Oracle Net TTC
// documentation and go-ora's parameter/command.go for reference.
const (
	ttcFuncOALL8    = 0x5E // all-in-one statement execution (SQL + binds in a single call)
	ttcFuncOFETCH   = 0x05 // fetch more rows
	ttcFuncOCOMMIT  = 0x0E // commit
	ttcFuncORLLBK   = 0x0F // rollback
	ttcFuncOCLOSE   = 0x69 // close cursor
	ttcFuncOSTMT    = 0x04 // parse / describe
	ttcFuncOLOGOFF  = 0x09 // logoff
	ttcMsgFunction  = 0x03 // outer opcode for function calls
	ttcMsgPiggyback = 0x11 // piggyback TTC
)

// pendingQuery tracks the SQL-string that was sent client→upstream; we correlate it
// with the subsequent upstream→client response so the session log has both.
type pendingQuery struct {
	sql       string
	timestamp time.Time
}

// QueryExtractor runs in its own goroutine, consuming DATA packet payloads from
// either direction via Feed() and emitting SessionLogEntry records when a complete
// client call + server response pair is recognized. Feed is non-blocking; if the
// internal channel fills, packets are dropped and a warning is logged. Logging is
// best-effort, same as MSSQL.
type QueryExtractor struct {
	logger     session.SessionLogger
	sessionID  string
	direction  string // "client->upstream" or "upstream->client"
	ch         chan []byte
	stopCh     chan struct{}
	wg         sync.WaitGroup
	use32Bit   bool
	pair       *pairState // shared across both directions via Pair
}

// pairState couples the client-side and upstream-side extractors so we can match
// requests with responses.
type pairState struct {
	mu      sync.Mutex
	pending *pendingQuery
}

// NewQueryExtractorPair returns two extractors, one per direction, sharing a pair state.
// They must both be started and stopped together.
func NewQueryExtractorPair(logger session.SessionLogger, sessionID string, use32Bit bool) (clientToUpstream, upstreamToClient *QueryExtractor) {
	p := &pairState{}
	clientToUpstream = newExtractor(logger, sessionID, "client->upstream", use32Bit, p)
	upstreamToClient = newExtractor(logger, sessionID, "upstream->client", use32Bit, p)
	return
}

func newExtractor(logger session.SessionLogger, sessionID, direction string, use32Bit bool, pair *pairState) *QueryExtractor {
	e := &QueryExtractor{
		logger:    logger,
		sessionID: sessionID,
		direction: direction,
		ch:        make(chan []byte, 64),
		stopCh:    make(chan struct{}),
		use32Bit:  use32Bit,
		pair:      pair,
	}
	e.wg.Add(1)
	go e.loop()
	return e
}

// Feed pushes a chunk of bytes into the extractor. Returns without blocking if the
// queue is full; drops on overflow. This keeps the relay hot path off the TTC parser.
func (e *QueryExtractor) Feed(data []byte) {
	if len(data) == 0 {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case e.ch <- cp:
	default:
		// drop — logging is best-effort
	}
}

func (e *QueryExtractor) Stop() {
	close(e.stopCh)
	e.wg.Wait()
}

func (e *QueryExtractor) loop() {
	defer e.wg.Done()
	var buffer bytes.Buffer

	for {
		select {
		case <-e.stopCh:
			return
		case chunk := <-e.ch:
			buffer.Write(chunk)
			e.drain(&buffer)
		}
	}
}

// drain consumes as many complete TNS packets as the buffer contains.
func (e *QueryExtractor) drain(buf *bytes.Buffer) {
	for {
		if buf.Len() < 8 {
			return
		}
		head := buf.Bytes()[:8]
		var length uint32
		if e.use32Bit {
			length = binary.BigEndian.Uint32(head)
		} else {
			length = uint32(binary.BigEndian.Uint16(head))
		}
		if length < 8 || length > 16*1024*1024 {
			// Framing is broken — reset. Shouldn't happen in normal flow.
			buf.Reset()
			return
		}
		if buf.Len() < int(length) {
			return
		}
		packet := make([]byte, length)
		if _, err := buf.Read(packet); err != nil {
			return
		}
		e.handlePacket(packet)
	}
}

func (e *QueryExtractor) handlePacket(raw []byte) {
	if PacketTypeOf(raw) != PacketTypeData {
		return
	}
	d, err := ParseDataPacket(raw, e.use32Bit)
	if err != nil {
		return
	}
	if len(d.Payload) < 1 {
		return
	}
	switch e.direction {
	case "client->upstream":
		e.handleClientRequest(d.Payload)
	case "upstream->client":
		e.handleServerResponse(d.Payload)
	}
}

func (e *QueryExtractor) handleClientRequest(payload []byte) {
	// Oracle clients (sqlcl, JDBC thin) frequently bundle multiple TTC messages
	// in a single packet — typically a piggybacked OCLOSE for the previous cursor
	// (0x11 0x69 ...) followed by the new function call (0x03 0x5E ... for OALL8).
	// The piggyback prefix is variable-length, so rather than parse it we scan the
	// payload for the function-call+opcode marker pair and start parsing there.
	if idx := findBytePair(payload, ttcMsgFunction, ttcFuncOALL8); idx >= 0 {
		r := NewTTCReader(payload[idx+2:])
		if sqlText := tryExtractSQL(r); sqlText != "" {
			e.pair.mu.Lock()
			e.pair.pending = &pendingQuery{sql: sqlText, timestamp: time.Now()}
			e.pair.mu.Unlock()
		}
		return
	}
	if findBytePair(payload, ttcMsgFunction, ttcFuncOCOMMIT) >= 0 {
		e.recordLiteral("COMMIT")
		return
	}
	if findBytePair(payload, ttcMsgFunction, ttcFuncORLLBK) >= 0 {
		e.recordLiteral("ROLLBACK")
		return
	}
	// FETCH packets are intentionally not surfaced — they correlate to a still-pending
	// SELECT and we want responses to attribute back to that, not to the FETCH itself.
}

func findBytePair(data []byte, b1, b2 byte) int {
	for i := 0; i+1 < len(data); i++ {
		if data[i] == b1 && data[i+1] == b2 {
			return i
		}
	}
	return -1
}

func (e *QueryExtractor) recordLiteral(sql string) {
	e.pair.mu.Lock()
	e.pair.pending = &pendingQuery{sql: sql, timestamp: time.Now()}
	e.pair.mu.Unlock()
}

// tryExtractSQL scans an OALL8 payload for the SQL statement. The OALL8 wire format
// has variable-length headers that differ across client drivers and bind patterns, so
// we use a simple heuristic rather than structured parsing: find the longest run of
// printable ASCII bytes ≥ 4 chars long. In practice the SQL text is always the
// longest such run in the payload. Lenient by design — we'd rather miss a query than
// crash on a bind-param shape we didn't anticipate.
func tryExtractSQL(r *TTCReader) string {
	// Pull the remaining bytes from the reader.
	// r.buf is private; use a Remaining-check-plus-GetBytes dance.
	remaining := r.Remaining()
	if remaining <= 0 {
		return ""
	}
	buf, err := r.GetBytes(remaining)
	if err != nil {
		return ""
	}
	return longestPrintableRun(buf)
}

// longestPrintableRun returns the longest contiguous run of printable ASCII (0x20..0x7E
// plus tab/newline/CR) in data, provided it's at least 4 chars. Otherwise returns "".
func longestPrintableRun(data []byte) string {
	bestStart, bestLen := 0, 0
	curStart, curLen := 0, 0
	for i, b := range data {
		printable := b == '\t' || b == '\n' || b == '\r' || (b >= 0x20 && b <= 0x7E)
		if printable {
			if curLen == 0 {
				curStart = i
			}
			curLen++
			if curLen > bestLen {
				bestLen = curLen
				bestStart = curStart
			}
		} else {
			curLen = 0
		}
	}
	if bestLen < 4 {
		return ""
	}
	return string(data[bestStart : bestStart+bestLen])
}

func (e *QueryExtractor) handleServerResponse(payload []byte) {
	// If we have a pending client query, emit one log entry with a best-effort outcome
	// derived from the response. Successful responses often contain an "OK" at opcode
	// 0x04 with returnCode == 0; error responses contain non-zero returnCode.
	e.pair.mu.Lock()
	pending := e.pair.pending
	e.pair.pending = nil
	e.pair.mu.Unlock()
	if pending == nil {
		return
	}
	output := extractResponseOutcome(payload)
	err := e.logger.LogEntry(session.SessionLogEntry{
		Timestamp: pending.timestamp,
		Input:     pending.sql,
		Output:    output,
	})
	if err != nil {
		log.Debug().Err(err).Str("sessionID", e.sessionID).Msg("session log entry dropped")
	}
}

// extractResponseOutcome scans the server response for either an OError packet (opcode
// 0x04) or a row-count in a status KV. Returns "OK", "ERROR: ORA-XXXX: ..." or "".
func extractResponseOutcome(payload []byte) string {
	r := NewTTCReader(payload)
	for r.Remaining() > 0 {
		op, err := r.GetByte()
		if err != nil {
			break
		}
		if op == 0x04 { // summary / error
			// Skip a few fields; return code is the 4th compressed int.
			for i := 0; i < 3; i++ {
				if _, err := r.GetInt(4, true, true); err != nil {
					return "OK"
				}
			}
			code, err := r.GetInt(4, true, true)
			if err != nil || code == 0 {
				return "OK"
			}
			return ora(code)
		}
	}
	return ""
}

func ora(code int) string {
	switch code {
	case 0:
		return "OK"
	case 1:
		return "ERROR: ORA-00001: unique constraint violated"
	case 900:
		return "ERROR: ORA-00900: invalid SQL statement"
	case 942:
		return "ERROR: ORA-00942: table or view does not exist"
	case 1017:
		return "ERROR: ORA-01017: invalid username/password"
	case 28000:
		return "ERROR: ORA-28000: the account is locked"
	}
	return "ERROR"
}
