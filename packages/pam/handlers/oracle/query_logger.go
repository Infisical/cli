package oracle

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

const (
	ttcFuncOALL8   = 0x5E
	ttcFuncOCOMMIT = 0x0E
	ttcFuncORLLBK  = 0x0F
	ttcMsgFunction = 0x03
)

type pendingQuery struct {
	sql       string
	timestamp time.Time
}

// Best-effort SQL extraction from the byte stream.
type QueryExtractor struct {
	logger    session.SessionLogger
	sessionID string
	direction string
	ch        chan []byte
	stopCh    chan struct{}
	wg        sync.WaitGroup
	use32Bit  bool
	pair      *pairState
}

type pairState struct {
	mu      sync.Mutex
	pending *pendingQuery
}

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

func (e *QueryExtractor) Feed(data []byte) {
	if len(data) == 0 {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case e.ch <- cp:
	default:
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
	// Clients often piggyback an OCLOSE before the new function call; scan for
	// the function-call+opcode marker pair instead of parsing from offset 0.
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

// tryExtractSQL uses a longest-printable-run heuristic because OALL8 headers
// vary across client drivers and bind patterns.
func tryExtractSQL(r *TTCReader) string {
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

func extractResponseOutcome(payload []byte) string {
	r := NewTTCReader(payload)
	for r.Remaining() > 0 {
		op, err := r.GetByte()
		if err != nil {
			break
		}
		if op == 0x04 {
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
	return fmt.Sprintf("ERROR: ORA-%05d", code)
}
