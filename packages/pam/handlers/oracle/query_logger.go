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
	minPrintableByte        = 0x20
	maxPrintableByte        = 0x7E
	maxTrailingNonPrintable = 2

	ttcFuncOALL8   = 0x5E
	ttcFuncOCOMMIT = 0x0E
	ttcFuncORLLBK  = 0x0F
	ttcMsgFunction = 0x03
)

type pendingQuery struct {
	sql       string
	timestamp time.Time
	extractor *QueryExtractor
}

// Best-effort SQL extraction from the byte stream.
type QueryExtractor struct {
	logger    session.SessionLogger
	sessionID string
	direction string
	use32Bit  bool
	pair      *pairState
}

type taggedChunk struct {
	extractor *QueryExtractor
	data      []byte
}

type pairState struct {
	mu      sync.Mutex
	pending *pendingQuery
	ch      chan taggedChunk
	stopCh  chan struct{}
	stopOne sync.Once
	wg      sync.WaitGroup
}

func NewQueryExtractorPair(logger session.SessionLogger, sessionID string, use32Bit bool) (clientToUpstream, upstreamToClient *QueryExtractor) {
	p := &pairState{
		ch:     make(chan taggedChunk, 128),
		stopCh: make(chan struct{}),
	}
	clientToUpstream = newExtractor(logger, sessionID, "client->upstream", use32Bit, p)
	upstreamToClient = newExtractor(logger, sessionID, "upstream->client", use32Bit, p)
	p.wg.Add(1)
	go p.loop()
	return
}

func (p *pairState) loop() {
	defer p.wg.Done()
	buffers := map[*QueryExtractor]*bytes.Buffer{}
	for {
		select {
		case <-p.stopCh:
			for {
				select {
				case chunk := <-p.ch:
					p.consume(buffers, chunk)
				default:
					p.flushPending()
					return
				}
			}
		case chunk := <-p.ch:
			p.consume(buffers, chunk)
		}
	}
}

func (p *pairState) consume(buffers map[*QueryExtractor]*bytes.Buffer, chunk taggedChunk) {
	buf, ok := buffers[chunk.extractor]
	if !ok {
		buf = &bytes.Buffer{}
		buffers[chunk.extractor] = buf
	}
	buf.Write(chunk.data)
	chunk.extractor.drain(buf)
}

func (p *pairState) flushPending() {
	p.mu.Lock()
	pending := p.pending
	p.pending = nil
	p.mu.Unlock()
	if pending != nil && pending.extractor != nil {
		pending.extractor.writeEntry(pending, sessionOutcomeUnknown)
	}
}

func newExtractor(logger session.SessionLogger, sessionID, direction string, use32Bit bool, pair *pairState) *QueryExtractor {
	return &QueryExtractor{
		logger:    logger,
		sessionID: sessionID,
		direction: direction,
		use32Bit:  use32Bit,
		pair:      pair,
	}
}

func (e *QueryExtractor) Feed(data []byte) {
	if len(data) == 0 {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case e.pair.ch <- taggedChunk{extractor: e, data: cp}:
	default:
	}
}

func (e *QueryExtractor) Stop() {
	e.pair.stopOne.Do(func() { close(e.pair.stopCh) })
	e.pair.wg.Wait()
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
			e.startPending(sqlText)
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
	e.startPending(sql)
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
	return trimLengthPrefix(longestPrintableRun(buf))
}

func trimLengthPrefix(run string) string {
	if len(run) < 2 {
		return run
	}
	declared := int(run[0])
	if declared < minPrintableByte || declared > maxPrintableByte {
		return run
	}
	if declared < len(run)-1 || declared > len(run)+maxTrailingNonPrintable {
		return run
	}
	return run[1:]
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

const (
	sessionOutcomeOK      = "OK"
	sessionOutcomeUnknown = "UNKNOWN"
	oraNoDataFound        = 1403
)

func (e *QueryExtractor) handleServerResponse(payload []byte) {
	outcome := extractResponseOutcome(payload)
	if outcome == sessionOutcomeUnknown {
		return
	}
	e.pair.mu.Lock()
	pending := e.pair.pending
	e.pair.pending = nil
	e.pair.mu.Unlock()
	if pending == nil {
		return
	}
	e.writeEntry(pending, outcome)
}

func (e *QueryExtractor) writeEntry(pending *pendingQuery, outcome string) {
	err := e.logger.LogEntry(session.SessionLogEntry{
		Timestamp: pending.timestamp,
		Input:     pending.sql,
		Output:    outcome,
	})
	if err != nil {
		log.Debug().Err(err).Str("sessionID", e.sessionID).Msg("session log entry dropped")
	}
}

func (e *QueryExtractor) startPending(sql string) {
	e.pair.mu.Lock()
	previous := e.pair.pending
	e.pair.pending = &pendingQuery{sql: sql, timestamp: time.Now(), extractor: e}
	e.pair.mu.Unlock()
	if previous != nil {
		e.writeEntry(previous, sessionOutcomeUnknown)
	}
}

func extractResponseOutcome(payload []byte) string {
	summary, ok := parseCallSummary(payload)
	if !ok {
		summary, ok = oracleErrorFromFramedText(payload)
	}
	if !ok {
		if bytes.Contains(payload, oraMessagePrefix) {
			return sessionOutcomeUnknown
		}
		if ociSummaryReportsSuccess(payload) || endOfCallStatusPresent(payload) {
			return sessionOutcomeOK
		}
		return sessionOutcomeUnknown
	}
	if summary.retCode == 0 || summary.retCode == oraNoDataFound {
		return sessionOutcomeOK
	}
	if summary.message == "" {
		return fmt.Sprintf("ERROR: ORA-%05d", summary.retCode)
	}
	return "ERROR: " + summary.message
}
