package oracle

import (
	"bytes"
	"encoding/binary"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

type callSummary struct {
	retCode int
	message string
}

type summaryLayout struct {
	hasEndOfCallStatus bool
	ttcVersion         int
}

var summaryLayouts = []summaryLayout{
	{hasEndOfCallStatus: true, ttcVersion: 7},
	{hasEndOfCallStatus: true, ttcVersion: 4},
	{hasEndOfCallStatus: false, ttcVersion: 7},
	{hasEndOfCallStatus: false, ttcVersion: 4},
}

const (
	maxSummaryTrailingBytes = 24
)

var (
	oraMessagePrefix     = []byte("ORA-")
	oracleMessagePattern = regexp.MustCompile(`ORA-(\d{5}): [^\x00\n]*`)
)

const (
	ttcStatusMessageLength = 8
	ttcEndOfMessage        = 0x1d
	minOraMessageLength    = len("ORA-00000: x")
	ociSummaryHeaderLength = 13
	maxPlausibleCallStatus = 1 << 20
	maxPlausibleRowNumber  = 1 << 24
)

var errSummaryHasBindErrors = errors.New("call summary reports per-bind errors")

type summaryReader struct {
	r   *TTCReader
	err error
}

func (s *summaryReader) num(size int) int {
	if s.err != nil {
		return 0
	}
	v, err := s.r.GetInt(size, true, true)
	if err != nil {
		s.err = err
	}
	return v
}

func (s *summaryReader) byte() uint8 {
	if s.err != nil {
		return 0
	}
	v, err := s.r.GetByte()
	if err != nil {
		s.err = err
	}
	return v
}

func (s *summaryReader) dlc() {
	if s.err != nil {
		return
	}
	if _, err := s.r.GetDlc(); err != nil {
		s.err = err
	}
}

func readCallSummary(r *TTCReader, layout summaryLayout) (callSummary, error) {
	s := &summaryReader{r: r}
	var result callSummary

	if layout.hasEndOfCallStatus {
		s.num(4)
	}
	if layout.ttcVersion >= 3 {
		s.num(2)
	}
	s.num(4)
	retCode := s.num(2)
	s.num(2)
	s.num(2)
	s.num(2)
	s.num(2)
	s.byte()
	s.byte()
	if layout.ttcVersion >= 4 {
		s.num(2)
		s.num(2)
	} else {
		s.byte()
		s.byte()
	}
	s.byte()
	s.byte()
	s.num(4)
	s.num(2)
	s.byte()
	s.num(4)
	s.num(2)
	s.num(4)
	s.byte()
	s.byte()
	s.num(2)
	s.num(4)
	s.dlc()

	if layout.ttcVersion < 7 {
		s.dlc()
		s.dlc()
		s.dlc()
	} else {
		if err := readBindErrorSections(s); err != nil {
			return result, err
		}
		retCode = s.num(4)
		if s.err == nil {
			if _, err := s.r.GetInt64(8, true, true); err != nil {
				s.err = err
			}
		}
	}
	if s.err != nil {
		return result, s.err
	}
	if retCode != 0 {
		raw, err := s.r.GetClr()
		if err != nil {
			return result, err
		}
		result.message = strings.TrimRight(string(raw), "\x00\r\n \t")
	}
	result.retCode = retCode
	return result, nil
}

func readBindErrorSections(s *summaryReader) error {
	for _, size := range []int{2, 4, 2} {
		if s.num(size) != 0 {
			return errSummaryHasBindErrors
		}
		if s.err != nil {
			return s.err
		}
	}
	return nil
}

func parseCallSummary(payload []byte) (callSummary, bool) {
	for offset := 0; offset < len(payload); offset++ {
		if payload[offset] != TTCMsgError {
			continue
		}
		for _, layout := range summaryLayouts {
			r := NewTTCReader(payload[offset+1:])
			summary, err := readCallSummary(r, layout)
			if err != nil || r.Remaining() > maxSummaryTrailingBytes {
				continue
			}
			if summary.retCode != 0 && !strings.HasPrefix(summary.message, "ORA-") {
				continue
			}
			return summary, true
		}
	}
	return callSummary{}, false
}

func oracleErrorFromFramedText(payload []byte) (callSummary, bool) {
	for from := 0; ; {
		at := bytes.Index(payload[from:], oraMessagePrefix)
		if at < 0 {
			return callSummary{}, false
		}
		at += from
		from = at + 1
		if at == 0 {
			continue
		}
		length := int(payload[at-1])
		if length < minOraMessageLength || at+length > len(payload) {
			continue
		}
		text := payload[at : at+length]
		match := oracleMessagePattern.FindSubmatch(text)
		if match == nil || len(match[0]) != len(bytes.TrimRight(text, "\x00\r\n \t")) {
			continue
		}
		code, err := strconv.Atoi(string(match[1]))
		if err != nil {
			continue
		}
		return callSummary{retCode: code, message: string(match[0])}, true
	}
}

func ociSummaryReportsSuccess(payload []byte) bool {
	for offset := 0; offset+ociSummaryHeaderLength <= len(payload); offset++ {
		if payload[offset] != TTCMsgError {
			continue
		}
		header := payload[offset+1:]
		endOfCallStatus := binary.LittleEndian.Uint32(header[0:4])
		curRowNumber := binary.LittleEndian.Uint32(header[6:10])
		retCode := binary.LittleEndian.Uint16(header[10:12])
		if endOfCallStatus > maxPlausibleCallStatus || curRowNumber > maxPlausibleRowNumber {
			continue
		}
		if retCode != 0 {
			continue
		}
		return true
	}
	return false
}

func endOfCallStatusPresent(payload []byte) bool {
	if len(payload) >= ttcStatusMessageLength {
		tail := payload[len(payload)-ttcStatusMessageLength:]
		if tail[0] == TTCMsgStatus && tail[ttcStatusMessageLength-1] == ttcEndOfMessage {
			return true
		}
	}
	return compressedStatusMessage(payload)
}

func compressedStatusMessage(payload []byte) bool {
	if len(payload) < 2 || payload[0] != TTCMsgStatus {
		return false
	}
	r := NewTTCReader(payload[1:])
	if _, err := r.GetInt(4, true, true); err != nil {
		return false
	}
	if _, err := r.GetInt(2, true, true); err != nil {
		return false
	}
	return r.Remaining() == 0
}
