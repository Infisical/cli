package handlers

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strconv"

	"github.com/Infisical/infisical-merge/packages/pam/session/masking"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
)

// Values of these types are plain text in both wire formats, so a match is replaced in place.
var pgTextTypes = map[uint32]bool{
	pgtype.TextOID:    true,
	pgtype.VarcharOID: true,
	pgtype.BPCharOID:  true,
	pgtype.NameOID:    true,
	pgtype.JSONOID:    true,
	pgtype.JSONBOID:   true,
	pgtype.XMLOID:     true,
	pgtype.UnknownOID: true,
}

type pgColumnFormat struct {
	typeOID uint32
	binary  bool
}

// Who receives the RowDescription or NoData answering a Describe; the server answers in request order.
type describeSource int

const (
	describeForClient describeSource = iota
	describeForMasking
	syncPoint
)

func (p *PostgresProxy) masking() bool {
	return p.config.OutputMasker != nil
}

// Each Execute gets a portal Describe sent ahead of it, so its rows always follow a RowDescription.
func (p *PostgresProxy) trackDescribe(msg pgproto3.FrontendMessage) *pgproto3.Describe {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	switch m := msg.(type) {
	case *pgproto3.Describe:
		p.describes = append(p.describes, describeForClient)
	case *pgproto3.Execute:
		p.describes = append(p.describes, describeForMasking)
		return &pgproto3.Describe{ObjectType: 'P', Name: m.Portal}
	case *pgproto3.Sync, *pgproto3.Query, *pgproto3.FunctionCall:
		p.describes = append(p.describes, syncPoint)
	}
	return nil
}

// maskServerMessage returns the message to relay, or nil to drop it.
func (p *PostgresProxy) maskServerMessage(msg pgproto3.BackendMessage) pgproto3.BackendMessage {
	if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
		p.discarding = false
		p.maskingCopy = false
		p.popThroughSync()
		return msg
	}
	if p.discarding {
		return nil
	}

	masker := p.config.OutputMasker
	switch m := msg.(type) {
	case *pgproto3.RowDescription:
		p.rowColumns = p.rowColumns[:0]
		for _, field := range m.Fields {
			p.rowColumns = append(p.rowColumns, pgColumnFormat{field.DataTypeOID, field.Format == pgtype.BinaryFormatCode})
		}
		return p.answerDescribe(msg)
	case *pgproto3.NoData:
		p.rowColumns = p.rowColumns[:0]
		return p.answerDescribe(msg)
	case *pgproto3.DataRow:
		for i, value := range m.Values {
			if value == nil {
				continue
			}
			var column pgColumnFormat
			if i < len(p.rowColumns) {
				column = p.rowColumns[i]
			}
			text := value
			if column.binary {
				text = binaryValueText(column.typeOID, value)
			}
			masked := masker.Mask(text)
			if bytes.Equal(masked, text) {
				continue
			}
			if pgTextTypes[column.typeOID] {
				m.Values[i] = masked
			} else {
				// A placeholder would not decode as this column's type.
				m.Values[i] = nil
			}
		}
	case *pgproto3.CopyOutResponse:
		if m.OverallFormat == 0 {
			p.maskingCopy = true
			return msg
		}
		return p.blockCopy()
	case *pgproto3.CopyBothResponse:
		return p.blockCopy()
	case *pgproto3.CopyData:
		if p.maskingCopy {
			m.Data = masker.Mask(m.Data)
		}
	case *pgproto3.FunctionCallResponse:
		if masked := masker.Mask(m.Result); !bytes.Equal(masked, m.Result) {
			m.Result = nil
		}
	case *pgproto3.NotificationResponse:
		m.Payload = masker.MaskString(m.Payload)
	case *pgproto3.ErrorResponse:
		maskStrings(masker, &m.Message, &m.Detail, &m.Hint, &m.Where)
	case *pgproto3.NoticeResponse:
		maskStrings(masker, &m.Message, &m.Detail, &m.Hint, &m.Where)
	}
	return msg
}

// Binary COPY rows have no text to match, so they cannot be masked.
func (p *PostgresProxy) blockCopy() pgproto3.BackendMessage {
	p.discarding = true
	return &pgproto3.ErrorResponse{
		Severity: "ERROR",
		Code:     "42501",
		Message:  "Binary COPY and replication are blocked because this account masks output, use COPY in text or CSV format instead",
	}
}

// Binary integers and addresses are matched as the text a text-format client would see, so a card
// number in a bigint column or an address in an inet column is caught whichever format was asked for.
func binaryValueText(typeOID uint32, value []byte) []byte {
	switch {
	case typeOID == pgtype.Int8OID && len(value) == 8:
		return strconv.AppendInt(nil, int64(binary.BigEndian.Uint64(value)), 10)
	case typeOID == pgtype.Int4OID && len(value) == 4:
		return strconv.AppendInt(nil, int64(int32(binary.BigEndian.Uint32(value))), 10)
	case (typeOID == pgtype.InetOID || typeOID == pgtype.CIDROID) && len(value) > 4 && int(value[3]) == len(value)-4:
		if addr, ok := netip.AddrFromSlice(value[4:]); ok {
			return []byte(addr.String())
		}
	}
	return value
}

func maskStrings(masker masking.Masker, fields ...*string) {
	for _, field := range fields {
		*field = masker.MaskString(*field)
	}
}

// Outside an extended batch a RowDescription answers a simple query, so it goes to the client.
func (p *PostgresProxy) answerDescribe(msg pgproto3.BackendMessage) pgproto3.BackendMessage {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if len(p.describes) == 0 || p.describes[0] == syncPoint {
		return msg
	}
	source := p.describes[0]
	p.describes = p.describes[1:]
	if source == describeForMasking {
		return nil
	}
	return msg
}

// popThroughSync drops what the batch ending at this ReadyForQuery left unanswered, as after an error.
func (p *PostgresProxy) popThroughSync() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for len(p.describes) > 0 {
		source := p.describes[0]
		p.describes = p.describes[1:]
		if source == syncPoint {
			return
		}
	}
}
