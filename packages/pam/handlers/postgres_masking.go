package handlers

import (
	"bytes"
	"encoding/json"

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
			isText := pgTextTypes[column.typeOID]
			text := value
			if column.binary && !isText {
				text = p.binaryValueText(column.typeOID, value)
			}
			masked := masker.Mask(text)
			if bytes.Equal(masked, text) {
				continue
			}
			if isText && keepsValidJSON(column, masked) {
				m.Values[i] = masked
			} else {
				// A placeholder would not decode as this column's type.
				m.Values[i] = nil
			}
		}
	case *pgproto3.CopyOutResponse:
		// COPY escapes its fields (CSV doubles quotes, text escapes control characters), so a pattern can
		// miss a value there that it matches in a row.
		p.discarding = true
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "42501",
			Message:  "COPY TO STDOUT is blocked because this account masks output, use SELECT instead",
		}
	case *pgproto3.CopyBothResponse:
		// A replication stream never reaches ReadyForQuery, so only ending the connection stops it.
		p.closeAfterReply = true
		return &pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "42501",
			Message:  "Replication is blocked because this account masks output",
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

// A binary value is matched as the text a text-format client would see, so a card number in a numeric
// column is caught whichever format was asked for. A type pgx can't decode is matched as its raw bytes.
func (p *PostgresProxy) binaryValueText(typeOID uint32, value []byte) []byte {
	if p.typeMap == nil {
		p.typeMap = pgtype.NewMap()
	}
	dataType, ok := p.typeMap.TypeForOID(typeOID)
	if !ok {
		return value
	}
	decoded, err := dataType.Codec.DecodeValue(p.typeMap, typeOID, pgtype.BinaryFormatCode, value)
	if err != nil || decoded == nil {
		return value
	}
	text, err := p.typeMap.Encode(typeOID, pgtype.TextFormatCode, decoded, nil)
	if err != nil {
		return value
	}
	return text
}

// A match inside a JSON number or key leaves a placeholder the client can't parse.
func keepsValidJSON(column pgColumnFormat, masked []byte) bool {
	switch column.typeOID {
	case pgtype.JSONOID:
		return json.Valid(masked)
	case pgtype.JSONBOID:
		if column.binary && len(masked) > 0 {
			masked = masked[1:] // binary jsonb leads with a version byte
		}
		return json.Valid(masked)
	}
	return true
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
