package handlers

import (
	"bytes"
	"encoding/json"

	"github.com/Infisical/infisical-merge/packages/pam/session/masking"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
)

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

// The server answers Describes in request order, so a queue of these says whose answer each one is.
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
		for i, field := range m.Fields {
			p.rowColumns = append(p.rowColumns, pgColumnFormat{field.DataTypeOID, field.Format == pgtype.BinaryFormatCode})
			// Dynamic SQL behind a cursor can name a column after a value.
			m.Fields[i].Name = masker.Mask(field.Name)
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
			text := p.matchText(column, value)
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
		// COPY escapes its fields, so patterns can miss values in it.
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
		maskStrings(masker, &m.Channel, &m.Payload)
	case *pgproto3.ParameterStatus:
		// The one reported parameter a query can set to arbitrary text, through set_config.
		if m.Name == "application_name" {
			m.Value = masker.MaskString(m.Value)
		}
	case *pgproto3.ErrorResponse:
		maskErrorFields(masker, m)
	case *pgproto3.NoticeResponse:
		maskErrorFields(masker, (*pgproto3.ErrorResponse)(m))
	}
	return msg
}

// Matches the content a client reads out of a value, so binary encoding or bytea's hex can't hide a match.
func (p *PostgresProxy) matchText(column pgColumnFormat, value []byte) []byte {
	isBytea := column.typeOID == pgtype.ByteaOID || column.typeOID == pgtype.ByteaArrayOID
	if pgTextTypes[column.typeOID] || (!column.binary && !isBytea) {
		return value
	}
	if p.typeMap == nil {
		p.typeMap = pgtype.NewMap()
	}
	dataType, ok := p.typeMap.TypeForOID(column.typeOID)
	if !ok {
		return value
	}
	format := int16(pgtype.TextFormatCode)
	if column.binary {
		format = pgtype.BinaryFormatCode
	}
	decoded, err := dataType.Codec.DecodeValue(p.typeMap, column.typeOID, format, value)
	if err != nil || decoded == nil {
		return value
	}
	if content, ok := appendContent(nil, decoded); ok {
		return content
	}
	if text, err := p.typeMap.Encode(column.typeOID, pgtype.TextFormatCode, decoded, nil); err == nil {
		return text
	}
	return value
}

func appendContent(buf []byte, value any) ([]byte, bool) {
	switch v := value.(type) {
	case []byte:
		return append(buf, v...), true
	case string:
		return append(buf, v...), true
	case []any:
		for i, element := range v {
			if i > 0 {
				buf = append(buf, '\n')
			}
			if element == nil {
				continue
			}
			var ok bool
			if buf, ok = appendContent(buf, element); !ok {
				return nil, false
			}
		}
		return buf, true
	}
	return nil, false
}

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

// Severity, code and source location come from the server, and clients act on them.
func maskErrorFields(masker masking.Masker, e *pgproto3.ErrorResponse) {
	maskStrings(masker, &e.Message, &e.Detail, &e.Hint, &e.Where, &e.InternalQuery, &e.SchemaName, &e.TableName,
		&e.ColumnName, &e.DataTypeName, &e.ConstraintName)
	for key, value := range e.UnknownFields {
		e.UnknownFields[key] = masker.MaskString(value)
	}
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

// After an error the server skips the rest of the batch, so its pending answers never arrive.
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
