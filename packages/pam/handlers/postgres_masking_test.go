package handlers

import (
	"regexp"
	"testing"

	"github.com/Infisical/infisical-merge/packages/pam/session/masking"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
)

func newMaskingProxy() *PostgresProxy {
	return NewPostgresProxy(PostgresProxyConfig{
		OutputMasker: masking.New([]*regexp.Regexp{regexp.MustCompile(`secret`), regexp.MustCompile(`\b\d{16}\b`)}, false, nil, "test"),
	})
}

func relay(p *PostgresProxy, client []pgproto3.FrontendMessage, server []pgproto3.BackendMessage) (int, []pgproto3.BackendMessage) {
	injected := 0
	for _, msg := range client {
		if p.trackDescribe(msg) != nil {
			injected++
		}
	}
	var forwarded []pgproto3.BackendMessage
	for _, msg := range server {
		if out := p.maskServerMessage(msg); out != nil {
			forwarded = append(forwarded, out)
		}
	}
	return injected, forwarded
}

func rowDescription(format int16, oids ...uint32) *pgproto3.RowDescription {
	desc := &pgproto3.RowDescription{}
	for _, oid := range oids {
		desc.Fields = append(desc.Fields, pgproto3.FieldDescription{Name: []byte("c"), DataTypeOID: oid, Format: format})
	}
	return desc
}

func dataRow(values ...[]byte) *pgproto3.DataRow {
	return &pgproto3.DataRow{Values: values}
}

func messageTypes(msgs []pgproto3.BackendMessage) []string {
	var types []string
	for _, msg := range msgs {
		switch msg.(type) {
		case *pgproto3.ParameterDescription:
			types = append(types, "ParameterDescription")
		case *pgproto3.RowDescription:
			types = append(types, "RowDescription")
		case *pgproto3.DataRow:
			types = append(types, "DataRow")
		case *pgproto3.PortalSuspended:
			types = append(types, "PortalSuspended")
		case *pgproto3.CommandComplete:
			types = append(types, "CommandComplete")
		case *pgproto3.ErrorResponse:
			types = append(types, "ErrorResponse")
		case *pgproto3.ReadyForQuery:
			types = append(types, "ReadyForQuery")
		default:
			types = append(types, "other")
		}
	}
	return types
}

func assertTypes(t *testing.T, got []pgproto3.BackendMessage, want ...string) {
	t.Helper()
	gotTypes := messageTypes(got)
	if len(gotTypes) != len(want) {
		t.Fatalf("forwarded %v, want %v", gotTypes, want)
	}
	for i := range want {
		if gotTypes[i] != want[i] {
			t.Fatalf("forwarded %v, want %v", gotTypes, want)
		}
	}
}

func TestMaskingDropsOnlyTheInsertedDescribe(t *testing.T) {
	p := newMaskingProxy()
	injected, forwarded := relay(p,
		[]pgproto3.FrontendMessage{&pgproto3.Describe{ObjectType: 'S'}, &pgproto3.Execute{}, &pgproto3.Sync{}},
		[]pgproto3.BackendMessage{
			&pgproto3.ParameterDescription{},
			rowDescription(0, pgtype.TextOID),
			rowDescription(0, pgtype.TextOID),
			dataRow([]byte("a secret")),
			&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
		})
	if injected != 1 {
		t.Fatalf("injected %d Describes, want 1", injected)
	}
	assertTypes(t, forwarded, "ParameterDescription", "RowDescription", "DataRow", "CommandComplete", "ReadyForQuery")
	if got := string(forwarded[2].(*pgproto3.DataRow).Values[0]); got != "a [MASKED]" {
		t.Fatalf("row value %q, want %q", got, "a [MASKED]")
	}
}

func TestMaskingClearsABatchThatFailedBeforeItsReply(t *testing.T) {
	p := newMaskingProxy()
	_, forwarded := relay(p,
		[]pgproto3.FrontendMessage{
			&pgproto3.Parse{}, &pgproto3.Bind{}, &pgproto3.Describe{ObjectType: 'P'}, &pgproto3.Execute{}, &pgproto3.Sync{},
			&pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{},
		},
		[]pgproto3.BackendMessage{
			&pgproto3.ErrorResponse{Severity: "ERROR", Message: "syntax error"},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
			rowDescription(0, pgtype.TextOID),
			dataRow([]byte("secret")),
			&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
		})
	assertTypes(t, forwarded, "ErrorResponse", "ReadyForQuery", "DataRow", "CommandComplete", "ReadyForQuery")
}

func TestMaskingDescribesAResumedPortalAgain(t *testing.T) {
	p := newMaskingProxy()
	injected, forwarded := relay(p,
		[]pgproto3.FrontendMessage{&pgproto3.Execute{MaxRows: 1}, &pgproto3.Execute{MaxRows: 1}, &pgproto3.Sync{}},
		[]pgproto3.BackendMessage{
			rowDescription(0, pgtype.TextOID),
			dataRow([]byte("one secret")),
			&pgproto3.PortalSuspended{},
			rowDescription(0, pgtype.TextOID),
			dataRow([]byte("two secret")),
			&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
		})
	if injected != 2 {
		t.Fatalf("injected %d Describes, want 2", injected)
	}
	assertTypes(t, forwarded, "DataRow", "PortalSuspended", "DataRow", "CommandComplete", "ReadyForQuery")
}

func TestMaskingForwardsASimpleQueryRowDescription(t *testing.T) {
	p := newMaskingProxy()
	_, forwarded := relay(p,
		[]pgproto3.FrontendMessage{&pgproto3.Query{String: "SELECT note FROM notes"}},
		[]pgproto3.BackendMessage{
			rowDescription(0, pgtype.TextOID),
			dataRow([]byte("secret")),
			&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
		})
	assertTypes(t, forwarded, "RowDescription", "DataRow", "CommandComplete", "ReadyForQuery")
}

func TestMaskingMatchesBinaryValuesAsText(t *testing.T) {
	typeMap := pgtype.NewMap()
	var card pgtype.Numeric
	if err := card.Scan("4111111111111111"); err != nil {
		t.Fatal(err)
	}
	binaryCard, err := typeMap.Encode(pgtype.NumericOID, pgtype.BinaryFormatCode, card, nil)
	if err != nil {
		t.Fatal(err)
	}

	p := newMaskingProxy()
	_, forwarded := relay(p,
		[]pgproto3.FrontendMessage{&pgproto3.Execute{}, &pgproto3.Sync{}},
		[]pgproto3.BackendMessage{rowDescription(1, pgtype.NumericOID), dataRow(binaryCard)})
	if value := forwarded[0].(*pgproto3.DataRow).Values[0]; value != nil {
		t.Fatalf("binary numeric card number was forwarded as %v, want NULL", value)
	}
}

func TestMaskingKeepsJSONParseable(t *testing.T) {
	p := newMaskingProxy()
	_, forwarded := relay(p,
		[]pgproto3.FrontendMessage{&pgproto3.Query{String: "SELECT doc FROM docs"}},
		[]pgproto3.BackendMessage{
			rowDescription(0, pgtype.JSONOID, pgtype.JSONOID),
			dataRow([]byte(`{"note":"secret"}`), []byte(`{"card":4111111111111111}`)),
		})
	row := forwarded[1].(*pgproto3.DataRow)
	if got := string(row.Values[0]); got != `{"note":"[MASKED]"}` {
		t.Fatalf("string match gave %q", got)
	}
	if row.Values[1] != nil {
		t.Fatalf("number match gave %q, want NULL", row.Values[1])
	}
}

func TestMaskingRefusesCopyAndReplication(t *testing.T) {
	p := newMaskingProxy()
	_, forwarded := relay(p,
		[]pgproto3.FrontendMessage{&pgproto3.Query{String: "COPY notes TO STDOUT"}},
		[]pgproto3.BackendMessage{
			&pgproto3.CopyOutResponse{},
			&pgproto3.CopyData{Data: []byte("secret\n")},
			&pgproto3.CopyDone{},
			&pgproto3.CommandComplete{CommandTag: []byte("COPY 1")},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
		})
	assertTypes(t, forwarded, "ErrorResponse", "ReadyForQuery")

	_, forwarded = relay(p, nil, []pgproto3.BackendMessage{&pgproto3.CopyBothResponse{}})
	if err, ok := forwarded[0].(*pgproto3.ErrorResponse); !ok || err.Severity != "FATAL" || !p.closeAfterReply {
		t.Fatalf("replication reply %+v, closeAfterReply %v", forwarded[0], p.closeAfterReply)
	}
}

func TestMaskingCoversProtocolMetadata(t *testing.T) {
	p := newMaskingProxy()
	_, forwarded := relay(p,
		[]pgproto3.FrontendMessage{&pgproto3.Query{String: "SELECT set_config('application_name', card::text, false) FROM cards"}},
		[]pgproto3.BackendMessage{
			&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("4111111111111111"), DataTypeOID: pgtype.TextOID}}},
			&pgproto3.ParameterStatus{Name: "application_name", Value: "4111111111111111"},
			&pgproto3.ParameterStatus{Name: "server_version", Value: "16.4"},
			&pgproto3.ErrorResponse{Severity: "ERROR", Code: "P0001", Message: "raised", ColumnName: "secret", ConstraintName: "secret"},
			&pgproto3.NotificationResponse{Channel: "secret", Payload: "secret"},
		})
	if name := string(forwarded[0].(*pgproto3.RowDescription).Fields[0].Name); name != "[MASKED]" {
		t.Fatalf("column name %q", name)
	}
	if value := forwarded[1].(*pgproto3.ParameterStatus).Value; value != "[MASKED]" {
		t.Fatalf("application_name %q", value)
	}
	if value := forwarded[2].(*pgproto3.ParameterStatus).Value; value != "16.4" {
		t.Fatalf("server_version %q", value)
	}
	if e := forwarded[3].(*pgproto3.ErrorResponse); e.ColumnName != "[MASKED]" || e.ConstraintName != "[MASKED]" || e.Code != "P0001" {
		t.Fatalf("error fields %+v", e)
	}
	if n := forwarded[4].(*pgproto3.NotificationResponse); n.Channel != "[MASKED]" || n.Payload != "[MASKED]" {
		t.Fatalf("notification %+v", n)
	}
}

func TestMaskingMatchesByteaContent(t *testing.T) {
	typeMap := pgtype.NewMap()
	encode := func(oid uint32, format int16, value any) []byte {
		encoded, err := typeMap.Encode(oid, format, value, nil)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}

	for _, c := range []struct {
		name   string
		oid    uint32
		format int16
		value  []byte
	}{
		{"binary bytea", pgtype.ByteaOID, 1, encode(pgtype.ByteaOID, 1, []byte("a secret"))},
		{"hex bytea", pgtype.ByteaOID, 0, encode(pgtype.ByteaOID, 0, []byte("a secret"))},
		{"binary bytea array", pgtype.ByteaArrayOID, 1, encode(pgtype.ByteaArrayOID, 1, [][]byte{[]byte("x"), []byte("secret")})},
		{"text bytea array", pgtype.ByteaArrayOID, 0, encode(pgtype.ByteaArrayOID, 0, [][]byte{[]byte("secret")})},
		{"binary text array", pgtype.TextArrayOID, 1, encode(pgtype.TextArrayOID, 1, []string{"x", "secret"})},
		{"binary bigint array", pgtype.Int8ArrayOID, 1, encode(pgtype.Int8ArrayOID, 1, []int64{4111111111111111})},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newMaskingProxy()
			_, forwarded := relay(p,
				[]pgproto3.FrontendMessage{&pgproto3.Execute{}, &pgproto3.Sync{}},
				[]pgproto3.BackendMessage{rowDescription(c.format, c.oid), dataRow(c.value)})
			if value := forwarded[0].(*pgproto3.DataRow).Values[0]; value != nil {
				t.Fatalf("forwarded %q, want NULL", value)
			}
		})
	}

	p := newMaskingProxy()
	plain := encode(pgtype.ByteaOID, 0, []byte("nothing to hide"))
	_, forwarded := relay(p,
		[]pgproto3.FrontendMessage{&pgproto3.Execute{}, &pgproto3.Sync{}},
		[]pgproto3.BackendMessage{rowDescription(0, pgtype.ByteaOID), dataRow(plain)})
	if value := forwarded[0].(*pgproto3.DataRow).Values[0]; string(value) != string(plain) {
		t.Fatalf("unmatched bytea forwarded as %q, want %q", value, plain)
	}
}

func TestMaskingChecksFunctionCallResults(t *testing.T) {
	p := newMaskingProxy()
	for _, result := range [][]byte{[]byte("a secret"), []byte("card 4111111111111111")} {
		_, forwarded := relay(p, nil, []pgproto3.BackendMessage{&pgproto3.FunctionCallResponse{Result: result}})
		if got := forwarded[0].(*pgproto3.FunctionCallResponse).Result; got != nil {
			t.Fatalf("function result %q forwarded as %q, want NULL", result, got)
		}
	}
}
