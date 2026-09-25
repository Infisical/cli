package clickhouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/ch-go"
	"github.com/ClickHouse/ch-go/proto"
	"github.com/rs/zerolog"
)

// Serves ClickHouse's HTTP interface over the native protocol, for a server that has HTTP disabled. Web Access
// reaches the gateway over HTTP and @clickhouse/client cannot speak native, so without this a native-only
// account would work from the CLI and nowhere else.
//
// ClickHouse serialises the values itself through formatRow, so every column type keeps working without this
// having to decode one.
//
// Only the two envelopes Web Access asks for are produced, and that is the intended scope rather than a gap.
// A native-only account is reached by native clients; a third-party HTTP client such as JDBC, which
// negotiates a binary format, is expected to fail against it rather than be translated for.

const (
	formatJSON        = "JSON"
	formatJSONCompact = "JSONCompact"

	// What formatRow is asked for, so each row arrives as the exact fragment the envelope needs.
	rowFormatJSON        = "JSONEachRow"
	rowFormatJSONCompact = "JSONCompactEachRow"

	bridgeReadTimeout = 5 * time.Minute
	maxBridgeRows     = 100_000
	// A row count alone does not bound memory: one row can be hundreds of megabytes, and the envelope is
	// assembled in memory. The gateway is shared, so one session must not be able to exhaust it.
	maxBridgeResultBytes = 64 << 20

	// The formatted column has to be named, because its default name is the whole call expression.
	formattedRowAlias = "__infisical_row"
)

type bridgeColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type bridgeStatistics struct {
	Elapsed   float64 `json:"elapsed"`
	RowsRead  uint64  `json:"rows_read"`
	BytesRead uint64  `json:"bytes_read"`
}

type bridgeEnvelope struct {
	Meta       []bridgeColumn   `json:"meta"`
	Data       json.RawMessage  `json:"data"`
	Rows       int              `json:"rows"`
	Statistics bridgeStatistics `json:"statistics"`
}

func (p *ClickHouseProxy) dialNative(ctx context.Context) (*ch.Client, error) {
	options := ch.Options{
		Address:          p.config.NativeAddr,
		Database:         p.config.Database,
		User:             p.config.Username,
		Password:         p.config.Password,
		ClientName:       "Infisical PAM",
		DialTimeout:      nativeDialTimeout,
		ReadTimeout:      bridgeReadTimeout,
		Compression:      ch.CompressionDisabled,
		ProtocolVersion:  maxNativeRevision,
		HandshakeTimeout: nativeHandshakeTimeout,
	}
	if p.config.EnableTLS {
		options.TLS = p.config.TLSConfig
	}
	return ch.Dial(ctx, options)
}

// serveBridge answers one HTTP request by running its statement over the native protocol.
func (p *ClickHouseProxy) serveBridge(w http.ResponseWriter, r *http.Request, state *requestState, l zerolog.Logger) {
	// The health endpoint carries no statement, so it would otherwise be refused as an empty one.
	if r.URL.Path == pingPath {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Ok.\n"))
		return
	}

	// The statement was already decoded during inspection, compression and all, so it is used rather than
	// the body, which the bridge cannot hand to ClickHouse the way the reverse proxy can.
	if state.truncated {
		message := fmt.Sprintf(
			"this account reaches ClickHouse over the native protocol, so a statement larger than %d MB is "+
				"not supported here", maxInspectBytes>>20)
		p.logStatement(state.statement, "ERROR: "+message)
		writeClickHouseError(w, http.StatusBadRequest, codeNotImplemented, message)
		return
	}

	body, format := splitFormatClause(state.sql)
	if format == "" {
		// A client can ask for the format as a setting instead of a clause, which is what the SQL editor does.
		format = r.URL.Query().Get("default_format")
	}
	if body == "" {
		writeClickHouseError(w, http.StatusBadRequest, codeNotImplemented, "No statement was sent.")
		return
	}

	client, err := p.dialNative(r.Context())
	if err != nil {
		l.Error().Err(err).Msg("Failed to reach ClickHouse over the native protocol")
		p.logStatement(state.statement, fmt.Sprintf("ERROR: %s", err))
		writeClickHouseError(w, http.StatusBadGateway, codeNetworkError,
			fmt.Sprintf("The gateway could not reach ClickHouse: %v", err))
		return
	}
	defer client.Close()

	envelope, err := p.runBridgeQuery(r.Context(), client, body, format, bridgeParameters(r), bridgeSettings(r))
	if err != nil {
		code, status, message := classifyNativeError(err)
		p.logStatement(state.statement, fmt.Sprintf("ERROR: %s", message))
		writeClickHouseError(w, status, code, message)
		return
	}

	envelope.Statistics.Elapsed = time.Since(state.started).Seconds()

	if format == "" {
		p.logStatement(state.statement, summarizeBridge(envelope, state.started))
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		return
	}

	encoded, err := json.Marshal(envelope)
	if err != nil {
		writeClickHouseError(w, http.StatusInternalServerError, codeNotImplemented, err.Error())
		return
	}

	p.logStatement(state.statement, summarizeBridge(envelope, state.started))

	summary, _ := json.Marshal(map[string]string{
		"read_rows":   strconv.FormatUint(envelope.Statistics.RowsRead, 10),
		"read_bytes":  strconv.FormatUint(envelope.Statistics.BytesRead, 10),
		"result_rows": strconv.Itoa(envelope.Rows),
	})

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("X-ClickHouse-Summary", string(summary))
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

func bridgeParameters(r *http.Request) []proto.Parameter {
	var parameters []proto.Parameter
	for name, values := range r.URL.Query() {
		if !strings.HasPrefix(name, "param_") || len(values) == 0 {
			continue
		}
		parameters = append(parameters, proto.Parameter{
			Key:   strings.TrimPrefix(name, "param_"),
			Value: quoteFieldDump(values[0]),
		})
	}
	return parameters
}

// The native protocol carries a query parameter as a custom setting, whose value ClickHouse reads as a Field
// dump rather than as the plain string the HTTP interface takes. An unquoted value is rejected outright.
func quoteFieldDump(value string) string {
	var quoted strings.Builder
	quoted.Grow(len(value) + 2)
	quoted.WriteByte('\'')
	// Byte-wise, because ranging over the string would turn every invalid byte into U+FFFD and silently
	// change the value. The two escapes are ASCII, and UTF-8 is self-synchronising.
	for i := 0; i < len(value); i++ {
		if c := value[i]; c == '\\' || c == '\'' {
			quoted.WriteByte('\\')
		}
		quoted.WriteByte(value[i])
	}
	quoted.WriteByte('\'')
	return quoted.String()
}

// splitFormatClause peels off the trailing FORMAT clause @clickhouse/client appends, which decides the
// envelope rather than anything the server should see. The scan runs over the original bytes: uppercasing
// first would shift offsets, because some runes shrink when folded.
func splitFormatClause(sql string) (string, string) {
	trimmed := trimTrailingSemicolons(sql)

	idx := lastIndexFold(trimmed, "FORMAT")
	if idx <= 0 {
		return trimmed, ""
	}
	// A word boundary is needed on both sides, or a trailing identifier such as `format_events` is read as
	// the clause and the operand before it is thrown away.
	if !isSQLSpace(trimmed[idx-1]) {
		return trimmed, ""
	}
	after := trimmed[idx+len("FORMAT"):]
	if after == "" || !isSQLSpace(after[0]) {
		return trimmed, ""
	}

	name := strings.TrimSpace(after)
	if !isFormatName(name) {
		return trimmed, ""
	}

	return trimTrailingSemicolons(trimmed[:idx]), name
}

// A format name is a bare identifier. Anything else means the word FORMAT was part of the statement.
func isFormatName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func isSQLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// trimTrailingSemicolons removes any run of trailing semicolons and the whitespace around them, so
// `SELECT 1 ; ;` does not end up inside the subquery wrapper.
func trimTrailingSemicolons(sql string) string {
	trimmed := strings.TrimSpace(sql)
	for strings.HasSuffix(trimmed, ";") {
		trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, ";"))
	}
	return trimmed
}

// lastIndexFold is strings.LastIndex with ASCII case folding, returning an offset into s itself.
func lastIndexFold(s string, substr string) int {
	for i := len(s) - len(substr); i >= 0; i-- {
		if strings.EqualFold(s[i:i+len(substr)], substr) {
			return i
		}
	}
	return -1
}

// checkSpliceable rejects a statement that would not stay inside the parentheses it is wrapped in. Quotes
// and comments are tracked so that a semicolon or bracket inside a string literal is left alone.
func checkSpliceable(body string) error {
	depth := 0
	for i := 0; i < len(body); i++ {
		switch c := body[i]; c {
		case '\'', '"', '`':
			end := skipQuoted(body, i, c)
			if end < 0 {
				return refuseBridge(codeNotImplemented, "this statement has an unterminated string, so the gateway could not read it")
			}
			i = end
		case '-':
			if i+1 < len(body) && body[i+1] == '-' {
				if idx := strings.IndexByte(body[i:], '\n'); idx != -1 {
					i += idx
				} else {
					i = len(body)
				}
			}
		case '/':
			if i+1 < len(body) && body[i+1] == '*' {
				idx := strings.Index(body[i+2:], "*/")
				if idx == -1 {
					return refuseBridge(codeNotImplemented, "this statement has an unterminated comment, so the gateway could not read it")
				}
				i += 2 + idx + 1
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return refuseBridge(codeNotImplemented,
					"this statement closes more parentheses than it opens, which the gateway cannot run over "+
						"ClickHouse's native protocol")
			}
		case ';':
			return refuseBridge(codeNotImplemented,
				"this account reaches ClickHouse over the native protocol, which runs one statement at a "+
					"time, so a semicolon inside a statement is not supported")
		}
	}
	if depth != 0 {
		return refuseBridge(codeNotImplemented,
			"this statement leaves %d parenthesis open, so the gateway could not run it", depth)
	}
	return nil
}

// skipQuoted returns the index of the closing quote, honouring doubled and backslash escapes.
func skipQuoted(body string, start int, quote byte) int {
	for i := start + 1; i < len(body); i++ {
		switch body[i] {
		case '\\':
			i++
		case quote:
			if i+1 < len(body) && body[i+1] == quote {
				i++
				continue
			}
			return i
		}
	}
	return -1
}

// humanList renders an allowlist the way the error messages read, so the message and the list cannot drift.
func humanList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
	}
}

func rowFormatFor(format string) (string, error) {
	switch strings.ToUpper(format) {
	case strings.ToUpper(formatJSON):
		return rowFormatJSON, nil
	case strings.ToUpper(formatJSONCompact):
		return rowFormatJSONCompact, nil
	default:
		return "", refuseBridge(codeNotImplemented,
			"this account has no HTTP port, so it is reached over ClickHouse's native protocol and only %s and "+
				"%s can be returned. This client asked for %s. Use a native client such as clickhouse-client, "+
				"or give the account an HTTP port",
			formatJSON, formatJSONCompact, format)
	}
}

// Settings a client sends to bound a statement. They are forwarded so a browser session costs the server no
// more over the native protocol than it does over HTTP; anything else a client asks for is dropped.
var forwardedSettings = map[string]bool{
	"max_execution_time":   true,
	"max_result_rows":      true,
	"max_result_bytes":     true,
	"result_overflow_mode": true,
	"max_rows_to_read":     true,
	"readonly":             true,
}

func bridgeSettings(r *http.Request) []ch.Setting {
	var settings []ch.Setting
	for name, values := range r.URL.Query() {
		if !forwardedSettings[name] || len(values) == 0 {
			continue
		}
		settings = append(settings, ch.Setting{Key: name, Value: values[0], Important: true})
	}
	return settings
}

func (p *ClickHouseProxy) runBridgeQuery(
	ctx context.Context,
	client *ch.Client,
	body string,
	format string,
	parameters []proto.Parameter,
	settings []ch.Setting,
) (*bridgeEnvelope, error) {
	envelope := &bridgeEnvelope{Meta: []bridgeColumn{}, Data: json.RawMessage("[]")}

	// A statement with no FORMAT clause is one nothing reads the rows of, so it only has to run.
	if format == "" {
		var discard proto.Results
		return envelope, client.Do(ctx, ch.Query{
			Body:       body,
			Parameters: parameters,
			Settings:   settings,
			Result:     discard.Auto(),
			// ch-go refuses a second data block unless a handler is present, so a statement that returns
			// more than one block would fail even though nothing here reads the rows.
			OnResult: func(context.Context, proto.Block) error { return nil },
			OnProgress: func(_ context.Context, pr proto.Progress) error {
				envelope.Statistics.RowsRead += pr.Rows
				envelope.Statistics.BytesRead += pr.Bytes
				return nil
			},
		})
	}

	rowFormat, err := rowFormatFor(format)
	if err != nil {
		return nil, err
	}

	if !isWrappable(body) {
		return nil, refuseBridge(codeNotImplemented,
			"this account reaches ClickHouse over the native protocol, where the gateway can only return rows "+
				"for a %s. Run this statement from the CLI instead", humanList(wrappableStatements))
	}

	meta, err := describeStatement(ctx, client, body, parameters, settings)
	if err != nil {
		return nil, err
	}
	envelope.Meta = meta

	rows, err := selectFormattedRows(ctx, client, body, rowFormat, parameters, settings, envelope)
	if err != nil {
		return nil, err
	}

	envelope.Rows = len(rows)
	envelope.Data = json.RawMessage("[" + strings.Join(rows, ",") + "]")
	return envelope, nil
}

// Only these can sit inside a subquery, which is what both halves of the bridge rely on.
var wrappableStatements = []string{"SELECT", "WITH", "EXPLAIN"}

func isWrappable(body string) bool {
	rest := strings.TrimLeft(stripLeadingNoise(body), "(")
	for _, prefix := range wrappableStatements {
		if len(rest) < len(prefix) || !strings.EqualFold(rest[:len(prefix)], prefix) {
			continue
		}
		// A prefix match is not a keyword match: SELECTFOO is an identifier, not a SELECT.
		if len(rest) == len(prefix) || !isIdentifierByte(rest[len(prefix)]) {
			return true
		}
	}
	return false
}

func isIdentifierByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// stripLeadingNoise drops a byte-order mark, whitespace and leading comments, which editors add freely and
// which would otherwise make a perfectly ordinary SELECT look like something the bridge cannot serve.
func stripLeadingNoise(body string) string {
	rest := strings.TrimPrefix(body, "\ufeff")
	for {
		rest = strings.TrimLeft(rest, " \t\r\n")
		switch {
		case strings.HasPrefix(rest, "--"):
			if idx := strings.IndexByte(rest, '\n'); idx != -1 {
				rest = rest[idx+1:]
				continue
			}
			return ""
		case strings.HasPrefix(rest, "/*"):
			idx := strings.Index(rest[2:], "*/")
			if idx == -1 {
				return ""
			}
			rest = rest[2+idx+2:]
			continue
		default:
			return rest
		}
	}
}

// DESCRIBE resolves the statement's header without running it, so the column types are the server's own.
func describeStatement(
	ctx context.Context,
	client *ch.Client,
	body string,
	parameters []proto.Parameter,
	settings []ch.Setting,
) ([]bridgeColumn, error) {
	// DESCRIBE returns more columns than are needed here and the set has grown between versions, so they are
	// inferred and picked by name rather than bound positionally.
	var described proto.Results
	columns := []bridgeColumn{}

	err := client.Do(ctx, ch.Query{
		Body:       "DESCRIBE (\n" + body + "\n)",
		Parameters: parameters,
		Settings:   settings,
		Result:     described.Auto(),
		OnResult: func(_ context.Context, block proto.Block) error {
			names, err := stringColumn(described, "name")
			if err != nil {
				return err
			}
			types, err := stringColumn(described, "type")
			if err != nil {
				return err
			}
			for i := 0; i < block.Rows; i++ {
				columns = append(columns, bridgeColumn{Name: names.Row(i), Type: types.Row(i)})
			}
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	return columns, nil
}

func stringColumn(results proto.Results, name string) (*proto.ColStr, error) {
	for _, column := range results {
		if column.Name != name {
			continue
		}
		if typed, ok := column.Data.(*proto.ColStr); ok {
			return typed, nil
		}
		return nil, fmt.Errorf("DESCRIBE returned %q as %s rather than String", name, column.Data.Type())
	}
	return nil, fmt.Errorf("DESCRIBE returned no %q column", name)
}

func selectFormattedRows(
	ctx context.Context,
	client *ch.Client,
	body string,
	rowFormat string,
	parameters []proto.Parameter,
	settings []ch.Setting,
	envelope *bridgeEnvelope,
) ([]string, error) {
	var formatted proto.ColStr
	rows := make([]string, 0, 64)
	resultBytes := 0

	err := client.Do(ctx, ch.Query{
		Body: "SELECT formatRowNoNewline('" + rowFormat + "', *) AS " + formattedRowAlias +
			" FROM (\n" + body + "\n)",
		Parameters: parameters,
		Settings:   settings,
		Result:     proto.Results{{Name: formattedRowAlias, Data: &formatted}},
		OnResult: func(_ context.Context, block proto.Block) error {
			for i := 0; i < block.Rows; i++ {
				if len(rows) >= maxBridgeRows {
					return refuseBridge(codeTooManyRows,
						"this statement returned more than %d rows, which is more than a browser session "+
							"returns over the native protocol. Add a LIMIT, or use the CLI", maxBridgeRows)
				}
				row := formatted.Row(i)
				resultBytes += len(row) + 1
				if resultBytes > maxBridgeResultBytes {
					return refuseBridge(codeTooManyRows,
						"this statement returned more than %d MB, which is more than a browser session "+
							"returns over the native protocol. Narrow the result, or use the CLI",
						maxBridgeResultBytes>>20)
				}
				rows = append(rows, row)
			}
			return nil
		},
		OnProgress: func(_ context.Context, pr proto.Progress) error {
			envelope.Statistics.RowsRead += pr.Rows
			envelope.Statistics.BytesRead += pr.Bytes
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// bridgeRefusal is something the gateway decided about the request itself, so it carries its own ClickHouse
// code and is reported as a bad request rather than as a network error wrapped in ch-go's decoding context.
type bridgeRefusal struct {
	code    int
	message string
}

func (e *bridgeRefusal) Error() string { return e.message }

func refuseBridge(code int, format string, args ...any) error {
	return &bridgeRefusal{code: code, message: fmt.Sprintf(format, args...)}
}

// classifyNativeError turns a ch-go error back into the code, message and status a ClickHouse client expects.
func classifyNativeError(err error) (int, int, string) {
	var refusal *bridgeRefusal
	if errors.As(err, &refusal) {
		return refusal.code, http.StatusBadRequest, refusal.message
	}
	if exception, ok := ch.AsException(err); ok {
		return int(exception.Code), http.StatusBadRequest, exception.Message
	}
	return codeNetworkError, http.StatusBadGateway, err.Error()
}

func summarizeBridge(envelope *bridgeEnvelope, started time.Time) string {
	parts := []string{"200 OK"}
	if envelope.Rows > 0 {
		parts = append(parts, fmt.Sprintf("%d row(s) returned", envelope.Rows))
	}
	if envelope.Statistics.RowsRead > 0 {
		parts = append(parts, fmt.Sprintf("%d row(s) read", envelope.Statistics.RowsRead))
	}
	return strings.Join(append(parts, fmt.Sprintf("%dms", time.Since(started).Milliseconds())), ", ")
}
