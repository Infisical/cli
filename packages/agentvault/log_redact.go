package agentvault

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/rs/zerolog"
)

// PAM's handlers log every SSH command and SQL query they relay (SSH commands at info), whether or not session logs
// are on, so a token on a command line would reach the proxy's console. The proxy can't change those lines, so it
// blanks the fields on the way out. Agent Vault's own lines don't use these names.
var redactedLogFields = []string{"command", "query"}

// RedactPayloadLogFields wraps the proxy's log output so no line carries a command or query PAM relayed.
func RedactPayloadLogFields(w io.Writer) io.Writer {
	return &redactingLogWriter{w: w}
}

type redactingLogWriter struct{ w io.Writer }

func (r *redactingLogWriter) Write(p []byte) (int, error) {
	if _, err := r.w.Write(redactLogFields(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (r *redactingLogWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	out := redactLogFields(p)
	var err error
	if lw, ok := r.w.(zerolog.LevelWriter); ok {
		_, err = lw.WriteLevel(level, out)
	} else {
		_, err = r.w.Write(out)
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func redactLogFields(p []byte) []byte {
	if !bytes.Contains(p, []byte(`"command"`)) && !bytes.Contains(p, []byte(`"query"`)) {
		return p
	}
	var event map[string]json.RawMessage
	if err := json.Unmarshal(p, &event); err != nil {
		return p
	}
	changed := false
	for _, field := range redactedLogFields {
		if _, ok := event[field]; ok {
			event[field] = json.RawMessage(`"[redacted]"`)
			changed = true
		}
	}
	if !changed {
		return p
	}
	out, err := json.Marshal(event)
	if err != nil {
		return p
	}
	return append(out, '\n')
}
