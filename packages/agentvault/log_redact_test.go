package agentvault

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestTheProxysLogNeverCarriesARelayedCommandOrQuery(t *testing.T) {
	var out bytes.Buffer
	logger := zerolog.New(RedactPayloadLogFields(&out))

	logger.Info().Str("sessionID", "s1").Str("command", "curl -H 'Authorization: Bearer ghp_secret'").Msg("SSH exec command")
	logger.Debug().Str("query", "ALTER USER app PASSWORD 'hunter2'").Msg("← CLIENT Query")
	logger.Info().Str("service", "db").Msg("agent-vault: native connection opened")

	logged := out.String()
	for _, secret := range []string{"ghp_secret", "hunter2"} {
		if strings.Contains(logged, secret) {
			t.Fatalf("the log carries %q:\n%s", secret, logged)
		}
	}
	lines := strings.Split(strings.TrimSpace(logged), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"command":"[redacted]"`) || !strings.Contains(lines[1], `"query":"[redacted]"`) {
		t.Fatalf("lines = %q, want the two payload fields redacted", lines)
	}
	if !strings.Contains(lines[2], `"service":"db"`) || !strings.Contains(lines[0], `"sessionID":"s1"`) {
		t.Fatalf("other fields changed: %q", lines)
	}
}

func TestRedactingKeepsTheLevelForALevelWriter(t *testing.T) {
	var info, errs bytes.Buffer
	split := zerolog.MultiLevelWriter(levelOnly{zerolog.InfoLevel, &info}, levelOnly{zerolog.ErrorLevel, &errs})
	logger := zerolog.New(RedactPayloadLogFields(split))
	logger.Error().Str("command", "rm -rf /").Msg("x")
	if info.Len() != 0 || !strings.Contains(errs.String(), "[redacted]") {
		t.Fatalf("info=%q error=%q, want the redacted line at error only", info.String(), errs.String())
	}
}

type levelOnly struct {
	level zerolog.Level
	w     *bytes.Buffer
}

func (l levelOnly) Write(p []byte) (int, error) { return len(p), nil }

func (l levelOnly) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	if level == l.level {
		return l.w.Write(p)
	}
	return len(p), nil
}
