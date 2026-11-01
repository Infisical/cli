package cmd

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

// --log-format JSON in a unit file used to produce console output silently, which puts human-readable
// lines into a log pipeline with nothing to explain it.
func TestBuildAgentProxyLogWriterAcceptsEitherCase(t *testing.T) {
	for _, format := range []string{"json", "JSON", "Json", " json "} {
		w, err := BuildAgentProxyLogWriter(format, "")
		if err != nil {
			t.Fatalf("%q: unexpected error %v", format, err)
		}
		if w != os.Stderr {
			t.Errorf("%q should give raw JSON on stderr, got %T", format, w)
		}
	}

	for _, format := range []string{"console", "CONSOLE", ""} {
		w, err := BuildAgentProxyLogWriter(format, "")
		if err != nil {
			t.Fatalf("%q: unexpected error %v", format, err)
		}
		if _, ok := w.(zerolog.ConsoleWriter); !ok {
			t.Errorf("%q should give console output, got %T", format, w)
		}
	}
}

func TestBuildAgentProxyLogWriterRefusesAnythingElse(t *testing.T) {
	for _, format := range []string{"banana", "text", "jsonl"} {
		if _, err := BuildAgentProxyLogWriter(format, ""); err == nil {
			t.Errorf("%q was accepted", format)
		}
	}
}
