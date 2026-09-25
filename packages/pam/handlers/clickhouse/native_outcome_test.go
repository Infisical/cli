package clickhouse

import (
	"strings"
	"testing"

	"github.com/ClickHouse/ch-go/proto"

	"github.com/stretchr/testify/require"
)

func newTestRecorder() (*outcomeRecorder, *recordingLogger) {
	logger := &recordingLogger{}
	return newOutcomeRecorder(&ClickHouseProxy{config: ClickHouseProxyConfig{SessionLogger: logger}}), logger
}

func TestOutcomeRecorderPairsStatementsInOrder(t *testing.T) {
	recorder, logger := newTestRecorder()

	recorder.begin("SELECT 1")
	recorder.begin("SELECT 2")
	recorder.progress(7, 70)
	recorder.complete("OK")
	recorder.complete("OK")

	dump := logger.dump()
	require.Contains(t, dump, "SELECT 1 => OK, 7 row(s) read")
	require.Contains(t, dump, "SELECT 2 => OK")
	// The progress landed before either completed, so it belongs to the first statement only.
	require.Equal(t, 1, strings.Count(dump, "row(s) read"))
}

func TestOutcomeRecorderMarksWhatTheSessionCutShort(t *testing.T) {
	recorder, logger := newTestRecorder()

	recorder.begin("SELECT 1")
	recorder.begin("SELECT 2")
	recorder.complete("OK")
	recorder.finish()

	dump := logger.dump()
	require.Contains(t, dump, "SELECT 1 => OK")
	require.Contains(t, dump, "SELECT 2 => INTERRUPTED: the session ended first")
}

func TestOutcomeRecorderDegradesLoudly(t *testing.T) {
	recorder, logger := newTestRecorder()

	recorder.begin("SELECT before")
	recorder.degrade("a column type it could not read")

	// Anything still queued has to say why it has no outcome, rather than look like it did nothing.
	require.Contains(t, logger.dump(), "SELECT before => SENT: the outcome could not be read")

	recorder.begin("SELECT after")
	require.Contains(t, logger.dump(), "SELECT after => SENT")

	// Degrading twice must not double-log, and completing afterwards must not resurrect pairing.
	recorder.degrade("again")
	recorder.complete("OK")
	require.Equal(t, 1, strings.Count(logger.dump(), "outcome could not be read"))
	require.NotContains(t, logger.dump(), "=> OK")
}

func TestOutcomeRecorderIgnoresAnUnmatchedCompletion(t *testing.T) {
	recorder, logger := newTestRecorder()

	// ClickHouse sends packets that are not tied to a statement we queued; they must not panic or invent one.
	recorder.complete("OK")
	recorder.progress(5, 5)
	recorder.finish()

	require.Empty(t, strings.TrimSpace(logger.dump()))
}

func TestNativeParameterSuffix(t *testing.T) {
	require.Empty(t, nativeParameterSuffix(nil))
	require.Equal(t, "\n-- parameters: a=1", nativeParameterSuffix([]proto.Parameter{{Key: "a", Value: "1"}}))
	require.Equal(t, "\n-- parameters: a=1 b=two",
		nativeParameterSuffix([]proto.Parameter{{Key: "a", Value: "1"}, {Key: "b", Value: "two"}}))
}
