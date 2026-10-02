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

	require.Contains(t, logger.dump(), "SELECT before => SENT: the outcome could not be read")

	recorder.begin("SELECT after")
	require.Contains(t, logger.dump(), "SELECT after => SENT")

	recorder.degrade("again")
	recorder.complete("OK")
	require.Equal(t, 1, strings.Count(logger.dump(), "outcome could not be read"))
	require.NotContains(t, logger.dump(), "=> OK")
}

func TestOutcomeRecorderIgnoresAnUnmatchedCompletion(t *testing.T) {
	recorder, logger := newTestRecorder()

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

func TestOutcomeRecorderRecordsARefusalItKnowsAbout(t *testing.T) {
	t.Run("while it is still pairing", func(t *testing.T) {
		recorder, logger := newTestRecorder()

		recorder.begin("INSERT INTO exotic VALUES")
		recorder.refuse("a data block could not be read, so it was not forwarded")

		require.Contains(t, logger.dump(),
			"INSERT INTO exotic VALUES => REFUSED: a data block could not be read, so it was not forwarded")
	})

	// ClickHouse answers an INSERT with the table's own columns, so a type the gateway cannot read
	// makes the server direction give up before the client's block is even refused.
	t.Run("after the server direction gave up", func(t *testing.T) {
		recorder, logger := newTestRecorder()

		recorder.begin("INSERT INTO exotic VALUES")
		recorder.degrade("automatic column inference not supported")
		recorder.refuse("a data block could not be read, so it was not forwarded")

		dump := logger.dump()
		require.Contains(t, dump, "REFUSED: a data block could not be read, so it was not forwarded",
			"a refusal the gateway made itself must be recorded, not left as sent")
		require.Contains(t, dump, "the outcome could not be read")
	})

	t.Run("with nothing to attach it to", func(t *testing.T) {
		recorder, logger := newTestRecorder()
		recorder.refuse("a data block could not be read")
		require.Empty(t, logger.dump(), "a refusal with no statement must not invent one")
	})

	t.Run("never onto a statement that already has an outcome", func(t *testing.T) {
		recorder, logger := newTestRecorder()

		recorder.begin("SELECT 1")
		recorder.complete("OK")
		recorder.refuse("a data block could not be read")

		dump := logger.dump()
		require.Contains(t, dump, "SELECT 1 => OK")
		require.NotContains(t, dump, "REFUSED",
			"a packet arriving after a statement finished must not be blamed on it")
	})

	t.Run("only once for one statement", func(t *testing.T) {
		recorder, logger := newTestRecorder()

		recorder.begin("INSERT INTO exotic VALUES")
		recorder.degrade("automatic column inference not supported")
		recorder.refuse("a data block could not be read")
		recorder.refuse("a data block could not be read")

		require.Equal(t, 1, strings.Count(logger.dump(), "REFUSED"))
	})
}

// A statement is kept for as long as the session lives, so only what a recording can hold is kept.
func TestOutcomeRecorderKeepsOnlyWhatItCanRecord(t *testing.T) {
	recorder, logger := newTestRecorder()

	huge := "SELECT " + strings.Repeat("x", 4<<20)
	recorder.begin(huge)
	recorder.complete("OK")

	require.LessOrEqual(t, len(recorder.last), maxLoggedStatementBytes+len("... [truncated]"))
	require.Contains(t, logger.dump(), "... [truncated]")
}
