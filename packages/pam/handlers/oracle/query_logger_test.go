package oracle

import (
	"strings"
	"testing"
)

func framedOracleMessage(message string) []byte {
	return append([]byte{byte(len(message))}, []byte(message)...)
}

func TestOutcomeReportsTheRealOracleError(t *testing.T) {
	payload := framedOracleMessage(`ORA-00904: "VERSION": invalid identifier`)
	got := extractResponseOutcome(payload)
	want := `ERROR: ORA-00904: "VERSION": invalid identifier`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestOutcomeTreatsEndOfFetchAsSuccess(t *testing.T) {
	payload := framedOracleMessage("ORA-01403: no data found")
	if got := extractResponseOutcome(payload); got != sessionOutcomeOK {
		t.Fatalf("end of fetch must not be reported as a failure, got %q", got)
	}
}

func TestOutcomeIgnoresAnUnframedOraMention(t *testing.T) {
	payload := []byte("a row containing the text ORA-00942 without framing")
	if got := extractResponseOutcome(payload); got != sessionOutcomeUnknown {
		t.Fatalf("an unframed mention must not be read as an error, got %q", got)
	}
}

func TestOutcomeOnAPartialPacketIsUnknown(t *testing.T) {
	if got := extractResponseOutcome([]byte{0x01, 0x02}); got != sessionOutcomeUnknown {
		t.Fatalf("a partial packet must read as unknown, got %q", got)
	}
}

func TestStatementDropsItsLengthPrefix(t *testing.T) {
	sql := "SELECT COUNT(*) FROM appdemo.orders"
	if got := trimLengthPrefix(string(rune(len(sql))) + sql); got != sql {
		t.Fatalf("got %q, want %q", got, sql)
	}
	plain := "COMMIT"
	if got := trimLengthPrefix(plain); got != plain {
		t.Fatalf("a statement with no length prefix must be left alone, got %q", got)
	}
	tricky := "5SELECT 1 FROM DUAL"
	if got := trimLengthPrefix(tricky); got != tricky {
		t.Fatalf("a leading character that is not the length must be kept, got %q", got)
	}
}

func TestLengthPrefixTrimIsUnambiguous(t *testing.T) {
	for _, sql := range []string{
		"SELECT COUNT(*) FROM appdemo.orders",
		"DELETE FROM appdemo.orders WHERE id=999",
		"SELECT DECODE(USER, 'XS$NULL',  XS_SYS_CONTEXT('XS$SESSION','USERNAME'), USER) FROM SYS.DUAL",
	} {
		prefixed := string(rune(len(sql))) + sql
		if got := trimLengthPrefix(prefixed); got != sql {
			t.Fatalf("got %q, want %q", got, sql)
		}
	}
	sql := "SELECT DECODE(USER, 'XS$NULL',  XS_SYS_CONTEXT('XS$SESSION','USERNAME'), USER) FROM SYS.DUAL"
	if got := trimLengthPrefix(string(rune(len(sql)+1)) + sql); got != sql {
		t.Fatalf("trailing non-printable case: got %q", got)
	}
	for _, sql := range []string{"COMMIT", "ROLLBACK", "SELECT USER FROM DUAL"} {
		if got := trimLengthPrefix(sql); got != sql {
			t.Fatalf("%q must be left alone, got %q", sql, got)
		}
	}
	long := "SELECT " + strings.Repeat("x", 200)
	if got := trimLengthPrefix(long); got != long {
		t.Fatalf("a long statement must be left alone, got %q", got[:20])
	}
}
