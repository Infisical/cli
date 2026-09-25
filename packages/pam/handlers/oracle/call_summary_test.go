package oracle

import (
	"encoding/hex"
	"strings"
	"testing"
)

func responseFixture(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return b
}

const thinEndOfFetchResponse = "1017894019f665da0c7ecdd43780b2d8aca5787e090e16293001160101820200" +
	"0000011600000000000000000108010808434f554e54282a2900000000000000" +
	"000000010707787e090e163a1900021fe8010201020006220101000102000000" +
	"0702c10408010603895ea90001030000000000000401010202ae010102057b00" +
	"0001030003000000000000000000000000040001010000000002057b01010103" +
	"00194f52412d30313430333a206e6f206461746120666f756e640a"

const thinSuccessResponse = "04030100050202b3000000000105002c000000000003012152000002035c0101" +
	"0000090000000000000000012c00"

const thinErrorResponse = "0401050202b40002038800000108010703000000000003012152000002035c01" +
	"0100000a00000000000002038800010300294f52412d30303930343a20225645" +
	"5253494f4e223a20696e76616c6964206964656e7469666965720a"

const ociSuccessResponse = "080600a35e890000000000020000000200000000000000000000000000000000" +
	"00000004050001009c020100000000000000000000020000002c000000000052" +
	"210100000400005c030000000000000000000000130000000000003601000000" +
	"0000000000000000000000d02171a1ffff000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"000000000000000000000000000000000000002c000000000000001d"

const ociErrorResponse = "0401000000a8020100000000c405000000000200080003000000000052210100" +
	"000000005c0300000000000000000000001f0000010000003601000000000000" +
	"0000000000000000d02171a1ffff000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"00000000c405000000000000000000000300000000000000244f52412d303134" +
	"37363a2064697669736f7220697320657175616c20746f207a65726f0a1d"

func TestOutcomeOnRealResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
		want string
	}{
		{"thin success", thinSuccessResponse, sessionOutcomeOK},
		{"thin end of fetch", thinEndOfFetchResponse, sessionOutcomeOK},
		{"oci success", ociSuccessResponse, sessionOutcomeOK},
		{"thin error", thinErrorResponse, `ERROR: ORA-00904: "VERSION": invalid identifier`},
		{"oci error", ociErrorResponse, "ERROR: ORA-01476: divisor is equal to zero"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := extractResponseOutcome(responseFixture(t, tc.hex))
			if tc.want == sessionOutcomeOK {
				if got != sessionOutcomeOK {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
				return
			}
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("got %q, want prefix %q", got, tc.want)
			}
		})
	}
}

func TestOutcomeNeverInventsSuccess(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"truncated", []byte{0x04, 0x01}},
		{"row data holding a stray marker", append([]byte{0x08, 0x01, 0x04, 0x00, 0x00}, []byte("a row value")...)},
		{"unframed oracle text", []byte("a row mentioning ORA-00942 in passing")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractResponseOutcome(tc.payload); got != sessionOutcomeUnknown {
				t.Fatalf("got %q, want %q", got, sessionOutcomeUnknown)
			}
		})
	}
}

func TestSummaryParserRejectsAStrayMarker(t *testing.T) {
	payload := append([]byte{TTCMsgError}, make([]byte, 200)...)
	if summary, ok := parseCallSummary(payload); ok && summary.retCode != 0 {
		t.Fatalf("zero padding must not decode as an error, got %+v", summary)
	}
}

func TestFramedTextRequiresTheDeclaredLength(t *testing.T) {
	message := "ORA-00942: table or view does not exist"
	good := append([]byte{byte(len(message))}, []byte(message)...)
	if _, ok := oracleErrorFromFramedText(good); !ok {
		t.Fatal("a correctly framed message must be recognised")
	}
	bad := append([]byte{byte(len(message) + 9)}, []byte(message)...)
	if _, ok := oracleErrorFromFramedText(bad); ok {
		t.Fatal("a message whose declared length does not match must be rejected")
	}
}

func TestEndOfCallStatusIsRecognisedInBothEncodings(t *testing.T) {
	fixedWidth := []byte{TTCMsgStatus, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, ttcEndOfMessage}
	if extractResponseOutcome(fixedWidth) != sessionOutcomeOK {
		t.Fatal("the fixed width end of call status must confirm the call completed")
	}
	compressed := []byte{TTCMsgStatus, 0x01, 0x01, 0x00}
	if extractResponseOutcome(compressed) != sessionOutcomeOK {
		t.Fatal("the compressed end of call status must confirm the call completed")
	}
	truncated := []byte{TTCMsgStatus, 0x04, 0x01}
	if extractResponseOutcome(truncated) != sessionOutcomeUnknown {
		t.Fatal("a truncated status message must not be read as success")
	}
}
