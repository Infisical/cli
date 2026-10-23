package winrm

import (
	"encoding/base64"
	"strings"
	"testing"
)

const (
	thumbA = "AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12"
	thumbB = "CD34CD34CD34CD34CD34CD34CD34CD34CD34CD34"
	thumbC = "EF56EF56EF56EF56EF56EF56EF56EF56EF56EF56"
)

func TestBuildStoreScanScriptListsStoresAndRejectsUnknownOnes(t *testing.T) {
	script, err := buildStoreScanScript([]string{"Root", "My", "My"}, 250)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"$requested = @('Root', 'My')",
		"$issuers = @('CA', 'Root')",
		"$max = 250",
		"$maxIssuers = 2000",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script is missing %q", want)
		}
	}

	for _, bad := range []string{"My'; Remove-Item C:\\ -Recurse; '", "TrustedPeople", ""} {
		if _, err := buildStoreScanScript([]string{bad}, 10); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
	if _, err := buildStoreScanScript(nil, 10); err == nil {
		t.Fatal("expected an empty store list to be rejected")
	}
	if _, err := buildStoreScanScript([]string{"My"}, 0); err == nil {
		t.Fatal("expected a zero limit to be rejected")
	}
}

func record(fields ...string) string {
	return "\x1e" + strings.Join(fields, "\t")
}

func TestParseStoreScanOutputIgnoresNoiseAndReadsRecords(t *testing.T) {
	der := base64.StdEncoding.EncodeToString([]byte{0x30, 0x00})
	out := strings.Join([]string{
		"Welcome to web-01",
		record("H", "web-01"),
		record("C", "Root", thumbB, "0", "0", der),
		record("I", "CA"),
		record("J", "Root"),
		"noise " + record("C", "My", strings.ToLower(thumbA), "1", "1", der),
		record("C", "My", thumbA, "1", "1", der),
		record("C", "My", thumbC, "0", "1", "not-base64!"),
		record("C", "My", "not-a-thumbprint", "0", "1", der),
		record("C", "Bogus", thumbC, "0", "1", der),
		record("D", "WebHosting"),
		record("Z"),
	}, "\r\n")

	result := parseStoreScanOutput([]byte(out), 10, false)
	if result.Hostname != "web-01" || result.Truncated || result.HitLimit {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(result.Records) != 2 {
		t.Fatalf("expected 2 valid, deduplicated records, got %d", len(result.Records))
	}
	if result.Records[0].Requested {
		t.Fatal("issuer-only record should not be marked requested")
	}
	mine := result.Records[1]
	if mine.Store != "My" || mine.Thumbprint != thumbA || !mine.HasPrivateKey || !mine.Requested {
		t.Fatalf("unexpected record: %+v", mine)
	}
	if len(result.DeniedStores) != 1 || result.DeniedStores[0] != "WebHosting" {
		t.Fatalf("expected WebHosting denied, got %v", result.DeniedStores)
	}
	if len(result.UnreadableIssuerStores) != 1 || result.UnreadableIssuerStores[0] != "CA" {
		t.Fatalf("expected CA unreadable, got %v", result.UnreadableIssuerStores)
	}
	if len(result.TruncatedIssuerStores) != 1 || result.TruncatedIssuerStores[0] != "Root" {
		t.Fatalf("expected Root cut short, got %v", result.TruncatedIssuerStores)
	}
}

func TestParseStoreScanOutputMarksRequestedIssuerStoresByReference(t *testing.T) {
	der := base64.StdEncoding.EncodeToString([]byte{0x30, 0x00})
	out := strings.Join([]string{
		record("C", "Root", thumbB, "0", "0", der),
		record("C", "Root", thumbC, "0", "0", der),
		record("R", "Root", thumbB, "0"),
		record("R", "Root", "0000000000000000000000000000000000000000", "0"),
		record("Z"),
	}, "\n")
	result := parseStoreScanOutput([]byte(out), 10, false)
	if len(result.Records) != 2 || !result.Records[0].Requested || result.Records[1].Requested {
		t.Fatalf("expected only the referenced Root record to be requested, got %+v", result.Records)
	}
}

func TestParseStoreScanOutputReportsScriptLimitAndBudget(t *testing.T) {
	der := base64.StdEncoding.EncodeToString([]byte{0x30, 0x00})
	out := strings.Join([]string{
		record("C", "My", thumbA, "0", "1", der),
		record("L"),
		record("B"),
		record("Z"),
	}, "\n")
	result := parseStoreScanOutput([]byte(out), 1, false)
	if !result.HitLimit || !result.OverBudget || result.Truncated || len(result.Records) != 1 {
		t.Fatalf("expected limit and budget markers to be read, got %+v", result)
	}
}

func TestParseStoreScanOutputLimitsRequestedAndDetectsCutOff(t *testing.T) {
	der := base64.StdEncoding.EncodeToString([]byte{0x30, 0x00})
	out := strings.Join([]string{
		record("C", "CA", thumbC, "0", "0", der),
		record("C", "My", thumbA, "0", "1", der),
		record("C", "My", thumbB, "0", "1", der),
	}, "\n")

	result := parseStoreScanOutput([]byte(out), 1, false)
	if !result.HitLimit || !result.Truncated {
		t.Fatalf("expected limit hit and missing end marker, got %+v", result)
	}
	requested := 0
	for _, r := range result.Records {
		if r.Requested {
			requested++
		}
	}
	if requested != 1 {
		t.Fatalf("expected 1 requested record, got %d", requested)
	}
}

func TestParseStoreScanOutputDropsTheCutLine(t *testing.T) {
	der := base64.StdEncoding.EncodeToString([]byte{0x30, 0x00, 0x30, 0x00})
	out := record("C", "My", thumbA, "0", "1", der) + "\n" + record("C", "My", thumbB, "0", "1", der[:4])
	result := parseStoreScanOutput([]byte(out), 10, true)
	if len(result.Records) != 1 || result.Records[0].Thumbprint != thumbA {
		t.Fatalf("expected the partial last record to be dropped, got %+v", result.Records)
	}
}
