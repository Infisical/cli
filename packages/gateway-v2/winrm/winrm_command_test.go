package winrm

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/masterzen/winrm"
)

func TestEscapePowerShellSingleQuotesNeutralizesInjection(t *testing.T) {
	got := escapePowerShellSingleQuotes(`it's'; Remove-Item C:\ -Recurse; #`)

	if !strings.Contains(got, `it''s''; Remove-Item C:\ -Recurse; #`) {
		t.Fatalf("expected doubled single quotes, got %q", got)
	}
	if strings.Contains(got, `'it's'`) {
		t.Fatalf("single quote was not escaped, got %q", got)
	}
}

func TestBuildCommandScriptPropagatesFailures(t *testing.T) {
	script := buildCommandScript("Write-Output ok", "nonce123")

	for _, expected := range []string{
		"$ErrorActionPreference = 'Stop'",
		"if (-not $?) { $InfisicalExitCode = if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 } }",
		"[Console]::Error.WriteLine($_.Exception.Message)",
		"[Console]::Out.WriteLine('nonce123:' + $InfisicalExitCode)",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("expected script to contain %q, got:\n%s", expected, script)
		}
	}
	if strings.Contains(script, "exit $LASTEXITCODE") || strings.Contains(script, "exit 1") {
		t.Fatalf("the script must state its outcome rather than exit with a code, got:\n%s", script)
	}
}

func TestTakeCommandTrailer(t *testing.T) {
	const nonce = "infisical-abc"

	t.Run("reads the stated code and strips the trailer", func(t *testing.T) {
		// The blank line is the separator the script writes before the trailer.
		code, remaining, ok := takeCommandTrailer("reloaded\r\n\r\n"+nonce+":7\r\n", nonce)
		if !ok || code != 7 {
			t.Fatalf("expected code 7 to be read, got code=%d ok=%v", code, ok)
		}
		// The command's own newline survives; only the separator the script added is removed.
		if remaining != "reloaded\r\n" {
			t.Fatalf("expected only the trailer and its separator to be stripped, got %q", remaining)
		}
	})

	t.Run("reports no trailer when the command exited early", func(t *testing.T) {
		if _, _, ok := takeCommandTrailer("partial output\r\n", nonce); ok {
			t.Fatal("expected output with no trailer to report none")
		}
	})

	t.Run("finds the trailer even when the command left no newline before it", func(t *testing.T) {
		code, remaining, ok := takeCommandTrailer("no trailing newline"+nonce+":3", nonce)
		if !ok || code != 3 {
			t.Fatalf("expected the marker to be found mid-line, got code=%d ok=%v", code, ok)
		}
		if remaining != "no trailing newline" {
			t.Fatalf("expected the command's own output to survive, got %q", remaining)
		}
	})

	t.Run("keeps the last marker when output contains an earlier lookalike", func(t *testing.T) {
		code, _, ok := takeCommandTrailer("echoed "+nonce+":9\r\n"+nonce+":0", nonce)
		if !ok || code != 0 {
			t.Fatalf("expected the trailing marker to win, got code=%d ok=%v", code, ok)
		}
	})

	t.Run("a command echoing a trailer of its own cannot forge one", func(t *testing.T) {
		if _, _, ok := takeCommandTrailer("infisical-guessed:0\r\n", nonce); ok {
			t.Fatal("expected a foreign marker to be ignored")
		}
	})

	t.Run("leaves stdout untouched when there is no trailer", func(t *testing.T) {
		_, remaining, _ := takeCommandTrailer("just output", nonce)
		if remaining != "just output" {
			t.Fatalf("expected stdout to survive unchanged, got %q", remaining)
		}
	})
}

func TestNewCommandNonceIsUniquePerRun(t *testing.T) {
	first, err := newCommandNonce()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, _ := newCommandNonce()

	if first == second {
		t.Fatal("expected a fresh nonce per run so a command cannot predict it")
	}
	if !strings.HasPrefix(first, "infisical-") || len(first) < 20 {
		t.Fatalf("unexpected nonce shape %q", first)
	}
}

func TestNormalizePowerShellStderrExtractsClixmlText(t *testing.T) {
	clixml := `#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">` +
		`<S S="Error">Cannot find any service with service name 'NoSuchSvc'._x000D__x000A_</S>` +
		`<S S="Error">At line:1 char:1</S></Objs>`

	got := normalizePowerShellStderr(clixml)

	if strings.Contains(got, "CLIXML") || strings.Contains(got, "<S ") {
		t.Fatalf("expected the CLIXML envelope to be stripped, got %q", got)
	}
	if !strings.Contains(got, "Cannot find any service with service name 'NoSuchSvc'.") {
		t.Fatalf("expected the error text to survive, got %q", got)
	}
	if !strings.Contains(got, "At line:1 char:1") {
		t.Fatalf("expected every text node to survive, got %q", got)
	}
}

func TestNormalizePowerShellStderrLeavesPlainTextAlone(t *testing.T) {
	plain := "command exited with code 7\r\n"

	if got := normalizePowerShellStderr(plain); got != plain {
		t.Fatalf("expected plain stderr to pass through unchanged, got %q", got)
	}
}

func TestLimitedBufferTruncatesAtCap(t *testing.T) {
	var buf bytes.Buffer
	writer := &limitedBuffer{buf: &buf, limit: 10}

	n, err := writer.Write([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Write returns the full length so io.Copy doesn't report a short write.
	if n != 16 {
		t.Fatalf("expected the writer to report 16 bytes written, got %d", n)
	}
	if buf.String() != "0123456789" {
		t.Fatalf("expected the buffer to stop at the cap, got %q", buf.String())
	}
	if !writer.truncated {
		t.Fatal("expected truncated to be set")
	}

	if _, err := writer.Write([]byte("more")); err != nil {
		t.Fatalf("unexpected error on a write past the cap: %v", err)
	}
	if buf.Len() != 10 {
		t.Fatalf("expected the buffer to stay at the cap, got %d bytes", buf.Len())
	}
}

func TestLimitedBufferKeepsOutputBelowCap(t *testing.T) {
	var buf bytes.Buffer
	writer := &limitedBuffer{buf: &buf, limit: 64}

	if _, err := writer.Write([]byte("reloaded nginx")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if writer.truncated {
		t.Fatal("expected truncated to stay false below the cap")
	}
	if buf.String() != "reloaded nginx" {
		t.Fatalf("unexpected buffer contents %q", buf.String())
	}
}

func TestNormalizePowerShellStderrKeepsUnparseableClixml(t *testing.T) {
	// The payload must have no <S> element, otherwise extraction succeeds and the fallback isn't hit.
	clixml := "#< CLIXML\n" + `<Objs><Obj RefId="0"><MS><I32 N="code">7</I32></MS></Obj></Objs>`

	got := normalizePowerShellStderr(clixml)

	if got != clixml {
		t.Fatalf("expected the raw payload to be returned unchanged, got %q", got)
	}
}

func TestNormalizePowerShellStderrDropsEmptyEnvelope(t *testing.T) {
	got := normalizePowerShellStderr("#< CLIXML\n<Objs><S></S><S>   </S></Objs>")

	if got != "" {
		t.Fatalf("expected an all-blank envelope to yield an empty string, got %q", got)
	}
}

func TestBuildCommandScriptDoesNotDuplicateProgressPreference(t *testing.T) {
	if strings.Contains(buildCommandScript("Write-Output ok", "nonce123"), "$ProgressPreference") {
		t.Fatal("expected the wrapper to leave $ProgressPreference to winrm.Powershell")
	}
}

func TestRunCommandRejectsAnOverlongEncodedCommand(t *testing.T) {
	// The length check runs before any connection, so no host is needed.
	_, err := RunCommand(context.Background(), Credentials{}, strings.Repeat("a", 10_000), time.Second)

	if err == nil {
		t.Fatal("expected an over-long command to be rejected")
	}
	if !strings.Contains(err.Error(), "too long to run on Windows once encoded") {
		t.Fatalf("expected the encoded-length error, got %v", err)
	}
}

func TestHandlerCommandCapAlwaysFitsInsideTheEncodedCeiling(t *testing.T) {
	// Mirrors maxWinrmCommandChars in the parent package.
	const handlerCommandCap = 2048

	encoded := winrm.Powershell(buildCommandScript(strings.Repeat("a", handlerCommandCap), "infisical-0123456789abcdef0123456789abcdef"))

	if len(encoded) > maxEncodedCommandChars {
		t.Fatalf("a command at the handler's %d-char cap encodes to %d, past the %d ceiling",
			handlerCommandCap, len(encoded), maxEncodedCommandChars)
	}
	t.Logf("handler cap %d chars -> %d encoded, ceiling %d", handlerCommandCap, len(encoded), maxEncodedCommandChars)
}

func TestResolveCommandOutcome(t *testing.T) {
	t.Run("uses the code the script stated", func(t *testing.T) {
		code, stderr := resolveCommandOutcome(5, true, "boom")
		if code != 5 || stderr != "boom" {
			t.Fatalf("expected the stated code to pass through, got code=%d stderr=%q", code, stderr)
		}
	})

	t.Run("an unstated outcome fails and never reports success", func(t *testing.T) {
		// The script carries no `exit`, so powershell.exe returns 0 for a failed command too. Taking
		// the process exit code here would report a failed command as a successful sync.
		code, stderr := resolveCommandOutcome(0, false, "")
		if code == 0 {
			t.Fatal("expected an unstated outcome to fail, not to inherit a zero exit code")
		}
		if !strings.Contains(stderr, "did not report a result") {
			t.Fatalf("expected the reason to be explained, got %q", stderr)
		}
	})

	t.Run("the explanation covers a parse error, not only exit", func(t *testing.T) {
		// PowerShell parses the whole script before running any of it, so a command that does not parse
		// produces no trailer either. Blaming exit alone would misname the commonest mistake.
		_, stderr := resolveCommandOutcome(0, false, "")
		if !strings.Contains(stderr, "did not parse") {
			t.Fatalf("expected parse failures to be covered, got %q", stderr)
		}
	})

	t.Run("leads with the explanation so the caller quotes it", func(t *testing.T) {
		_, stderr := resolveCommandOutcome(0, false, "some earlier noise")
		if !strings.HasPrefix(stderr, "The command did not report a result") {
			t.Fatalf("expected the explanation first, got %q", stderr)
		}
	})
}

func TestLimitedBufferKeepsTheTailPastTheCap(t *testing.T) {
	// A command that floods stdout and then fails must still be reported as failed: the trailer is the
	// last thing written, so it has to survive the head being capped.
	var buf bytes.Buffer
	writer := &limitedBuffer{buf: &buf, limit: 16}

	writer.Write([]byte(strings.Repeat("x", 4096)))
	writer.Write([]byte("\nnonce-abc:7\n"))

	if !writer.truncated {
		t.Fatal("expected the head to be marked truncated")
	}
	code, _, ok := takeCommandTrailer(string(writer.tail), "nonce-abc")
	if !ok || code != 7 {
		t.Fatalf("expected the trailer to survive truncation, got code=%d ok=%v", code, ok)
	}
	if len(writer.tail) > commandTailBytes {
		t.Fatalf("expected the tail to stay bounded, got %d bytes", len(writer.tail))
	}
}

func TestTakeCommandTrailerKeepsDeliberateBlankLines(t *testing.T) {
	// Only the separator the script writes is removed, so output that ends in blank lines keeps them.
	_, remaining, ok := takeCommandTrailer("line\n\n\n\nnonce-abc:0\n", "nonce-abc")
	if !ok {
		t.Fatal("expected the trailer to be found")
	}
	if remaining != "line\n\n\n" {
		t.Fatalf("expected only the separator to be stripped, got %q", remaining)
	}
}
