package masking

import (
	"regexp"
	"strings"
	"testing"
)

// Assembled at runtime rather than written as literals: a complete credential-shaped string in
// source trips GitHub push protection and blocks the push. The names avoid key/secret/token too,
// or generic-api-key matches the assignment itself. The detector sees the joined value, so
// coverage is unchanged.
var (
	awsIDFixture    = "AKIA" + "4X7ZQJ2NPLMVBK3D"
	awsValueFixture = "hT9xQv2LpR8mZk4YbN6w" + "Ec1JsA7dFg3UnV5oXi0P"
	awsIDLine       = "aws_access_key_id = " + awsIDFixture
	ghpFixture      = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	jwtFixture      = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pwFixture       = "hunter2" + "CorrectHorseBattery"
)

// Built at runtime for the same reason as the fixtures above: a literal PEM block in source is a
// private-key hit for both our own scanner and GitHub push protection.
func pemFixture() string {
	banner := func(edge string) string { return "-----" + edge + " OPENSSH PRIVATE " + "KEY-----" }
	return strings.Join([]string{
		banner("BEGIN"),
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gt",
		"cnNhAAAAAwEAAQAAAYEAy8kQvN3mK9Zt7Lp2RwXhJ4dF6gYcQnB1sVeTmAoPdKjHrUxN",
		banner("END"),
	}, "\n")
}

func mustCompile(t *testing.T, patterns ...string) []*regexp.Regexp {
	t.Helper()
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		compiled = append(compiled, regexp.MustCompile(p))
	}
	return compiled
}

func TestNewSelectsMasker(t *testing.T) {
	if _, ok := New(nil, false, nil, "s").(nopMasker); !ok {
		t.Error("no patterns and no detection should produce a nop masker")
	}
	if _, ok := New(mustCompile(t, `secret`), false, nil, "s").(*patternMasker); !ok {
		t.Error("patterns alone should produce a regex masker")
	}
	if _, ok := New(nil, true, nil, "s").(*detectionMasker); !ok {
		t.Error("detection alone should produce a detect masker")
	}
	if _, ok := New(mustCompile(t, `secret`), true, nil, "s").(*chainMasker); !ok {
		t.Error("patterns plus detection should produce a chain")
	}
}

func TestCustomPatternsUnaffectedByDetection(t *testing.T) {
	patterns := mustCompile(t, `password\s*=\s*\S+`, `secret_key`)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"masks password pattern", "SET password = hunter2", "SET [MASKED]"},
		{"masks secret_key", "export secret_key=abc123", "export [MASKED]=abc123"},
		{"masks multiple occurrences", "password=foo and password=bar", "[MASKED] and [MASKED]"},
		{"no match leaves input unchanged", "SELECT * FROM users", "SELECT * FROM users"},
		{"empty input", "", ""},
	}

	masker := New(patterns, false, nil, "s")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := masker.MaskString(tt.input); got != tt.expected {
				t.Errorf("MaskString(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}

	// The minimum-length floor applies to built-in findings only, never to a custom pattern.
	t.Run("short custom match is not floored", func(t *testing.T) {
		short := New(mustCompile(t, `abc`), true, nil, "s")
		if got, want := short.MaskString("id: abc"), "id: [MASKED]"; got != want {
			t.Errorf("MaskString = %q, want %q", got, want)
		}
	})
}

func TestBuiltInDetectionMasksCredentials(t *testing.T) {
	masker := New(nil, true, nil, "s")

	tests := []struct {
		name  string
		input string
		leak  string
	}{
		{"aws access key", awsIDLine, awsIDFixture},
		{"aws secret key", "export AWS_SECRET_ACCESS_KEY=" + awsValueFixture, awsValueFixture},
		{"github pat", "git remote set-url origin https://" + ghpFixture + "@github.com/o/r", ghpFixture},
		{"jwt", "curl -H 'Authorization: Bearer " + jwtFixture + "'", jwtFixture},
		{"pgpassword env", "export PGPASSWORD=" + pwFixture, pwFixture},
		// Unbranded, caught by the keyword before it rather than by its shape.
		{"unbranded token with context", "my_internal_token = Zk9wZjR4TmF0S2hHc1BtVzdaeVh1QVBxTHc", "Zk9wZjR4TmF0S2hHc1BtVzdaeVh1QVBxTHc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := masker.MaskString(tt.input)
			if strings.Contains(got, tt.leak) {
				t.Errorf("secret survived masking\n input:  %s\n output: %s\n leaked: %s", tt.input, got, tt.leak)
			}
			if !strings.Contains(got, Placeholder) {
				t.Errorf("expected a redaction in %q", got)
			}
		})
	}
}

// A wrongly-masked recording is silent and unrecoverable, so this is the test that catches a rule
// or threshold regression.
func TestBuiltInDetectionLeavesOrdinaryOutputIntact(t *testing.T) {
	masker := New(nil, true, nil, "s")

	corpus := []struct {
		name  string
		input string
	}{
		{"ls -l", "drwxr-xr-x  2 root root  4096 Sep 16 09:31 bin"},
		{"ls total", "total 48"},
		{"ps aux", "root       1284  0.0  0.1 107988  3252 ?        Ss   09:31   0:00 /usr/sbin/sshd -D"},
		{"git log", "commit 9f8c2b1e4d7a0c3f6b5e8d1a2c4f7b0e3d6a9c2f"},
		{"sql select", "SELECT id, name FROM users WHERE tenant_id = 42 ORDER BY created_at DESC;"},
		{"uuid column", "3f2504e0-4f89-11d3-9a0c-0305e82c3301 | widget       | 2026-09-16"},
		{"sha256 digest", "sha256:1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890"},
		{"md5sum", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4  /etc/hosts"},
		// Thinnest margin against the entropy threshold of any ordinary output measured (4.41).
		{"long path", "/usr/lib/x86_64-linux-gnu/libcrypto.so.3.0.2"},
		{"long path 2", "/var/lib/postgresql/16/main/pg_wal/000000010000000000000042"},
		{"prose", "the quick brown fox jumps over the lazy dog and then runs away"},
		{"psql banner", "psql (16.4 (Ubuntu 16.4-0ubuntu0.24.04.2))"},
		{"env listing", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	}

	for _, tt := range corpus {
		t.Run(tt.name, func(t *testing.T) {
			if got := masker.MaskString(tt.input); got != tt.input {
				t.Errorf("ordinary output was masked\n input:  %s\n output: %s", tt.input, got)
			}
		})
	}
}

// Detection may redact more, but must never change or undo what custom patterns already caught.
func TestDetectionIsAdditive(t *testing.T) {
	patterns := mustCompile(t, `password\s*=\s*\S+`, `internal-vault://\S+`)
	customOnly := New(patterns, false, nil, "s")
	both := New(patterns, true, nil, "s")

	inputs := []string{
		"SET password = hunter2",
		"fetch internal-vault://prod/db",
		"SELECT id, name FROM users WHERE tenant_id = 42;",
		"drwxr-xr-x  2 root root  4096 Sep 16 09:31 bin",
		"password = x and " + awsIDLine,
	}

	for _, input := range inputs {
		custom := customOnly.MaskString(input)
		chained := both.MaskString(input)

		if strings.Count(chained, Placeholder) < strings.Count(custom, Placeholder) {
			t.Errorf("detection removed a custom redaction\n input:      %s\n custom:     %s\n with detect: %s", input, custom, chained)
		}
		for _, segment := range strings.Split(custom, Placeholder) {
			if segment == "" {
				continue
			}
			if !strings.Contains(chained, segment) && !strings.Contains(chained, Placeholder) {
				t.Errorf("detection altered untouched text\n custom:      %s\n with detect: %s", custom, chained)
			}
		}
	}
}

func TestMaskBytesMatchesMaskString(t *testing.T) {
	masker := New(mustCompile(t, `password\s*=\s*\S+`), true, nil, "s")
	inputs := []string{
		"",
		"password = hunter2",
		"nothing to see here",
		"export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	for _, input := range inputs {
		if got, want := string(masker.Mask([]byte(input))), masker.MaskString(input); got != want {
			t.Errorf("Mask(%q) = %q, MaskString = %q", input, got, want)
		}
	}
}

func TestDetectMaskerIsConcurrencySafe(t *testing.T) {
	masker := New(nil, true, nil, "s")
	input := awsIDLine
	want := masker.MaskString(input)

	done := make(chan string, 16)
	for i := 0; i < 16; i++ {
		go func() { done <- masker.MaskString(input) }()
	}
	for i := 0; i < 16; i++ {
		if got := <-done; got != want {
			t.Fatalf("concurrent MaskString = %q, want %q", got, want)
		}
	}
}

// The case detection structurally cannot reach: a human-chosen password with no recognisable
// shape, too short to separate from a file path by entropy.
func TestAccountCredentialsAreRedacted(t *testing.T) {
	password := "k5.~A76J|5}~Mmvj3~m.&X3v"
	masker := New(nil, true, []string{password, pwFixture}, "s")

	for _, input := range []string{
		password,
		"sheen@host:~$ " + password,
		"mysql -u root -p" + password,
		"echo " + password + " > /tmp/x",
	} {
		got := masker.MaskString(input)
		if strings.Contains(got, password) {
			t.Errorf("credential survived masking\n input:  %s\n output: %s", input, got)
		}
	}
}

func TestCredentialRedactionIgnoresShortAndDuplicateValues(t *testing.T) {
	// A short credential would blank out ordinary words wherever they appeared.
	if newCredentialMasker([]string{"root", "ca", ""}) != nil {
		t.Error("expected no masker for values below the length floor")
	}

	m := newCredentialMasker([]string{"longpassword", "longpassword", "short"})
	if m == nil || len(m.secrets) != 1 {
		t.Fatalf("expected one deduped secret, got %#v", m)
	}
}

// A credential containing another must be redacted first, or the shorter one rewrites the text
// the longer one needs to match.
func TestLongestCredentialRedactedFirst(t *testing.T) {
	m := newCredentialMasker([]string{"passphrase", "passphrase-and-more"})
	got := m.MaskString("value=passphrase-and-more")
	if got != "value="+Placeholder {
		t.Errorf("MaskString = %q, want %q", got, "value="+Placeholder)
	}
}

func TestCredentialsNotRedactedWhenDetectionOff(t *testing.T) {
	password := "k5.~A76J|5}~Mmvj3~m.&X3v"
	if got := New(nil, false, []string{password}, "s").MaskString(password); got != password {
		t.Errorf("detection is off, so nothing should change; got %q", got)
	}
}

// The logger masks one rendered terminal line at a time, so a key registered only as a whole blob
// never matches. `cat id_rsa` is the case this covers. Format constants (banners, the PEM header
// line, the padding trailer) are deliberately skipped: they are identical across every key of a
// type, so registering them would redact foreign keys whose bodies still leak.
func TestMultiLineCredentialIsMaskedPerLine(t *testing.T) {
	key := pemFixture()
	masker := New(nil, true, []string{key}, "s")

	body := strings.Split(key, "\n")
	unique := body[2 : len(body)-1] // skip BEGIN, the header line, and END
	if len(unique) == 0 {
		t.Fatal("fixture has no unique body lines to assert on")
	}
	for _, line := range unique {
		if got := masker.MaskString(line); got == line {
			t.Errorf("unique key line survived masking: %s", line)
		}
	}

	// The whole blob still masks when it arrives in one fragment.
	if got := masker.MaskString(key); strings.Contains(got, unique[0]) {
		t.Error("whole key blob survived masking")
	}
}

func TestCredentialLinesRespectTheLengthFloor(t *testing.T) {
	// Blank and short lines must not become masks, or they would blank out ordinary output.
	// A whitespace-only credential must register nothing: masking it would replace that run of
	// whitespace throughout the recording.
	if newCredentialMasker([]string{"   \n\n  ", ""}) != nil {
		t.Error("registered a blank credential")
	}

	m := newCredentialMasker([]string{"longenoughvalue\n\nabc\n   \nanotherlongvalue"})
	for _, secret := range m.secrets {
		if len([]rune(secret)) < minCredentialLength {
			t.Errorf("registered a secret below the floor: %q", secret)
		}
	}
	if got := m.MaskString("abc and    spaces"); got != "abc and    spaces" {
		t.Errorf("short line was masked: %q", got)
	}
}

// Session content is untrusted input, so the inline allow marker must not suppress masking —
// otherwise anyone can exempt a secret by appending it to the command.
func TestInlineAllowMarkerCannotSuppressMasking(t *testing.T) {
	masker := New(nil, true, nil, "s")

	for _, suffix := range []string{"", " # gitleaks:allow", " //gitleaks:allow", " -- gitleaks:allow"} {
		input := awsIDLine + suffix
		if got := masker.MaskString(input); strings.Contains(got, awsIDFixture) {
			t.Errorf("secret survived with suffix %q: %s", suffix, got)
		}
	}
}

// Masking only a key's banners is worse than masking nothing: the body still leaks while the
// recording reads as handled. Banners are identical across keys, so they must not be registered.
func TestPemBoilerplateIsNotRegistered(t *testing.T) {
	accountKey := pemFixture()
	otherKey := strings.Join([]string{
		"-----BEGIN OPENSSH PRIVATE " + "KEY-----",
		"Proc-Type: 4,ENCRYPTED",
		"BBBBotherKeyBodyLineCompletelyDifferentFromOurs",
		"-----END OPENSSH PRIVATE " + "KEY-----",
	}, "\n")

	masker := New(nil, true, []string{accountKey}, "s")
	for _, line := range strings.Split(otherKey, "\n") {
		if got := masker.MaskString(line); got != line {
			t.Errorf("another key's line was masked, implying cover we do not have: %q -> %q", line, got)
		}
	}

	// The account's own unique body lines are still masked; only format constants are skipped.
	own := strings.Split(accountKey, "\n")
	for _, line := range own[2 : len(own)-1] {
		if got := masker.MaskString(line); got == line {
			t.Errorf("account key body survived masking: %s", line)
		}
	}
}

// The PEM rules must not reach a credential that is not a PEM block, or a multi-line value whose
// lines happen to look like headers would lose its per-line cover.
func TestNonPemMultiLineCredentialKeepsEveryLine(t *testing.T) {
	value := "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456\nX-Other: alsoacredentialline"
	masker := New(nil, true, []string{value}, "s")

	for _, line := range strings.Split(value, "\n") {
		if got := masker.MaskString(line); got == line {
			t.Errorf("line of a non-PEM credential survived masking: %s", line)
		}
	}
}
