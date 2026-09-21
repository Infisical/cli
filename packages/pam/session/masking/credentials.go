package masking

import (
	"regexp"
	"sort"
	"strings"
)

// Only lines unique to this credential may be registered. A line shared with every other key of
// the same type would redact foreign keys whose bodies still leak, and masking the parts that
// carry no secret is worse than masking nothing: it reads as handled.
var (
	pemBegin = regexp.MustCompile(`^-{5}BEGIN[ A-Za-z0-9]*-{5}$`)
	// The END banner and RFC 1421 headers (Proc-Type, DEK-Info) are format constants too.
	pemBoilerplate = regexp.MustCompile(`^(?:-{5}END[ A-Za-z0-9]*-{5}|[A-Za-z-]+: .*)$`)
)

// A credential shorter than this would blank out ordinary words wherever they appear.
const minCredentialLength = 6

// A line pulled out of a multi-line credential has to clear a much higher bar than a whole
// credential: PEM bodies wrap at ~70 characters, so anything materially shorter is a format
// constant (a header, a trailer, padding) shared with every other key of that type.
const minCredentialLineLength = 32

// credentialMasker redacts the account's own credential values.
type credentialMasker struct {
	secrets []string
}

func (m *credentialMasker) MaskString(s string) string {
	if s == "" {
		return s
	}
	result := s
	for _, secret := range m.secrets {
		result = strings.ReplaceAll(result, secret, Placeholder)
	}
	return result
}

func (m *credentialMasker) Mask(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	original := string(data)
	masked := m.MaskString(original)
	if masked == original {
		return data
	}
	return []byte(masked)
}

// newCredentialMasker returns nil when nothing is worth redacting, so callers can skip the stage.
func newCredentialMasker(values []string) *credentialMasker {
	seen := make(map[string]struct{}, len(values))
	var secrets []string

	add := func(v string) {
		// A blank or whitespace-only credential is a misconfiguration, and registering it would
		// replace that run of whitespace throughout the recording.
		if strings.TrimSpace(v) == "" {
			return
		}
		if len([]rune(v)) < minCredentialLength {
			return
		}
		if _, dup := seen[v]; dup {
			return
		}
		seen[v] = struct{}{}
		secrets = append(secrets, v)
	}

	for _, v := range values {
		add(v)
		// A private key reaches the logger one rendered line at a time, so the whole blob never
		// matches. Register its lines too, which needs no buffering.
		if strings.ContainsAny(v, "\r\n") {
			lines := strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == '\r' })
			isPem := false
			for _, line := range lines {
				if pemBegin.MatchString(strings.TrimSpace(line)) {
					isPem = true
					break
				}
			}

			atBodyStart := false
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if !isPem {
					// Nothing structural to skip, so the ordinary floor applies.
					add(trimmed)
					continue
				}
				if pemBegin.MatchString(trimmed) {
					atBodyStart = true
					continue
				}
				if pemBoilerplate.MatchString(trimmed) {
					continue
				}
				if atBodyStart {
					// The first body line encodes the PEM header rather than key material, so it
					// is identical across every key of this type.
					atBodyStart = false
					continue
				}
				if len([]rune(trimmed)) >= minCredentialLineLength {
					add(trimmed)
				}
			}
		}
	}
	if len(secrets) == 0 {
		return nil
	}
	// Longest first: a credential containing another (a passphrase inside a key block) must be
	// redacted before the shorter one rewrites the text around it.
	sort.SliceStable(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	return &credentialMasker{secrets: secrets}
}
