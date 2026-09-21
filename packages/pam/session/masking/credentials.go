package masking

import (
	"sort"
	"strings"
)

// A credential shorter than this would blank out ordinary words wherever they appear.
const minCredentialLength = 6

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
			for _, line := range strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == '\r' }) {
				add(strings.TrimSpace(line))
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
