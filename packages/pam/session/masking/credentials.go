package masking

import "strings"

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
	for _, v := range values {
		if len([]rune(v)) < minCredentialLength {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		secrets = append(secrets, v)
	}
	if len(secrets) == 0 {
		return nil
	}
	// Longest first: a credential containing another (a passphrase inside a key block) must be
	// redacted before the shorter one rewrites the text around it.
	for i := 1; i < len(secrets); i++ {
		for j := i; j > 0 && len(secrets[j]) > len(secrets[j-1]); j-- {
			secrets[j], secrets[j-1] = secrets[j-1], secrets[j]
		}
	}
	return &credentialMasker{secrets: secrets}
}
