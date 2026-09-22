package masking

import (
	"regexp"

	"github.com/rs/zerolog/log"
)

// Fixed-width so a redaction cannot leak the length of what it replaced.
const Placeholder = "[MASKED]"

// Masker must be safe for concurrent use: one masker serves every connection in a session.
type Masker interface {
	Mask(data []byte) []byte
	MaskString(s string) string
}

type nopMasker struct{}

func (nopMasker) Mask(data []byte) []byte    { return data }
func (nopMasker) MaskString(s string) string { return s }

func Nop() Masker { return nopMasker{} }

type chainMasker struct {
	maskers []Masker
}

func (m *chainMasker) Mask(data []byte) []byte {
	result := data
	for _, masker := range m.maskers {
		result = masker.Mask(result)
	}
	return result
}

func (m *chainMasker) MaskString(s string) string {
	result := s
	for _, masker := range m.maskers {
		result = masker.MaskString(result)
	}
	return result
}

// Custom patterns run first, so a session with detection off masks exactly as it did before
// detection existed. The account's own credentials and the engine are both gated on detection.
func New(customPatterns []*regexp.Regexp, builtInDetection bool, credentialValues []string, sessionID string) Masker {
	var maskers []Masker

	if len(customPatterns) > 0 {
		maskers = append(maskers, &patternMasker{patterns: customPatterns})
	}

	if builtInDetection {
		// Exact, so it runs before detection and catches what detection structurally cannot.
		if literal := newCredentialMasker(credentialValues); literal != nil {
			maskers = append(maskers, literal)
		}

		d, err := sharedDetector()
		if err != nil {
			// A session that cannot start protects nobody, so fall back rather than fail.
			log.Warn().
				Err(err).
				Str("sessionId", sessionID).
				Msg("Failed to build built-in secret detection engine, falling back to custom masking patterns only")
		} else {
			maskers = append(maskers, &detectionMasker{detector: d})
		}
	}

	switch len(maskers) {
	case 0:
		return Nop()
	case 1:
		return maskers[0]
	default:
		return &chainMasker{maskers: maskers}
	}
}
