package masking

import (
	"sort"
	"strings"
	"sync"

	"github.com/Infisical/infisical-merge/detect"
	"github.com/Infisical/infisical-merge/detect/config"
)

var (
	detectorOnce sync.Once
	detector     *detect.Detector
	detectorErr  error
)

// Built once per process: compiling every rule and the keyword trie is far too expensive to
// repeat per session, and scanning only reads that state.
func sharedDetector() (*detect.Detector, error) {
	detectorOnce.Do(func() {
		var cfg *config.Config
		if cfg, detectorErr = config.Default(); detectorErr != nil {
			return
		}
		relaxRequiredComponents(cfg)

		detector = detect.NewDetector(cfg)
		// A session is untrusted input, unlike a repository someone owns: honouring the inline
		// allow marker would let anyone suppress masking by appending it to a command.
		detector.IgnoreGitleaksAllow = true
	})

	return detector, detectorErr
}

// relaxRequiredComponents makes every multi-part rule's components optional.
//
// Betterleaks introduces new rules that only report some secret if something
// else is leaked up to 5 lines away from the original leak.
// For example:
// It only triggers an AWS_ACCESS_KEY_ID it it finds a AWS_SECRET_KEY_ID next
// to it (5 lines away) to it, otherwise it does not report it as a leaked secret.
// But because this is used for redacting secrets, It makes more sense to be more
// restrictive.
func relaxRequiredComponents(cfg *config.Config) {
	for id, rule := range cfg.Rules {
		if len(rule.Components) == 0 {
			continue
		}
		for _, component := range rule.Components {
			component.Optional = true
		}
		cfg.Rules[id] = rule
	}
}

// Below this a finding is likelier a capture-group artifact than a credential, and replacing it
// would blank out every occurrence of a common token on the line.
const minSecretLength = 8

type detectionMasker struct {
	detector *detect.Detector
}

func (m *detectionMasker) MaskString(s string) string {
	if s == "" {
		return s
	}

	findings := m.detector.DetectString(s)
	if len(findings) == 0 {
		return s
	}

	// Longest first: each replacement rewrites the string, so a short finding applied early can
	// destroy the text a longer overlapping finding needs, leaving the rest of it in the recording.
	sort.SliceStable(findings, func(i, j int) bool {
		return len(findings[i].Secret) > len(findings[j].Secret)
	})

	// Columns describe the match, not the secret, and diverge when a rule sets secretGroup, so
	// there are no usable offsets to cut on.
	result := s
	for _, finding := range findings {
		if len(finding.Secret) < minSecretLength {
			continue
		}
		result = strings.ReplaceAll(result, finding.Secret, Placeholder)
	}
	return result
}

func (m *detectionMasker) Mask(data []byte) []byte {
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
