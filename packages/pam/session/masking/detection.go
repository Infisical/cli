package masking

import (
	_ "embed"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/viper"

	"github.com/Infisical/infisical-merge/detect"
	"github.com/Infisical/infisical-merge/detect/config"
)

//go:embed pam-rules.toml
var pamRules string

var (
	detectorOnce sync.Once
	detector     *detect.Detector
	detectorErr  error
)

// Built once per process: compiling every rule and the keyword trie is far too expensive to
// repeat per session, and scanning only reads that state.
func sharedDetector() (*detect.Detector, error) {
	detectorOnce.Do(func() {
		// Isolated instance: detect uses the viper singleton, which `infisical scan` also writes.
		v := viper.New()
		v.SetConfigType("toml")

		// Both documents are [[rules]] arrays, so concatenating appends ours to the defaults.
		if detectorErr = v.ReadConfig(strings.NewReader(config.DefaultConfig + "\n" + pamRules)); detectorErr != nil {
			return
		}

		var vc config.ViperConfig
		if detectorErr = v.Unmarshal(&vc); detectorErr != nil {
			return
		}

		var cfg config.Config
		if cfg, detectorErr = vc.Translate(); detectorErr != nil {
			return
		}

		detector = detect.NewDetector(cfg)
	})

	return detector, detectorErr
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
