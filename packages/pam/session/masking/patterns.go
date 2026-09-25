package masking

import "regexp"

type patternMasker struct {
	patterns []*regexp.Regexp
}

func (m *patternMasker) Mask(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	result := data
	for _, pattern := range m.patterns {
		result = pattern.ReplaceAll(result, []byte(Placeholder))
	}
	return result
}

func (m *patternMasker) MaskString(s string) string {
	if s == "" {
		return s
	}
	result := s
	for _, pattern := range m.patterns {
		result = pattern.ReplaceAllString(result, Placeholder)
	}
	return result
}
