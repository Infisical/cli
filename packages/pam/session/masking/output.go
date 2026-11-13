package masking

import (
	"slices"
	"regexp"
	"sort"
)

// Matcher finds the spans to mask. *regexp.Regexp is one.
type Matcher interface {
	FindAllIndex(b []byte, n int) [][]int
}

var cardNumber = regexp.MustCompile(`\b(?:\d{4}[ -]?){3}\d{4}\b|\b3[47]\d{2}[ -]?\d{6}[ -]?\d{5}\b`)

type cardMatcher struct{}

// CardNumbers matches card-shaped numbers that pass the Luhn checksum, so other long digit runs stay visible.
func CardNumbers() Matcher {
	return cardMatcher{}
}

func (cardMatcher) FindAllIndex(b []byte, n int) [][]int {
	var valid [][]int
	for _, loc := range cardNumber.FindAllIndex(b, n) {
		if luhnValid(b[loc[0]:loc[1]]) {
			valid = append(valid, loc)
		}
	}
	return valid
}

func luhnValid(number []byte) bool {
	sum, digits := 0, 0
	for _, n := range slices.Backward(number) {
		if n < '0' || n > '9' {
			continue
		}
		digit := int(n - '0')
		if digits%2 == 1 {
			if digit *= 2; digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		digits++
	}
	return sum%10 == 0
}

type matcherMasker struct {
	matchers []Matcher
}

// NewMatcherMasker masks every span any matcher finds, merging overlaps, so the order of matchers doesn't matter.
func NewMatcherMasker(matchers []Matcher) Masker {
	return matcherMasker{matchers: matchers}
}

func (m matcherMasker) Mask(data []byte) []byte {
	var spans [][2]int
	for _, matcher := range m.matchers {
		for _, loc := range matcher.FindAllIndex(data, -1) {
			if loc[1] > loc[0] {
				spans = append(spans, [2]int{loc[0], loc[1]})
			}
		}
	}
	if len(spans) == 0 {
		return data
	}
	sort.Slice(spans, func(a, b int) bool { return spans[a][0] < spans[b][0] })

	out := make([]byte, 0, len(data))
	last := 0
	for i := 0; i < len(spans); {
		start, end := spans[i][0], spans[i][1]
		for i++; i < len(spans) && spans[i][0] <= end; i++ {
			end = max(end, spans[i][1])
		}
		out = append(out, data[last:start]...)
		out = append(out, Placeholder...)
		last = end
	}
	return append(out, data[last:]...)
}

func (m matcherMasker) MaskString(s string) string {
	return string(m.Mask([]byte(s)))
}
