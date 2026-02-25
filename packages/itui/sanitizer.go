package itui

import (
	"fmt"
	"regexp"
	"strings"
)

// valuePatterns matches common patterns where users provide secret values
// Examples: "set X to VALUE", "set X=VALUE", "set X as VALUE", "with value VALUE"
var valuePatterns = []*regexp.Regexp{
	// "set KEY to VALUE" or "set KEY to VALUE in env"
	regexp.MustCompile(`(?i)\bto\s+(.+?)(?:\s+(?:in|on|for|--)\s|\s*$)`),
	// "set KEY=VALUE"
	regexp.MustCompile(`=(\S+)`),
	// "set KEY as VALUE"
	regexp.MustCompile(`(?i)\bas\s+(.+?)(?:\s+(?:in|on|for|--)\s|\s*$)`),
	// "with value VALUE"
	regexp.MustCompile(`(?i)with\s+value\s+(.+?)(?:\s+(?:in|on|for|--)\s|\s*$)`),
}

// SanitizePrompt extracts potential secret values from a user prompt,
// replaces them with placeholders, and returns a cache for later hydration.
// This ensures secret values never reach the AI API.
func SanitizePrompt(input string, knownSecretValues []string) (sanitized string, cache map[string]string) {
	cache = make(map[string]string)
	sanitized = input
	counter := 1

	// First: redact any known secret values found in the prompt
	for _, val := range knownSecretValues {
		if val == "" {
			continue
		}
		if strings.Contains(sanitized, val) {
			placeholder := fmt.Sprintf("[VALUE_%d]", counter)
			cache[placeholder] = val
			sanitized = strings.Replace(sanitized, val, placeholder, 1)
			counter++
		}
	}

	// Second: detect value patterns in set/update/change commands
	// Only apply if the prompt looks like a write operation
	lowerInput := strings.ToLower(sanitized)
	isWriteOp := strings.Contains(lowerInput, "set ") ||
		strings.Contains(lowerInput, "update ") ||
		strings.Contains(lowerInput, "change ") ||
		strings.Contains(lowerInput, "create ")

	if isWriteOp {
		// Look for "to VALUE" pattern (most common)
		toPattern := regexp.MustCompile(`(?i)\bto\s+(\S+(?:\S*://\S+|\S+))`)
		if matches := toPattern.FindStringSubmatchIndex(sanitized); matches != nil {
			valStart := matches[2]
			valEnd := matches[3]
			val := sanitized[valStart:valEnd]

			// Don't redact environment names or common words
			if !isCommonWord(val) && !alreadyPlaceholder(val) {
				placeholder := fmt.Sprintf("[VALUE_%d]", counter)
				cache[placeholder] = val
				sanitized = sanitized[:valStart] + placeholder + sanitized[valEnd:]
				counter++
			}
		}

		// Look for KEY=VALUE pattern
		eqPattern := regexp.MustCompile(`(\w+)=(\S+)`)
		if matches := eqPattern.FindStringSubmatchIndex(sanitized); matches != nil {
			valStart := matches[4]
			valEnd := matches[5]
			val := sanitized[valStart:valEnd]

			if !alreadyPlaceholder(val) {
				placeholder := fmt.Sprintf("[VALUE_%d]", counter)
				cache[placeholder] = val
				sanitized = sanitized[:valStart] + placeholder + sanitized[valEnd:]
				counter++
			}
		}
	}

	return sanitized, cache
}

// HydrateCommand replaces [VALUE_N] placeholders in an AI-generated command
// with the real cached values.
func HydrateCommand(command string, cache map[string]string) string {
	result := command
	for placeholder, value := range cache {
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

// isCommonWord returns true if the value is a common word that shouldn't be redacted
func isCommonWord(s string) bool {
	common := map[string]bool{
		"dev": true, "staging": true, "prod": true, "production": true,
		"test": true, "development": true, "local": true,
		"shared": true, "personal": true,
		"json": true, "dotenv": true, "yaml": true, "csv": true,
		"true": true, "false": true,
	}
	return common[strings.ToLower(s)]
}

// alreadyPlaceholder returns true if the string is already a [VALUE_N] placeholder
func alreadyPlaceholder(s string) bool {
	return strings.HasPrefix(s, "[VALUE_") && strings.HasSuffix(s, "]")
}
