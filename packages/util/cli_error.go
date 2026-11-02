package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/google/uuid"
	"gopkg.in/yaml.v2"
)

// NextStep is a command that resolves a CLIError, with why you would run it.
type NextStep struct {
	Purpose string // "To see the environments in this project"
	Command string // complete and runnable; build values with SuggestedValue
}

// CLIError is an error a person or an agent can act on: what went wrong, then the commands that fix
// it. See the Errors section of CLI.md.
type CLIError struct {
	Code    string
	Message string
	Next    []NextStep
	Cause   error
}

func (e *CLIError) Error() string { return e.Message }

func (e *CLIError) Unwrap() error { return e.Cause }

var (
	suggestableSlug      = regexp.MustCompile(`^[a-z0-9]+(?:[_-][a-z0-9]+)*$`)
	suggestableSecretKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
	suggestablePath      = regexp.MustCompile(`^/(?:[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*)?$`)
	// Scheme, host, optional port and plain path segments only: no user info, query or fragment, and
	// nothing a shell would read as an operator (; & | $ ...).
	suggestableDomain = regexp.MustCompile(`^https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~-]+)*/?$`)
	// A credential pasted into a flag the CLI didn't expect still never reaches a suggestion.
	credentialFlagValue = regexp.MustCompile(`(--(?:token|client-secret|client-id|password|passphrase)[= ])\S+`)
	credentialLooking   = regexp.MustCompile(`\b(?:st\.[A-Za-z0-9._-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+)`)
	// Third-party token formats that would otherwise pass as a secret name or slug. Each is matched by
	// its prefix and length, so names that only start the same way (npm_config_registry) still print.
	knownTokenFormat = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|[rs]k_(?:live|test)_[A-Za-z0-9]{10,}|xox[abprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36}|(?:AKIA|ASIA)[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,})\b`)
)

func isKnownToken(match string) bool {
	return !strings.HasPrefix(match, "sk-") || strings.ToLower(match) != match
}

func containsKnownToken(value string) bool {
	for _, match := range knownTokenFormat.FindAllString(value, -1) {
		if isKnownToken(match) {
			return true
		}
	}
	return false
}

const maxSuggestedValueLength = 64

// SuggestedValue returns value when it is safe to put in a command someone may paste: a UUID, a
// slug, a secret key name or a folder path. Anything else (spaces, quotes, $, newlines, long
// strings) becomes <placeholder>. Use it for identifiers only, never for a credential or a secret
// value.
func SuggestedValue(value, placeholder string) string {
	if isSuggestable(value) {
		return value
	}
	return "<" + placeholder + ">"
}

func isSuggestable(value string) bool {
	if parsed, err := uuid.Parse(value); err == nil {
		return parsed.String() == strings.ToLower(value)
	}
	if value == "" || len(value) > maxSuggestedValueLength || containsKnownToken(value) {
		return false
	}
	return suggestableSlug.MatchString(value) || suggestableSecretKey.MatchString(value) || suggestablePath.MatchString(value)
}

// SuggestedDomain returns domain when it is a plain http(s) URL, so a suggested command reaches the
// same instance; otherwise <domain>.
func SuggestedDomain(domain string) string {
	if !suggestableDomain.MatchString(domain) {
		return "<domain>"
	}
	return domain
}

// RedactCredentials hides anything credential-shaped in text the CLI prints. Messages need it as
// much as suggestions: some repeat what the backend said or what a project is named.
func RedactCredentials(text string) string {
	text = credentialFlagValue.ReplaceAllString(text, "$1<redacted>")
	text = credentialLooking.ReplaceAllString(text, "<redacted>")
	return knownTokenFormat.ReplaceAllStringFunc(text, func(match string) string {
		if isKnownToken(match) {
			return "<redacted>"
		}
		return match
	})
}

type cliErrorBody struct {
	Code       string   `json:"code" yaml:"code"`
	Message    string   `json:"message" yaml:"message"`
	Next       []string `json:"next" yaml:"next"`
	StatusCode int      `json:"statusCode,omitempty" yaml:"statusCode,omitempty"`
	RequestID  string   `json:"requestId,omitempty" yaml:"requestId,omitempty"`
}

// WriteCLIError writes err in the CLI.md format: two sentences for people, or {"error": {...}} for
// -o json and -o yaml.
func WriteCLIError(w io.Writer, err *CLIError, outputFormat string) {
	switch outputFormat {
	case OUTPUT_FORMAT_JSON, OUTPUT_FORMAT_YAML:
		body := cliErrorBody{Code: err.Code, Message: RedactCredentials(SanitizeDisplay(err.Message)), Next: []string{}}
		for _, step := range err.Next {
			body.Next = append(body.Next, RedactCredentials(step.Command))
		}
		var apiErr *api.APIError
		if errors.As(err.Cause, &apiErr) {
			body.StatusCode, body.RequestID = apiErr.StatusCode, apiErr.ReqId
		}
		wrapped := map[string]cliErrorBody{"error": body}
		if outputFormat == OUTPUT_FORMAT_JSON {
			// Placeholders like <value> stay readable instead of becoming <value>.
			encoder := json.NewEncoder(w)
			encoder.SetEscapeHTML(false)
			_ = encoder.Encode(wrapped)
		} else {
			out, _ := yaml.Marshal(wrapped)
			_, _ = w.Write(out)
		}
	default:
		fmt.Fprintln(w, RedactCredentials(SanitizeDisplay(err.Message)))
		for _, step := range err.Next {
			fmt.Fprintf(w, "%s, run: %s\n", RedactCredentials(SanitizeDisplay(step.Purpose)), RedactCredentials(step.Command))
		}
	}
}
