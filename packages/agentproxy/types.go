package agentproxy

import (
	"errors"

	"github.com/Infisical/infisical-merge/packages/api"
)

// isAuthError reports whether the backend refused us rather than failed. Callers fail closed on it: a
// revoked session or a lost grant must stop brokering, not fall back to the last known credentials.
func isAuthError(err error) bool {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 401 || apiErr.StatusCode == 403 || apiErr.StatusCode == 404
	}
	return false
}

// dynamicCredentialRef names the dynamic secret a credential came from. Names only, for the activity log:
// the value itself is resolved by the backend and lives on resolvedCredential.
type dynamicCredentialRef struct {
	secretName string
	field      string
}

type resolvedCredential struct {
	secretKey     string
	role          string
	headerName    string
	headerPrefix  string
	headerPurpose string
	placeholder   string
	surfaces      []string
	value         string
	dynamic       *dynamicCredentialRef
}

type resolvedService struct {
	id   string
	name string
	// Match order among services whose host patterns overlap. Lower wins.
	priority     int
	hostPatterns []hostPattern
	isEnabled    bool
	credentials  []resolvedCredential
}
