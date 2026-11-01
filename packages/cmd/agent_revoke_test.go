package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With no dynamic secret leases, RevokeCredentials used to wait for lease results that never came, time out
// after five minutes and return before revoking the access token.
func TestRevokeCredentialsWithoutLeasesRevokesTokenPromptly(t *testing.T) {
	var revokeCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v1/auth/token/revoke") {
			revokeCalls.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer server.Close()
	withMockInfisicalURL(t, server.URL+"/api")

	sinkPath := filepath.Join(t.TempDir(), "access-token")
	require.NoError(t, os.WriteFile(sinkPath, []byte("test-token"), 0o600))

	tm := &AgentManager{
		accessToken:         "test-token",
		filePaths:           []Sink{{Type: "file", Config: SinkDetails{Path: sinkPath}}},
		dynamicSecretLeases: NewDynamicSecretLeaseManager(nil, nil),
	}

	done := make(chan error, 1)
	go func() { done <- tm.RevokeCredentials() }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("RevokeCredentials did not return: it is waiting for dynamic secret leases that were never revoked")
	}

	assert.EqualValues(t, 1, revokeCalls.Load(), "the access token should be revoked once")
	token, err := os.ReadFile(sinkPath)
	require.NoError(t, err)
	assert.Empty(t, string(token), "the token sink should be emptied")
}
