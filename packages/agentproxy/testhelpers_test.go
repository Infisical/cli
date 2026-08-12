package agentproxy

import (
	"encoding/base64"
	"time"
)

// staticResolver stands in for bundleResolver: the tests care about matching, injection, and the activity
// record, not about how a bundle was fetched.
type staticResolver struct {
	services_ []*resolvedService
	err       error
}

func (s staticResolver) services(Session) ([]*resolvedService, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.services_, nil
}

// testSession is the session a test's broker view brokers for. Named so records are recognisable.
func testSession() *Session {
	return &Session{
		ID:               "session-1",
		AgentGatewayID:   "gateway-1",
		AgentGatewayName: "coding-agent",
		ActorName:        "dev@acme.com",
		ExpiresAt:        time.Now().Add(time.Hour),
	}
}

// proxySecretHeader builds the Proxy-Authorization header a local-mode listener expects.
func proxySecretHeader(secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("session:"+secret))
}
