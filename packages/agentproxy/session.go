package agentproxy

import "time"

// Session is the unit of brokering. In remote mode the gateway derives it from the client certificate a
// connection presented, never from anything the agent sends, which is what makes it impossible for one
// agent's connection to be served another's credentials. In local mode the CLI holds exactly one.
type Session struct {
	ID               string
	AgentGatewayID   string
	AgentGatewayName string

	// Recorded on activity so a request can be attributed without trusting the agent.
	ActorType string
	ActorID   string
	ActorName string

	// The policy for hosts no service matches comes from the agent gateway, not from the agent's flags: an
	// agent choosing its own passthrough behaviour would defeat the point of an allowlist.
	UnmatchedHost string

	// Hosts that pass through uncredentialed even under a block policy. Only local runs set this, from
	// --allow-host; a remote session has no flags of its own to honour.
	AllowedHosts []string

	ExpiresAt time.Time
}

func (s Session) expired() bool {
	return !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt)
}
