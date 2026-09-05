package agentvault

import (
	"encoding/base64"
	"net/http"
)

const (
	credentialBearer      = "bearer"
	credentialBasic       = "basic"
	credentialPassthrough = "passthrough"
)

// injectCredential writes the real credential onto an outbound request.
//
// An existing header on the agent's request is overwritten, silently and deliberately: the agent is
// expected to send a placeholder or nothing, and the whole point is that whatever it sent is fake.
//
// The prefix is stored exactly as typed, with no trailing space, and joined to the value with one space
// which is skipped when the prefix is empty. That is how `DD-API-KEY: abc123` comes out right while
// `Authorization: Bearer abc123` also does.
func injectCredential(req *http.Request, cred *credential) bool {
	switch cred.kind {
	case credentialBearer:
		headerName := cred.headerName
		if headerName == "" {
			headerName = "Authorization"
		}
		value := string(cred.value)
		if cred.headerPrefix != "" {
			value = cred.headerPrefix + " " + value
		}
		req.Header.Set(headerName, value)
		return true
	case credentialBasic:
		encoded := base64.StdEncoding.EncodeToString([]byte(cred.username + ":" + string(cred.password)))
		req.Header.Set("Authorization", "Basic "+encoded)
		return true
	default:
		// Passthrough adds nothing. Under the `allow` default that differs from doing nothing only in
		// that TLS is still terminated, which is why the connection sheet says so.
		return false
	}
}

// stripHopByHopHeaders removes headers that belong to a single hop, so they are not forwarded upstream.
//
// Note this deletes Upgrade, which is why WebSockets do not work through this proxy. That is an
// inherited, documented gap rather than an oversight — see the protocol gaps in the Agent Vault docs.
func stripHopByHopHeaders(header http.Header) {
	for _, name := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
}
