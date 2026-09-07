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

// injectCredential overwrites an existing header on the agent's request, silently and deliberately.
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
		return false
	}
}

// stripHopByHopHeaders also deletes Upgrade, which is why WebSocket upgrades cannot be forwarded.
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
