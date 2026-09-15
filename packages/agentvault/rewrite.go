package agentvault

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
)

const (
	credentialBearer      = "bearer"
	credentialBasic       = "basic"
	credentialPassthrough = "passthrough"

	surfacePath   = "path"
	surfaceQuery  = "query"
	surfaceHeader = "header"
	surfaceBody   = "body"

	maxBodyRewriteSize = 10 * 1024 * 1024
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

// injectCustomHeaders writes the service's custom headers, before the credential, so one whose name collides with
// the credential's loses to it rather than replacing the real token. A pass-through service injects no
// credential at all, which is why setting Authorization as a custom header on one still works.
func injectCustomHeaders(req *http.Request, customHeaders []customHeader) bool {
	for _, header := range customHeaders {
		value := string(header.value)
		if header.prefix != "" {
			value = header.prefix + " " + value
		}
		req.Header.Set(header.name, value)
	}
	return len(customHeaders) > 0
}

// applySubstitutions swaps each placeholder for its real value across the surfaces the service names.
// Ported from the agent proxy (packages/agentproxy/rewrite.go), with one deliberate change: a body it
// cannot rewrite is logged rather than skipped in silence, because the request then goes upstream with the
// placeholder still in it and the agent only ever sees a third-party 401.
func applySubstitutions(req *http.Request, serviceName string, subs []substitution) []string {
	changed := map[string]bool{}
	for _, sub := range subs {
		if len(sub.placeholder) == 0 {
			continue
		}
		real := string(sub.value)

		// Swapped in the escaped path and written back escaped, so every other segment keeps the byte form
		// the agent sent. Rewriting the decoded Path and clearing RawPath (which is what Agent Proxy does)
		// makes Go re-derive the wire path, and its encoder does not re-escape '/' or '+': a GitLab project
		// addressed as `group%2Fproject` would arrive as two segments, pointing at a different resource.
		if sub.surfaces[surfacePath] {
			escaped := req.URL.EscapedPath()
			// EscapedPath re-encodes the whole path whenever what the agent sent is not already valid
			// encoding, so a `{{TOKEN}}` on the wire reads here as `%7B%7BTOKEN%7D%7D`. Looking only for the
			// form the author typed would leave those placeholders on the wire, and the agent would see
			// nothing but a third-party 404.
			needle := sub.placeholder
			if !strings.Contains(escaped, needle) {
				needle = escapedPathForm(sub.placeholder)
			}
			if strings.Contains(escaped, needle) {
				// The replacement is escaped too, or a secret containing '/' or '?' would itself reshape the URL.
				if v, ok := replaceWithinLimit(escaped, needle, url.PathEscape(real), maxBodyRewriteSize); ok {
					if decoded, err := url.PathUnescape(v); err == nil {
						// Both halves: Path is what the policy re-check and any later reader see, RawPath is
						// what goes on the wire. Go uses RawPath only when it agrees with Path.
						req.URL.Path = decoded
						req.URL.RawPath = v
						changed[surfacePath] = true
					}
				}
			}
		}

		// Escaped, because RawQuery goes on the wire verbatim. A base64 key containing '+' would otherwise
		// arrive as a space, and one containing '&' would split into a second parameter.
		if sub.surfaces[surfaceQuery] && strings.Contains(req.URL.RawQuery, sub.placeholder) {
			if v, ok := replaceWithinLimit(req.URL.RawQuery, sub.placeholder, url.QueryEscape(real), maxBodyRewriteSize); ok {
				req.URL.RawQuery = v
				changed[surfaceQuery] = true
			}
		}

		if sub.surfaces[surfaceHeader] {
			for name, values := range req.Header {
				for i, v := range values {
					if !strings.Contains(v, sub.placeholder) {
						continue
					}
					if replaced, ok := replaceWithinLimit(v, sub.placeholder, real, maxBodyRewriteSize); ok {
						req.Header[name][i] = replaced
						changed[surfaceHeader] = true
					}
				}
			}
		}
	}

	if bodySubstitutions(subs) && req.Body != nil {
		if applyBodySubstitutions(req, serviceName, subs) {
			changed[surfaceBody] = true
		}
	}

	surfaces := make([]string, 0, len(changed))
	for _, surface := range []string{surfacePath, surfaceQuery, surfaceHeader, surfaceBody} {
		if changed[surface] {
			surfaces = append(surfaces, surface)
		}
	}
	return surfaces
}

// escapedPathForm is the placeholder as EscapedPath would render it: the same encoder, reached the same way.
// The leading '/' keeps url.URL's `Path == "*"` special case out of it, and the path encoder leaves a slash
// alone, so trimming it back off is exact.
func escapedPathForm(placeholder string) string {
	return strings.TrimPrefix((&url.URL{Path: "/" + placeholder}).EscapedPath(), "/")
}

func bodySubstitutions(subs []substitution) bool {
	for _, sub := range subs {
		if sub.surfaces[surfaceBody] {
			return true
		}
	}
	return false
}

// The body is only ever read when some substitution names it, so a service without one keeps streaming
// exactly as before.
func applyBodySubstitutions(req *http.Request, serviceName string, subs []substitution) bool {
	if req.Body == http.NoBody || req.ContentLength == 0 {
		return false
	}
	if enc := req.Header.Get("Content-Encoding"); enc != "" {
		log.Warn().
			Str("service", serviceName).
			Str("contentEncoding", enc).
			Msg("agent-vault: body substitution skipped on an encoded body; the placeholder is going upstream unchanged")
		return false
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, maxBodyRewriteSize+1))
	if err != nil {
		// Deliberately not correcting ContentLength to what was actually read. The declared length and the
		// bytes now disagree, so http.Transport refuses the request and nothing reaches the upstream. Making
		// them agree would hand the upstream a well-formed shorter request it cannot tell from a complete
		// one, turning a broken upload into a partial write nobody can take back. A 502 the agent may not
		// even be alive to see is the better end of that trade.
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
		log.Warn().Err(err).Str("service", serviceName).Int("bytesRead", len(body)).
			Msg("agent-vault: could not read the whole request body for substitution; refusing to forward a truncated one")
		return false
	}
	if len(body) > maxBodyRewriteSize {
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), req.Body))
		log.Warn().Str("service", serviceName).Int("limitBytes", maxBodyRewriteSize).
			Msg("agent-vault: body larger than the substitution limit; the placeholder is going upstream unchanged")
		return false
	}
	_ = req.Body.Close()

	rewritten := body
	replaced := false
	for _, sub := range subs {
		if !sub.surfaces[surfaceBody] || len(sub.placeholder) == 0 {
			continue
		}
		count := bytes.Count(rewritten, []byte(sub.placeholder))
		if count == 0 {
			continue
		}
		// Forward unchanged when expanding the placeholder would push the body past the cap.
		if len(rewritten)+count*(len(sub.value)-len(sub.placeholder)) > maxBodyRewriteSize {
			log.Warn().Str("service", serviceName).Int("limitBytes", maxBodyRewriteSize).
				Msg("agent-vault: substituted body would exceed the limit; the placeholder is going upstream unchanged")
			continue
		}
		rewritten = bytes.ReplaceAll(rewritten, []byte(sub.placeholder), sub.value)
		replaced = true
	}

	if len(rewritten) == 0 {
		// A NopCloser over an empty reader reads to net/http as "length unknown", which turns a bodyless
		// POST into a chunked request. Signing schemes and some gateways reject that.
		req.Body = http.NoBody
	} else {
		req.Body = io.NopCloser(bytes.NewReader(rewritten))
	}
	req.ContentLength = int64(len(rewritten))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	return replaced
}

// replaceWithinLimit substitutes every occurrence of old in s, but only when the expanded result stays
// within limit bytes; otherwise it returns the input unchanged. This stops a short placeholder mapped to a
// long secret from ballooning proxy memory, since ReplaceAll allocates by the expansion ratio.
func replaceWithinLimit(s, old, replacement string, limit int) (string, bool) {
	count := strings.Count(s, old)
	if count == 0 {
		return s, true
	}
	if len(s)+count*(len(replacement)-len(old)) > limit {
		return s, false
	}
	return strings.ReplaceAll(s, old, replacement), true
}

// stripHopByHopHeaders also deletes Upgrade, which is why WebSocket upgrades cannot be forwarded.
// Callers strip before injecting a credential: a Connection list naming the credential's header would
// otherwise delete it, which is the same trap Go documents on httputil.ReverseProxy.Director.
func stripHopByHopHeaders(header http.Header) {
	// Connection names the headers meant for this hop alone, so read it before deleting it. Deleting it
	// first would forward the marked header with nothing left to say it was hop-by-hop.
	for _, values := range header.Values("Connection") {
		for _, name := range strings.Split(values, ",") {
			if name = strings.TrimSpace(name); name != "" {
				header.Del(name)
			}
		}
	}
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
