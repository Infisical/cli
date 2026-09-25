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

// Written before the credential, so one colliding with the credential's header loses to it. Pass-through
// injects nothing, which is why Authorization as a custom header on one still works.
// Returns whether any header was written, and whether a placeholder was resolved inside one, so the audit
// record can report the injection the way a request-surface substitution is reported.
func injectCustomHeaders(req *http.Request, customHeaders []customHeader, subs []substitution) (brokered, resolved bool) {
	for _, header := range customHeaders {
		value := string(header.value)
		if header.prefix != "" {
			value = header.prefix + " " + value
		}
		// A placeholder written into a header value is resolved here, so one substitution can stand for a
		// secret reused across several headers. Gated on the header surface: ticking it is the admin saying
		// the secret may appear in a header, and a custom header is one. Never the agent's request or the
		// credential, so nothing the agent sends can steer it.
		for _, sub := range subs {
			if !sub.surfaces[surfaceHeader] || len(sub.placeholder) == 0 {
				continue
			}
			if replacedValue, ok := replaceWithinLimit(value, sub.placeholder, string(sub.value), maxBodyRewriteSize); ok && replacedValue != value {
				value = replacedValue
				resolved = true
			}
		}
		req.Header.Set(header.name, value)
	}
	return len(customHeaders) > 0, resolved
}

// A body it cannot rewrite is logged rather than skipped in silence: the placeholder goes upstream and the
// agent would otherwise see only a third-party 401.
func applySubstitutions(req *http.Request, serviceName string, subs []substitution) ([]string, error) {
	changed := map[string]bool{}
	for _, sub := range subs {
		if len(sub.placeholder) == 0 {
			continue
		}
		real := string(sub.value)

		// Swapped in the escaped path so every other segment keeps the byte form the agent sent. Rewriting the
		// decoded Path makes Go re-derive the wire path without re-escaping '/', and `group%2Fproject` would
		// arrive as two segments pointing at a different resource.
		if sub.surfaces[surfacePath] {
			escaped := req.URL.EscapedPath()
			// normalizeRequestTarget has already escaped whatever Go would have objected to, so a `{{TOKEN}}`
			// on the wire reads here as `%7B%7BTOKEN%7D%7D` and matching only the typed form would miss it.
			needle := sub.placeholder
			if !strings.Contains(escaped, needle) {
				// Percent-escapes carry no required case and clients differ, so the fallback matches against
				// upper-cased escapes. Rewriting them is free here: substituting changes the URL anyway, so a
				// request the agent signed itself could never have used this surface.
				needle = escapedPathForm(sub.placeholder)
				escaped = upperPercentEscapes(escaped)
			}
			if strings.Contains(escaped, needle) {
				if v, ok := replaceWithinLimit(escaped, needle, url.PathEscape(real), maxBodyRewriteSize); ok {
					if decoded, err := url.PathUnescape(v); err == nil {
						// Go uses RawPath only when it agrees with Path, so both are written.
						req.URL.Path = decoded
						req.URL.RawPath = v
						changed[surfacePath] = true
					}
				}
			}
		}

		// Escaped, because RawQuery goes on the wire verbatim. A base64 key containing '+' would otherwise
		// arrive as a space, and one containing '&' would split into a second parameter.
		if sub.surfaces[surfaceQuery] {
			// A client that builds the query from parameters rather than a string percent-encodes the
			// placeholder first, so `{{TOKEN}}` arrives as `%7B%7BTOKEN%7D%7D`. The path surface already
			// falls back this way; without it the placeholder reaches the third party and the 401 that
			// comes back says nothing about why.
			rawQuery := req.URL.RawQuery
			needle := sub.placeholder
			if !strings.Contains(rawQuery, needle) {
				needle = queryEscapedForm(sub.placeholder)
				rawQuery = upperPercentEscapes(rawQuery)
			}
			if strings.Contains(rawQuery, needle) {
				if v, ok := replaceWithinLimit(rawQuery, needle, queryValueEscape(real), maxBodyRewriteSize); ok {
					req.URL.RawQuery = v
					changed[surfaceQuery] = true
				}
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

	// The path, query and header surfaces are already rewritten by now, so a body that cannot be read has to
	// hand back what fired alongside the error. The request is refused, but the record still has to say the
	// credential was written into it.
	var bodyErr error
	if bodySubstitutions(subs) && req.Body != nil {
		replaced, err := applyBodySubstitutions(req, serviceName, subs)
		if replaced {
			changed[surfaceBody] = true
		}
		bodyErr = err
	}

	surfaces := make([]string, 0, len(changed))
	for _, surface := range []string{surfacePath, surfaceQuery, surfaceHeader, surfaceBody} {
		if changed[surface] {
			surfaces = append(surfaces, surface)
		}
	}
	return surfaces, bodyErr
}

// The placeholder as EscapedPath would render it. The leading '/' keeps url.URL's `Path == "*"` case out of
// it, and the encoder leaves a slash alone, so trimming it back off is exact.
// QueryEscape is form encoding, where a space becomes '+'. Anything reading the raw query per RFC 3986,
// SigV4 signing among them, takes that as a literal plus. Every other special is already %XX by then, so
// the only '+' left to rewrite is a space.
func queryValueEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func queryEscapedForm(placeholder string) string {
	return queryValueEscape(placeholder)
}

// Percent-escapes are case-insensitive, so matching is done against a copy with the hex digits upper-cased.
// Same length as the input, so nothing else about the string moves.
func upperPercentEscapes(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] != '%' {
			continue
		}
		b[i+1] = upperHexDigit(b[i+1])
		b[i+2] = upperHexDigit(b[i+2])
	}
	return string(b)
}

func upperHexDigit(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}

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

func applyBodySubstitutions(req *http.Request, serviceName string, subs []substitution) (bool, error) {
	if req.Body == http.NoBody || req.ContentLength == 0 {
		return false, nil
	}
	if req.Header.Get("Content-Encoding") != "" {
		log.Warn().
			Str("service", serviceName).
			Bool("hasContentEncoding", true).
			Msg("agent-vault: body substitution skipped on an encoded body; the placeholder is going upstream unchanged")
		return false, nil
	}
	// Judged before reading, so an oversize body costs no memory. The check below still has to stand on its
	// own: a chunked request declares -1, and a declared length is a claim rather than a fact.
	if req.ContentLength > maxBodyRewriteSize {
		log.Warn().Str("service", serviceName).Int("limitBytes", maxBodyRewriteSize).
			Int64("declaredBytes", req.ContentLength).
			Msg("agent-vault: body larger than the substitution limit; the placeholder is going upstream unchanged")
		return false, nil
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, maxBodyRewriteSize+1))
	if err != nil {
		// Refused outright rather than forwarded short. This used to leave ContentLength disagreeing with the
		// bytes so http.Transport would refuse, but a chunked upload declares -1 and there is nothing to leave
		// wrong, so the upstream received a well-formed partial request with the credential on it and could not
		// tell. A partial write is not something an agent can take back.
		_ = req.Body.Close()
		log.Warn().Err(err).Str("service", serviceName).Int("bytesRead", len(body)).
			Msg("agent-vault: could not read the whole request body for substitution; refusing to forward a truncated one")
		return false, errBodyUnreadable
	}
	if len(body) > maxBodyRewriteSize {
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), req.Body))
		log.Warn().Str("service", serviceName).Int("limitBytes", maxBodyRewriteSize).
			Msg("agent-vault: body larger than the substitution limit; the placeholder is going upstream unchanged")
		return false, nil
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
		// Division for the growing case, for the overflow reason replaceWithinLimit spells out below.
		delta := len(sub.value) - len(sub.placeholder)
		room := maxBodyRewriteSize - len(rewritten)
		if delta > 0 && (room < 0 || count > room/delta) {
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
	return replaced, nil
}

// Returns the input unchanged when the expansion would exceed limit, so a short placeholder mapped to a long
// secret cannot balloon proxy memory.
func replaceWithinLimit(s, old, replacement string, limit int) (string, bool) {
	count := strings.Count(s, old)
	if count == 0 {
		return s, true
	}
	delta := len(replacement) - len(old)
	if delta > 0 {
		// Division rather than count*delta, which overflows int on the 386 and armv6 builds and wraps to a
		// negative, answering "small enough" for something that then fails to allocate.
		room := limit - len(s)
		if room < 0 || count > room/delta {
			return s, false
		}
	} else if len(s)+count*delta > limit {
		return s, false
	}
	return strings.ReplaceAll(s, old, replacement), true
}

// stripHopByHopHeaders also deletes Upgrade, which is why WebSocket upgrades cannot be forwarded.
// Callers strip before injecting a credential: a Connection list naming the credential's header would
// otherwise delete it, which is the same trap Go documents on httputil.ReverseProxy.Director.
func stripHopByHopHeaders(header http.Header) {
	// Read Connection before deleting it, or the headers it names go on with nothing marking them.
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
