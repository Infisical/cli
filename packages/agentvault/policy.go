package agentvault

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"
)

// errPolicyBlocked is the sentinel for a service's own method and path rules, distinct from errHostBlocked,
// which is the proxy-wide traffic policy. Both render as a 403 whose body is err.Error().
var errPolicyBlocked = errors.New("blocked by service policy")

// checkServicePolicy runs on the request exactly as it arrived, before anything rewrites it, and before the
// plaintext refusal that nils a match: a restriction has to hold on http:// too, not only where a credential
// would have been attached.
func checkServicePolicy(svc *resolvedService, req *http.Request) error {
	if !svc.allowsMethod(req.Method) {
		return fmt.Errorf("service %q does not allow %s: %w", svc.name, req.Method, errPolicyBlocked)
	}
	if len(svc.allowedPathPrefixes) > 0 {
		path := requestPath(req)
		if !pathAllowed(path, svc.allowedPathPrefixes) {
			return fmt.Errorf("service %q does not allow path %q: %w", svc.name, truncatePath(path), errPolicyBlocked)
		}
	}
	return nil
}

// A nil map is every method. The set is built upper-case, and the comparison folds the request's method the
// same way, so a client sending "get" is judged on GET rather than silently blocked.
func (s *resolvedService) allowsMethod(method string) bool {
	if s.allowedMethods == nil {
		return true
	}
	return s.allowedMethods[strings.ToUpper(method)]
}

// EscapedPath is byte-for-byte what Request.write puts on the wire (RequestURI() returns it, and forward only
// rewrites Scheme, Host and RequestURI), so this judges exactly what the upstream will receive.
func requestPath(req *http.Request) string {
	path := req.URL.EscapedPath()
	if path == "" {
		// OPTIONS * arrives as "*" and is left alone; a genuinely empty path is the root.
		if req.URL.Opaque != "" {
			return req.URL.Opaque
		}
		return "/"
	}
	return path
}

func truncatePath(path string) string {
	if len(path) > maxLoggedPathLen {
		return path[:maxLoggedPathLen] + "...[truncated]"
	}
	return path
}

// pathAllowed never decodes. Anything whose meaning would depend on how the upstream normalises it is refused
// outright, so the prefix comparison below is a plain byte comparison and the filter can only ever allow a
// path every reader agrees on. Prefixes carry none of these characters by grammar.
func pathAllowed(escaped string, prefixes []string) bool {
	if isAmbiguousPath(escaped) {
		return false
	}
	return matchesPrefix(escaped, prefixes)
}

// pathAllowedAfterSubstitution judges a path the proxy itself part-wrote, so it cannot use the rule above.
// applySubstitutions percent-escapes the value precisely so a secret containing '/' cannot add a segment,
// and that escape is the '%2F' isAmbiguousPath refuses: judged by pathAllowed, a GitLab project addressed
// as `group%2Fproject` would 403 against a prefix that plainly covers it.
//
// The prefix comparison is unchanged and still byte-exact, which is what keeps the substituted span after
// the prefix: a placeholder sitting inside the prefix region rewrites those bytes and fails the comparison.
// That leaves traversal as the only way out of an allowed prefix, so it is the only thing still refused,
// and it is judged on the decoded path because an upstream that decodes '%2F' before routing is exactly
// the reader `..%2F..%2Fadmin` is written for.
func pathAllowedAfterSubstitution(escaped, decoded string, prefixes []string) bool {
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return matchesPrefix(escaped, prefixes)
}

func matchesPrefix(escaped string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix == "/" {
			return true
		}
		if !strings.HasPrefix(escaped, prefix) {
			continue
		}
		// Whole segments only, so /repos does not cover /repositories.
		if rest := escaped[len(prefix):]; rest == "" || rest[0] == '/' {
			return true
		}
	}
	return false
}

func isAmbiguousPath(escaped string) bool {
	// ';' because Tomcat, Jetty and Spring strip ;params per segment before normalising, so /repos/..;/admin
	// resolves to /admin upstream while reading as an ordinary segment here. '\' because Go treats it as a
	// path byte and IIS and .NET read it as a separator.
	if strings.ContainsAny(escaped, ";\\") {
		return true
	}
	if hasUnsafeEscape(escaped) {
		return true
	}
	for _, segment := range strings.Split(escaped, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	// An empty segment: /a//b normalises differently per server. A leading // is covered too; it could only
	// ever fail the prefix comparison anyway, but judging it here keeps the rule one sentence.
	return strings.Contains(escaped, "//")
}

// Judges the percent-escapes in a path. An escape is unsafe when it decodes to a separator, a dot, a
// control byte, or to a byte sequence that is not valid UTF-8.
//
// The UTF-8 check is what lets a real non-ASCII path through while still refusing the attack it protects
// against. `%c3%a9` is a correctly encoded 'é' and decodes to one rune; `%c0%ae` is an overlong encoding
// of '.', which Go decodes to RuneError and some servers read as a dot. Rejecting every byte >= 0x80
// would catch the second but also break every API that carries a filename or a user string in its path.
// The rest (%2e, %2f, %5c, the double-encoded %252e, and the null-truncation ..%00) fall out of the
// decoded-byte switch. %20 still works.
func hasUnsafeEscape(escaped string) bool {
	decoded := make([]byte, 0, len(escaped))
	sawEscape := false

	for i := 0; i < len(escaped); i++ {
		if escaped[i] != '%' {
			decoded = append(decoded, escaped[i])
			continue
		}
		if i+2 >= len(escaped) {
			// A truncated escape is not something we can judge either.
			return true
		}
		hi, hiOk := unhex(escaped[i+1])
		lo, loOk := unhex(escaped[i+2])
		if !hiOk || !loOk {
			return true
		}
		b := hi<<4 | lo
		if b < 0x20 || b == 0x7f {
			return true
		}
		switch b {
		case '.', '/', '\\', ';', '%':
			return true
		}
		decoded = append(decoded, b)
		sawEscape = true
		i += 2
	}

	// Only escaped input can carry an overlong or truncated sequence; an unescaped path is whatever the
	// client put on the wire and is compared byte for byte anyway.
	return sawEscape && !utf8.Valid(decoded)
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
