package agentvault

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

var errPolicyBlocked = errors.New("blocked by service policy")

// The agent's own upload broke part way. Not a policy refusal and not an upstream failure, so it carries its
// own status rather than landing in either of theirs.
var errBodyUnreadable = errors.New("could not read the request body")

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

func (s *resolvedService) allowsMethod(method string) bool {
	if s.allowedMethods == nil {
		return true
	}
	return s.allowedMethods[strings.ToUpper(method)]
}

// Rails, Laravel and Symfony all honour these, so a POST carrying one performs the method it names. The
// wire method is what the allowlist judged, so where there is an allowlist the header has to go.
func stripMethodOverrideHeaders(header http.Header) {
	for _, name := range []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"} {
		header.Del(name)
	}
}

// Whether Go would escape a byte appearing unescaped in a path. Derived from the standard library rather
// than transcribed from it: the table behind encodePath is generated, so a copy would be one Go release
// away from disagreeing with the rebuild this guards against.
var pathByteNeedsEscape = func() (table [256]bool) {
	for b := 0; b < 256; b++ {
		raw := string([]byte{byte(b)})
		table[b] = (&url.URL{Path: raw}).EscapedPath() != raw
	}
	return table
}()

// EscapedPath falls back to rebuilding the path from its decoded form whenever RawPath is not valid
// encoding, and one literal '{' is enough. The rebuild turns '%2F' into a real '/', so hasUnsafeEscape
// never sees the escape it exists to refuse and the upstream receives a path the agent did not send.
// Escaping those bytes ourselves keeps RawPath valid, so EscapedPath returns it untouched. The wire form is
// unchanged either way: Go was already sending '%7B'.
func normalizeRequestTarget(u *url.URL) {
	if u.RawPath == "" || u.EscapedPath() == u.RawPath {
		return
	}
	escaped := escapeInvalidPathBytes(u.RawPath)
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		return
	}
	u.Path = decoded
	u.RawPath = escaped
}

// A '%' opening a valid triple is carried through, so an escape the agent wrote is never escaped twice. A
// malformed one cannot arrive: ParseRequestURI rejects it and the server answers 400 before the handler.
func escapeInvalidPathBytes(raw string) string {
	var out strings.Builder
	out.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '%' && i+2 < len(raw) {
			if _, hiOk := unhex(raw[i+1]); hiOk {
				if _, loOk := unhex(raw[i+2]); loOk {
					out.WriteString(raw[i : i+3])
					i += 2
					continue
				}
			}
		}
		if pathByteNeedsEscape[c] {
			const hexDigits = "0123456789ABCDEF"
			out.WriteByte('%')
			out.WriteByte(hexDigits[c>>4])
			out.WriteByte(hexDigits[c&0x0f])
			continue
		}
		out.WriteByte(c)
	}
	return out.String()
}

func requestPath(req *http.Request) string {
	path := req.URL.EscapedPath()
	if path == "" {
		// forwardHTTP refuses an opaque target before this runs, so the branch is a floor under that check
		// rather than a shape expected here. A genuinely empty path is the root.
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

// Never decodes: anything whose meaning depends on the upstream's normalisation is refused outright, so the
// comparison below is a plain byte comparison.
func pathAllowed(escaped string, prefixes []string) bool {
	if isAmbiguousPath(escaped) {
		return false
	}
	return matchesPrefix(escaped, prefixes)
}

// Deliberately not isAmbiguousPath. The path here is part-written by us: applySubstitutions escapes the
// value so it cannot add a segment, and isAmbiguousPath refuses that very '%2F', so a secret like
// 'org/repo' would be rejected on its own escaping. Judged on the decoded path instead, which is both what
// an upstream decoding '%2F' will route on and the form our own escaping is invisible in. Everything below
// is a shape a substituted value could introduce; the agent's half of the path has already been through
// isAmbiguousPath on arrival.
func pathAllowedAfterSubstitution(escaped, decoded string, prefixes []string) bool {
	if strings.ContainsAny(decoded, ";\\") {
		return false
	}
	// Normalises differently per server, and an empty value substituted mid-path is how it arises here.
	if strings.Contains(decoded, "//") {
		return false
	}
	for i := 0; i < len(decoded); i++ {
		if decoded[i] < 0x20 || decoded[i] == 0x7f {
			return false
		}
	}
	// '%c0%ae' is an overlong '.', which some servers read as a dot and route on.
	if !utf8.ValidString(decoded) {
		return false
	}
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
		if rest := escaped[len(prefix):]; rest == "" || rest[0] == '/' {
			return true
		}
	}
	return false
}

func isAmbiguousPath(escaped string) bool {
	// Tomcat and Spring strip ;params before normalising, so /repos/..;/admin resolves to /admin upstream
	// while reading as an ordinary segment here. IIS reads '\' as a separator.
	if strings.ContainsAny(escaped, ";\\") {
		return true
	}
	if hasUnsafeEscape(escaped) {
		return true
	}
	for _, segment := range strings.Split(escaped, "/") {
		if isDotSegment(decodeBenignEscapes(segment)) {
			return true
		}
	}
	// /a//b normalises differently per server.
	return strings.Contains(escaped, "//")
}

// The UTF-8 check is what lets a real non-ASCII path through while still refusing the attack: `%c0%ae` is
// an overlong '.', which some servers read as a dot, while `%c3%a9` is a legitimate 'é'. Refusing every
// byte >= 0x80 would catch the first and break every API carrying a filename in its path.
func hasUnsafeEscape(escaped string) bool {
	decoded := make([]byte, 0, len(escaped))
	sawEscape := false

	for i := 0; i < len(escaped); i++ {
		if escaped[i] != '%' {
			decoded = append(decoded, escaped[i])
			continue
		}
		if i+2 >= len(escaped) {
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

	// Only escaped input can carry an overlong sequence.
	return sawEscape && !utf8.Valid(decoded)
}

// Runs after hasUnsafeEscape, so every escape still standing decodes to something harmless. Only the
// decoded form tells us whether a segment is all dots and spaces: "..%20" is not, ".. " is.
func decodeBenignEscapes(segment string) string {
	if !strings.Contains(segment, "%") {
		return segment
	}
	out := make([]byte, 0, len(segment))
	for i := 0; i < len(segment); i++ {
		if segment[i] != '%' || i+2 >= len(segment) {
			out = append(out, segment[i])
			continue
		}
		hi, hiOk := unhex(segment[i+1])
		lo, loOk := unhex(segment[i+2])
		if !hiOk || !loOk {
			out = append(out, segment[i])
			continue
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return string(out)
}

// Windows and IIS strip trailing dots and spaces from a segment, so anything built only from those reads
// as "." or ".." once it lands.
func isDotSegment(segment string) bool {
	if segment == "" {
		return false
	}
	for i := 0; i < len(segment); i++ {
		if segment[i] != '.' && segment[i] != ' ' {
			return false
		}
	}
	return true
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
