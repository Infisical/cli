package agentvault

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"
)

var errPolicyBlocked = errors.New("blocked by service policy")

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

// Never decodes: anything whose meaning depends on the upstream's normalisation is refused outright, so the
// comparison below is a plain byte comparison.
func pathAllowed(escaped string, prefixes []string) bool {
	if isAmbiguousPath(escaped) {
		return false
	}
	return matchesPrefix(escaped, prefixes)
}

// The path here is part-written by us: applySubstitutions escapes the value so it cannot add a segment, and
// pathAllowed would refuse that very '%2F'. Only traversal can leave an allowed prefix, so only traversal is
// refused, judged on the decoded path because that is what an upstream decoding '%2F' will route on. ';' and
// '\' count as traversal here for the reason isAmbiguousPath gives.
func pathAllowedAfterSubstitution(escaped, decoded string, prefixes []string) bool {
	if strings.ContainsAny(decoded, ";\\") {
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
