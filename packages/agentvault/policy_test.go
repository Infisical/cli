package agentvault

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func serviceWithPolicy(methods []string, prefixes []string) *resolvedService {
	return &resolvedService{
		name:                "github",
		allowedMethods:      toMethodSet(methods),
		allowedPathPrefixes: toPathPrefixes(prefixes),
	}
}

func requestTo(t *testing.T, method, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "https://api.github.com"+target, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	return req
}

func TestMethodPolicy(t *testing.T) {
	t.Run("a nil set allows every method", func(t *testing.T) {
		svc := serviceWithPolicy(nil, nil)
		for _, method := range []string{"GET", "POST", "DELETE", "PROPFIND"} {
			if err := checkServicePolicy(svc, requestTo(t, method, "/x")); err != nil {
				t.Fatalf("%s should be allowed: %v", method, err)
			}
		}
	})

	t.Run("only the listed methods pass", func(t *testing.T) {
		svc := serviceWithPolicy([]string{"GET", "HEAD"}, nil)
		if err := checkServicePolicy(svc, requestTo(t, "GET", "/x")); err != nil {
			t.Fatalf("GET should be allowed: %v", err)
		}
		err := checkServicePolicy(svc, requestTo(t, "POST", "/x"))
		if !errors.Is(err, errPolicyBlocked) {
			t.Fatalf("POST should be blocked, got %v", err)
		}
		if !strings.Contains(err.Error(), `service "github" does not allow POST`) {
			t.Fatalf("unhelpful message: %q", err.Error())
		}
	})

	t.Run("a refused method is capped before it reaches the log", func(t *testing.T) {
		svc := serviceWithPolicy([]string{"GET"}, nil)
		err := checkServicePolicy(svc, requestTo(t, strings.Repeat("A", 1<<20), "/x"))
		if !errors.Is(err, errPolicyBlocked) {
			t.Fatalf("an unlisted method should be blocked, got %v", err)
		}
		if len(err.Error()) > 200 {
			t.Fatalf("the refusal carries %d bytes; the agent's method would fill the proxy log", len(err.Error()))
		}
	})

	t.Run("a lower-case method is folded rather than blocked", func(t *testing.T) {
		svc := serviceWithPolicy([]string{"GET"}, nil)
		req := requestTo(t, "GET", "/x")
		req.Method = "get"
		if err := checkServicePolicy(svc, req); err != nil {
			t.Fatalf("get should fold to GET: %v", err)
		}
	})
}

func TestPathPolicy(t *testing.T) {
	svc := serviceWithPolicy(nil, []string{"/repos"})

	allowed := []string{
		"/repos/my%20repo",
		"/repos/...name", "/repos", "/repos/", "/repos/octo/hello", "/repos/a%20b"}
	for _, path := range allowed {
		t.Run("allows "+path, func(t *testing.T) {
			if err := checkServicePolicy(svc, requestTo(t, "GET", path)); err != nil {
				t.Fatalf("%s should be allowed: %v", path, err)
			}
		})
	}

	blocked := []string{
		"/repositories",
		"/repo",
		"/admin",
		"/repos/../admin",
		"/repos/./x",
		"//repos/x",
		"/repos/%2e%2e/admin",
		"/repos/%2E%2E/admin",
		"/admin/%2e%2e/repos/x",
		"/repos/%252e%252e/admin",
		"/repos/%c0%ae%c0%ae/admin",
		"/repos/..;/admin",
		"/repos;x/y",
		"/repos/%2fadmin",
		"/repos%5cx",
		// Windows and IIS drop a trailing space or dot, so each of these lands as ".." upstream.
		"/repos/..%20/admin",
		"/repos/.. /admin",
		"/repos/..../admin",
		"/repos/.%20./admin",
	}
	for _, path := range blocked {
		t.Run("blocks "+path, func(t *testing.T) {
			req := requestTo(t, "GET", "/placeholder")
			req.URL.Path = ""
			req.URL.RawPath = ""
			req.URL.Opaque = ""
			parsed := requestTo(t, "GET", path)
			req.URL = parsed.URL
			err := checkServicePolicy(svc, req)
			if !errors.Is(err, errPolicyBlocked) {
				t.Fatalf("%s should be blocked, got %v", path, err)
			}
		})
	}

	t.Run("a backslash is blocked even where Go keeps it literal", func(t *testing.T) {
		req := requestTo(t, "GET", "/repos")
		req.URL.Path = `/repos/\..\admin`
		req.URL.RawPath = ""
		if err := checkServicePolicy(svc, req); !errors.Is(err, errPolicyBlocked) {
			t.Fatalf("backslash traversal should be blocked, got %v", err)
		}
	})

	t.Run("an unrestricted service is untouched by any of it", func(t *testing.T) {
		open := serviceWithPolicy(nil, nil)
		for _, path := range blocked {
			req := requestTo(t, "GET", path)
			if err := checkServicePolicy(open, req); err != nil {
				t.Fatalf("%s should pass on an unrestricted service: %v", path, err)
			}
		}
	})

	t.Run("a deeper prefix still matches whole segments only", func(t *testing.T) {
		deep := serviceWithPolicy(nil, []string{"/repos/octo"})
		if err := checkServicePolicy(deep, requestTo(t, "GET", "/repos/octo/hello")); err != nil {
			t.Fatalf("/repos/octo should cover /repos/octo/hello: %v", err)
		}
		if err := checkServicePolicy(deep, requestTo(t, "GET", "/repos/octopus")); err == nil {
			t.Fatal("/repos/octo should not cover /repos/octopus")
		}
	})

	t.Run("prefix / matches everything", func(t *testing.T) {
		root := serviceWithPolicy(nil, []string{"/"})
		if err := checkServicePolicy(root, requestTo(t, "GET", "/anything/at/all")); err != nil {
			t.Fatalf("/ should match: %v", err)
		}
	})

	t.Run("a trailing slash on the prefix is normalised away", func(t *testing.T) {
		trailing := serviceWithPolicy(nil, []string{"/repos/"})
		if err := checkServicePolicy(trailing, requestTo(t, "GET", "/repos/octo")); err != nil {
			t.Fatalf("/repos/ should cover /repos/octo: %v", err)
		}
	})

	t.Run("an empty path reads as the root", func(t *testing.T) {
		root := serviceWithPolicy(nil, []string{"/"})
		req := requestTo(t, "GET", "/")
		req.URL.Path = ""
		if err := checkServicePolicy(root, req); err != nil {
			t.Fatalf("an empty path should read as /: %v", err)
		}
	})
}

func TestControlByteEscapesAreRefused(t *testing.T) {
	svc := serviceWithPolicy(nil, []string{"/repos"})
	for _, path := range []string{"/repos/..%00/admin", "/repos/%00../admin", "/repos/x%09y", "/repos/x%7f"} {
		t.Run(path, func(t *testing.T) {
			if err := checkServicePolicy(svc, requestTo(t, "GET", path)); !errors.Is(err, errPolicyBlocked) {
				t.Fatalf("%s should be blocked, got %v", path, err)
			}
		})
	}
}

func TestWireMappingFailsClosed(t *testing.T) {
	t.Run("nil stays unrestricted", func(t *testing.T) {
		if toMethodSet(nil) != nil || toPathPrefixes(nil) != nil {
			t.Fatal("a nil list must stay nil, which every caller reads as unrestricted")
		}
	})

	t.Run("an empty restriction allows nothing", func(t *testing.T) {
		methods := toMethodSet([]string{})
		if methods == nil || len(methods) != 0 {
			t.Fatalf("an empty method list must restrict, got %v", methods)
		}

		// "//" trims to "" the same way "  " does, so both have to reach the fail-closed guard.
		for _, empty := range []string{"  ", "//", "///"} {
			prefixes := toPathPrefixes([]string{empty})
			if len(prefixes) == 0 {
				t.Fatalf("%q must restrict, not fall through to unrestricted", empty)
			}
			svc := &resolvedService{name: "s", allowedPathPrefixes: prefixes}
			if err := checkServicePolicy(svc, requestTo(t, "GET", "/anything")); !errors.Is(err, errPolicyBlocked) {
				t.Fatalf("%q: expected a block, got %v", empty, err)
			}
		}
	})
}

func TestNonAsciiPathsAreJudgedByUtf8Validity(t *testing.T) {
	svc := serviceWithPolicy(nil, []string{"/repos"})

	allowed := []string{
		"/repos/owner/repo/contents/caf%C3%A9.md",
		"/repos/%E6%97%A5%E6%9C%AC%E8%AA%9E",
		"/repos/a%20b",
		"/repos/%F0%9F%94%91",
	}
	for _, path := range allowed {
		t.Run("allows "+path, func(t *testing.T) {
			if err := checkServicePolicy(svc, requestTo(t, "GET", path)); err != nil {
				t.Fatalf("%s should be allowed: %v", path, err)
			}
		})
	}

	// %c0%ae is an overlong '.', which some servers normalise as a traversal segment.
	blocked := []string{
		"/repos/%c0%ae%c0%ae/admin",
		"/repos/%c0%af",
		"/repos/%e0%80%ae",
		"/repos/%ff",
		"/repos/%c3",
	}
	for _, path := range blocked {
		t.Run("blocks "+path, func(t *testing.T) {
			if err := checkServicePolicy(svc, requestTo(t, "GET", path)); !errors.Is(err, errPolicyBlocked) {
				t.Fatalf("%s should be blocked, got %v", path, err)
			}
		})
	}
}

func TestAnExplicitRootPrefixMatchesEverythingAnUnrestrictedServiceWould(t *testing.T) {
	root := serviceWithPolicy(nil, []string{"/"})
	open := serviceWithPolicy(nil, nil)

	for _, path := range []string{"/anything", "/repos/caf%C3%A9.md", "/a%20b"} {
		t.Run(path, func(t *testing.T) {
			rootErr := checkServicePolicy(root, requestTo(t, "GET", path))
			openErr := checkServicePolicy(open, requestTo(t, "GET", path))
			if (rootErr == nil) != (openErr == nil) {
				t.Fatalf("prefix / and no prefix disagree on %s: %v vs %v", path, rootErr, openErr)
			}
		})
	}
}

// The post-substitution check is weaker than isAmbiguousPath on purpose, because we escape the value
// ourselves and isAmbiguousPath refuses that escaping. It still has to refuse what a value can introduce.
func TestThePostSubstitutionCheckRefusesWhatAValueCanIntroduce(t *testing.T) {
	prefixes := toPathPrefixes([]string{"/repos"})
	for _, tc := range []struct {
		value string
		want  bool
		why   string
	}{
		{"ghp_plain", true, "an ordinary secret"},
		{"org/repo", true, "a slash is escaped by us, not a separator"},
		{"v1.2", true, "a dot inside a segment is not a dot segment"},
		{"a%b", true, "a percent is escaped by us"},
		{"", false, "an empty value leaves '//' behind"},
		{"/admin", false, "a leading slash leaves '//' behind"},
		{"admin/", false, "a trailing slash leaves '//' behind"},
		{"a//b", false, "a doubled slash inside the value"},
		{"a\tb", false, "a control byte"},
		{"\xc0\xae\xc0\xae", false, "an overlong '..'"},
	} {
		req, _ := http.NewRequest("GET", "https://api.github.com/repos/__PAT__/admin", nil)
		if _, err := applySubstitutions(req, "github", []substitution{subOn("__PAT__", tc.value, surfacePath)}); err != nil {
			t.Fatalf("%s: %v", tc.why, err)
		}
		if got := pathAllowedAfterSubstitution(requestPath(req), req.URL.Path, prefixes); got != tc.want {
			t.Errorf("value %q (%s): allowed = %v, want %v (path %q)", tc.value, tc.why, got, tc.want, requestPath(req))
		}
	}
}

// Go rebuilds EscapedPath from the decoded path when RawPath is not valid encoding, which drops the very
// '%2F' hasUnsafeEscape exists to refuse. Escaping those bytes first keeps the escape intact.
func TestNormalizeRequestTargetKeepsAnEscapeGoWouldDrop(t *testing.T) {
	for _, tc := range []struct{ raw, want, why string }{
		{"/repos/a%2Fb", "/repos/a%2Fb", "already valid, left alone"},
		{"/repos/a%2Fb/{x}", "/repos/a%2Fb/%7Bx%7D", "the brace is escaped, the %2F survives"},
		{"/repos/{{PAT}}", "/repos/%7B%7BPAT%7D%7D", "a placeholder still reads as one"},
		{"/repos/a|b", "/repos/a%7Cb", "a pipe"},
		{"/repos/a%25b/{x}", "/repos/a%25b/%7Bx%7D", "an escaped percent is not escaped twice"},
		{"/repos/plain", "/repos/plain", "nothing to do"},
		// validEncoded accepts these, so Go never rebuilds and the guard leaves them exactly as sent. Escaping
		// them would change the wire and break a byte-compared prefix.
		{"/repos/a(b)!*[]'", "/repos/a(b)!*[]'", "sub-delims Go accepts unescaped"},
		{"/repos/a%2Fb/c(d)", "/repos/a%2Fb/c(d)", "an escape plus sub-delims, still valid"},
	} {
		u, err := url.ParseRequestURI(tc.raw)
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		normalizeRequestTarget(u)
		if got := u.EscapedPath(); got != tc.want {
			t.Errorf("%s (%s): EscapedPath = %q, want %q", tc.raw, tc.why, got, tc.want)
		}
	}
}

// The escape that used to be dropped is the one the prefix check runs on, so a single brace decided whether
// a path was refused.
func TestAnEscapedSlashIsRefusedWhateverElseThePathCarries(t *testing.T) {
	prefixes := toPathPrefixes([]string{"/repos"})
	for _, raw := range []string{"/repos/a%2Fb", "/repos/a%2Fb/{x}"} {
		u, err := url.ParseRequestURI(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		normalizeRequestTarget(u)
		if pathAllowed(u.EscapedPath(), prefixes) {
			t.Errorf("%s was allowed; an escaped slash must be refused", raw)
		}
	}
}
