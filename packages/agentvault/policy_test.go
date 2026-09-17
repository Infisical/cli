package agentvault

import (
	"errors"
	"net/http"
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
