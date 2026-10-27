package agentvault

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
)

const testSkillID = "8f0e7c1a-3b9e-4c55-9d3e-2a1b7c6d5e4f"

type fakeInfisical struct {
	t *testing.T

	mu          sync.Mutex
	resolveCode int
	resolveName string
	skills      []api.AgentVaultProxySkill
	listCode    int
	listBody    map[string]any
	hits        map[string]int
}

func newFakeInfisical(t *testing.T) *fakeInfisical {
	f := &fakeInfisical{t: t, hits: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = old })
	return f
}

func (f *fakeInfisical) hitCount(kind string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[kind]
}

func writeJSONError(w http.ResponseWriter, code int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeInfisical) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get(api.AgentVaultSessionHeader) == "" {
		f.t.Errorf("%s arrived without the session header", r.URL.Path)
	}
	switch strings.TrimPrefix(r.URL.Path, "/api/v1/agent-vault/proxy") {
	case "/resolve":
		f.hits["resolve"]++
		if f.resolveCode != 0 {
			writeJSONError(w, f.resolveCode, map[string]any{"statusCode": f.resolveCode, "message": "no", "error": f.resolveName})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sessionId": "s1", "services": []any{}})
	case "/skills":
		f.hits["list"]++
		if f.listCode != 0 {
			writeJSONError(w, f.listCode, f.listBody)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.AgentVaultProxySkillsResponse{Skills: f.skills})
	default:
		http.NotFound(w, r)
	}
}

func newSkillsProxy(t *testing.T) *proxyServer {
	t.Helper()
	resolver, err := newInfisicalResolver(func() string { return "ptok" })
	if err != nil {
		t.Fatal(err)
	}
	ps := &proxyServer{skillsSource: resolver}
	ps.cache = newSessionCache(resolver, ps.pollInterval)
	return ps
}

func skillsRequest(ps *proxyServer, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(ProxyAuthUsername+":"+token)))
	}
	rec := httptest.NewRecorder()
	ps.dispatch(rec, req)
	return rec
}

func TestSkillFilesSha256MatchesJSONStringify(t *testing.T) {
	files := []api.AgentVaultSkillFile{
		{Path: "z.sh", Mode: "0755", ContentBase64: "eA=="},
		{Path: "a<&> \"\\\n.md", Mode: "0644", ContentBase64: "eQ=="},
	}
	// What JSON.stringify(sortedFiles) prints for the same input.
	stringified := `[{"path":"a<&>` + " " + `\"\\\n.md","mode":"0644","contentBase64":"eQ=="},{"path":"z.sh","mode":"0755","contentBase64":"eA=="}]`
	sum := sha256.Sum256([]byte(stringified))
	if got, want := SkillFilesSha256(files), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("hash %s, want %s", got, want)
	}
	if files[0].Path != "z.sh" {
		t.Fatal("hashing reordered the caller's slice")
	}
}

// U+FF5A sorts after an astral character in UTF-16 but before it in UTF-8, and Infisical sorts by UTF-8 bytes.
func TestSkillFilesSha256SortsByUTF8Bytes(t *testing.T) {
	files := []api.AgentVaultSkillFile{
		{Path: "\U0001D49C.md", Mode: "0644", ContentBase64: "eA=="},
		{Path: "ｚ.md", Mode: "0644", ContentBase64: "eQ=="},
	}
	stringified := `[{"path":"` + "ｚ" + `.md","mode":"0644","contentBase64":"eQ=="},{"path":"` + "\U0001D49C" + `.md","mode":"0644","contentBase64":"eA=="}]`
	sum := sha256.Sum256([]byte(stringified))
	if got, want := SkillFilesSha256(files), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("hash %s, want %s", got, want)
	}
}

func TestSkillsAreFetchedFromInfisicalOnEveryRequest(t *testing.T) {
	f := newFakeInfisical(t)
	files := []api.AgentVaultSkillFile{{Path: "SKILL.md", Mode: "0644", ContentBase64: "eA=="}}
	f.skills = []api.AgentVaultProxySkill{{ID: testSkillID, Name: "code-review", Version: 2, Sha256: SkillFilesSha256(files), Files: files}}
	ps := newSkillsProxy(t)

	for i := 0; i < 2; i++ {
		rec := skillsRequest(ps, http.MethodGet, SkillsPath, "tok")
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		var body api.AgentVaultProxySkillsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Skills) != 1 || body.Skills[0].Version != 2 || len(body.Skills[0].Files) != 1 ||
			body.Skills[0].Sha256 != SkillFilesSha256(body.Skills[0].Files) {
			t.Fatalf("unexpected body %+v", body)
		}
	}
	if got := f.hitCount("list"); got != 2 {
		t.Fatalf("the proxy must not cache skills; Infisical was asked %d times for 2 requests", got)
	}
	if got := f.hitCount("resolve"); got != 1 {
		t.Fatalf("the session should be validated through the cache, resolved %d times", got)
	}
}

func TestSkillsWithNoneAttachedIsAnEmptyList(t *testing.T) {
	newFakeInfisical(t)
	rec := skillsRequest(newSkillsProxy(t), http.MethodGet, SkillsPath, "tok")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"skills":[]`) {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
}

func TestSkillsStatusMapping(t *testing.T) {
	routeMissing := map[string]any{"statusCode": 404, "message": "Route GET:/x not found", "error": "Not Found", "documentationUrl": "https://infisical.com/docs/api-reference"}
	cases := []struct {
		name   string
		setup  func(f *fakeInfisical)
		token  string
		method string
		want   int
	}{
		{"no token", func(*fakeInfisical) {}, "", http.MethodGet, http.StatusProxyAuthRequired},
		{"not a GET", func(*fakeInfisical) {}, "tok", http.MethodPost, http.StatusMethodNotAllowed},
		{"Infisical has no skills route", func(f *fakeInfisical) { f.listCode, f.listBody = 404, routeMissing }, "tok", http.MethodGet, http.StatusNotImplemented},
		{"session gone at resolve", func(f *fakeInfisical) { f.resolveCode, f.resolveName = 401, infisicalUnauthorizedName }, "tok", http.MethodGet, http.StatusForbidden},
		{"session gone at skills", func(f *fakeInfisical) {
			f.listCode, f.listBody = 404, map[string]any{"statusCode": 404, "message": "Session not found", "error": infisicalNotFoundName}
		}, "tok", http.MethodGet, http.StatusForbidden},
		{"proxy revoked", func(f *fakeInfisical) { f.resolveCode, f.resolveName = 401, proxyTokenRejectedName }, "tok", http.MethodGet, http.StatusServiceUnavailable},
		{"a middlebox 404", func(f *fakeInfisical) { f.listCode, f.listBody = 404, map[string]any{"error": "Not Found"} }, "tok", http.MethodGet, http.StatusBadGateway},
		{"Infisical failing", func(f *fakeInfisical) {
			f.listCode, f.listBody = 500, map[string]any{"statusCode": 500, "error": "InternalServerError"}
		}, "tok", http.MethodGet, http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeInfisical(t)
			tc.setup(f)
			rec := skillsRequest(newSkillsProxy(t), tc.method, SkillsPath, tc.token)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.want, rec.Body)
			}
			if tc.want == http.StatusNotImplemented && !strings.Contains(rec.Body.String(), skillsUnsupportedBody) {
				t.Fatalf("501 body %q", rec.Body)
			}
		})
	}
}

func TestSkillsSubpathsAreNotEndpoints(t *testing.T) {
	newFakeInfisical(t)
	ps := newSkillsProxy(t)
	if rec := skillsRequest(ps, http.MethodGet, SkillsPath+"/"+testSkillID+"/versions/1", "tok"); rec.Code != http.StatusNotFound {
		t.Fatalf("the removed version route answered %d", rec.Code)
	}
}
