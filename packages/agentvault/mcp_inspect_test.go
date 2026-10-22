package agentvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
)

func TestParseJSONRPCCalls(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		parsed bool
		calls  []mcpCall
	}{
		{"single request", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, true, []mcpCall{{Method: "tools/list"}}},
		{"tool call names the tool", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_issue","arguments":{"title":"x"}}}`, true,
			[]mcpCall{{Method: "tools/call", Tool: "create_issue"}}},
		{"params before method", `{"params":{"arguments":{},"name":"search"},"method":"tools/call","id":3}`, true,
			[]mcpCall{{Method: "tools/call", Tool: "search"}}},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, true, []mcpCall{{Method: "notifications/initialized"}}},
		{"name ignored outside tools/call", `{"method":"prompts/get","params":{"name":"greet"}}`, true, []mcpCall{{Method: "prompts/get"}}},
		{"tools/call without params", `{"method":"tools/call","id":1}`, true, []mcpCall{{Method: "tools/call"}}},
		{"batch", `[{"method":"tools/call","params":{"name":"a"}},{"method":"notifications/cancelled"},{"jsonrpc":"2.0","id":9,"result":{}}]`, true,
			[]mcpCall{{Method: "tools/call", Tool: "a"}, {Method: "notifications/cancelled"}}},
		{"response only", `{"jsonrpc":"2.0","id":1,"result":{"method":"tools/call"}}`, true, []mcpCall{}},
		{"empty batch", `[]`, true, []mcpCall{}},
		{"duplicate keys inside arguments are not ours to judge", `{"method":"tools/call","params":{"name":"a","arguments":{"k":1,"k":2}}}`, true,
			[]mcpCall{{Method: "tools/call", Tool: "a"}}},
		{"huge number skipped", `{"method":"ping","id":1e999}`, true, []mcpCall{{Method: "ping"}}},

		{"duplicate method", `{"method":"tools/list","method":"tools/call","params":{"name":"a"}}`, false, nil},
		{"duplicate params", `{"method":"tools/call","params":{"name":"a"},"params":{"name":"b"}}`, false, nil},
		{"duplicate name", `{"method":"tools/call","params":{"name":"a","name":"b"}}`, false, nil},
		{"case variant of method", `{"method":"tools/list","Method":"tools/call"}`, false, nil},
		{"case variant of name", `{"method":"tools/call","params":{"name":"a","NAME":"b"}}`, false, nil},
		{"duplicate in one batch element", `[{"method":"ping"},{"method":"a","method":"b"}]`, false, nil},
		{"method with a space", `{"method":"tools call"}`, false, nil},
		{"tool with a quote", `{"method":"tools/call","params":{"name":"a\"b"}}`, false, nil},
		{"tool too long", `{"method":"tools/call","params":{"name":"` + strings.Repeat("a", 129) + `"}}`, false, nil},
		{"tool not a string", `{"method":"tools/call","params":{"name":{"x":1}}}`, false, nil},
		{"method not a string", `{"method":7}`, false, nil},
		{"malformed", `{"method":"tools/call",`, false, nil},
		{"trailing message", `{"method":"ping"} {"method":"tools/call","params":{"name":"x"}}`, false, nil},
		{"top level scalar", `"tools/call"`, false, nil},
		{"empty", ``, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMCPBody([]byte(tc.body))
			if got.Parsed != tc.parsed {
				t.Fatalf("parsed = %v, want %v (calls %+v)", got.Parsed, tc.parsed, got.Calls)
			}
			want := tc.calls
			if want == nil {
				want = []mcpCall{}
			}
			if !reflect.DeepEqual(got.Calls, want) {
				t.Fatalf("calls = %+v, want %+v", got.Calls, want)
			}
		})
	}
}

func pingBatch(n int, tail ...string) string {
	elems := make([]string, 0, n+len(tail))
	for range n {
		elems = append(elems, `{"method":"ping"}`)
	}
	return "[" + strings.Join(append(elems, tail...), ",") + "]"
}

func TestParseJSONRPCCallsTruncatesLongBatches(t *testing.T) {
	kept := make([]mcpCall, maxMCPCallsPerRecord)
	for i := range kept {
		kept[i] = mcpCall{Method: "ping"}
	}
	cases := []struct {
		name string
		body string
		want *mcpDetail
	}{
		{"exactly the limit", pingBatch(maxMCPCallsPerRecord), &mcpDetail{Calls: kept, Parsed: true}},
		{"one past the limit", pingBatch(maxMCPCallsPerRecord + 1), &mcpDetail{Calls: kept, Parsed: true, Truncated: true}},
		{"far past the limit", pingBatch(100), &mcpDetail{Calls: kept, Parsed: true, Truncated: true}},
		{"responses past the limit are not calls", pingBatch(maxMCPCallsPerRecord, `{"id":1,"result":{}}`), &mcpDetail{Calls: kept, Parsed: true}},
		{"tool call past the limit is still validated", pingBatch(maxMCPCallsPerRecord+5, `{"method":"tools/call","params":{"name":{"x":1}}}`), unparsedMCP()},
		{"duplicate key past the limit", pingBatch(maxMCPCallsPerRecord+1, `{"method":"a","method":"b"}`), unparsedMCP()},
		{"malformed past the limit", pingBatch(maxMCPCallsPerRecord+1, `{"method":`), unparsedMCP()},
		{"trailing content after a long batch", pingBatch(maxMCPCallsPerRecord+1) + ` {"method":"ping"}`, unparsedMCP()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMCPBody([]byte(tc.body))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestMCPDetailOmitsTruncatedWhenFalse(t *testing.T) {
	out, err := json.Marshal(&mcpDetail{Calls: []mcpCall{{Method: "ping"}}, Parsed: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"calls":[{"method":"ping"}],"parsed":true}` {
		t.Fatalf("got %s", out)
	}
	out, err = json.Marshal(parseMCPBody([]byte(pingBatch(maxMCPCallsPerRecord + 1))))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(out, []byte(`"parsed":true,"truncated":true}`)) {
		t.Fatalf("got %s", out)
	}
}

type mcpUpstream struct {
	server *httptest.Server
	bodies chan []byte
	auth   chan string
}

func newMCPUpstream(t *testing.T) *mcpUpstream {
	t.Helper()
	u := &mcpUpstream{bodies: make(chan []byte, 1), auth: make(chan string, 1)}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.bodies <- body
		u.auth <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *mcpUpstream) host() string { return strings.TrimPrefix(u.server.URL, "http://") }

func mcpService(host string, subs ...substitution) *resolvedService {
	svc := policyService(host, nil, nil, nil, subs)
	svc.name = "linear"
	svc.kind = serviceKindMCP
	svc.credential = credential{kind: credentialBearer, headerPrefix: "Bearer", value: []byte("real-oauth-token")}
	return svc
}

func proxiedDo(t *testing.T, front *httptest.Server, method, target, contentType string, body io.Reader, header http.Header) *http.Response {
	t.Helper()
	proxyURL, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("infisical", "agv_test-token")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		req.Header[name] = values
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through the proxy failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return res
}

func recordJSON(t *testing.T, rec sessionLogRecord) string {
	t.Helper()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAnMCPToolCallIsRecordedAndForwardedUnchanged(t *testing.T) {
	up := newMCPUpstream(t)
	front, log, _ := newRecordingProxy(t, TrafficPolicyAnyHost, []*resolvedService{mcpService(up.host())})

	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_issue","arguments":{"title":"Bug","Authorization":"x"}}}`
	proxiedDo(t, front, http.MethodPost, up.server.URL+"/mcp", "application/json; charset=utf-8", strings.NewReader(body), nil)

	if got := <-up.bodies; string(got) != body {
		t.Fatalf("upstream body changed:\n got %s\nwant %s", got, body)
	}
	if got := <-up.auth; got != "Bearer real-oauth-token" {
		t.Fatalf("credential was not injected, upstream saw %q", got)
	}

	rec := drainOneRecord(t, log)
	if rec.ServiceType == nil || *rec.ServiceType != serviceKindMCP {
		t.Fatalf("serviceType = %v", rec.ServiceType)
	}
	want := &mcpDetail{Calls: []mcpCall{{Method: "tools/call", Tool: "create_issue"}}, Parsed: true}
	if !reflect.DeepEqual(rec.MCP, want) {
		t.Fatalf("mcp = %+v, want %+v", rec.MCP, want)
	}
	encoded := recordJSON(t, rec)
	if !strings.Contains(encoded, `"serviceType":"mcp"`) ||
		!strings.Contains(encoded, `"mcp":{"calls":[{"method":"tools/call","tool":"create_issue"}],"parsed":true}`) {
		t.Fatalf("record JSON is %s", encoded)
	}
	for _, leaked := range []string{"real-oauth-token", "Bug", "arguments"} {
		if strings.Contains(encoded, leaked) {
			t.Fatalf("record carries %q: %s", leaked, encoded)
		}
	}
}

func TestAnMCPBatchAndNotificationAreRecorded(t *testing.T) {
	up := newMCPUpstream(t)
	front, log, _ := newRecordingProxy(t, TrafficPolicyAnyHost, []*resolvedService{mcpService(up.host())})

	body := `[{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}]`
	proxiedDo(t, front, http.MethodPost, up.server.URL+"/mcp", "application/json", strings.NewReader(body), nil)
	<-up.bodies

	rec := drainOneRecord(t, log)
	want := &mcpDetail{Calls: []mcpCall{{Method: "notifications/initialized"}, {Method: "tools/call", Tool: "search"}}, Parsed: true}
	if !reflect.DeepEqual(rec.MCP, want) {
		t.Fatalf("mcp = %+v, want %+v", rec.MCP, want)
	}
}

func TestAnMCPBodyTheProxyCannotTrustIsRecordedUnparsedAndForwarded(t *testing.T) {
	oversized := `{"method":"tools/call","params":{"name":"big","arguments":{"blob":"` + strings.Repeat("x", maxMCPInspectBody) + `"}}}`
	cases := []struct {
		name    string
		body    string
		header  http.Header
		chunked bool
	}{
		{"duplicate keys", `{"method":"tools/call","params":{"name":"safe","name":"rm_rf"}}`, nil, false},
		{"malformed", `{"method":"tools/call","params":`, nil, false},
		{"oversized", oversized, nil, false},
		{"oversized and chunked", oversized, nil, true},
		{"encoded", `{"method":"tools/call","params":{"name":"x"}}`, http.Header{"Content-Encoding": {"gzip"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newMCPUpstream(t)
			front, log, _ := newRecordingProxy(t, TrafficPolicyAnyHost, []*resolvedService{mcpService(up.host())})

			var reader io.Reader = strings.NewReader(tc.body)
			if tc.chunked {
				reader = io.MultiReader(reader)
			}
			res := proxiedDo(t, front, http.MethodPost, up.server.URL+"/mcp", "application/json", reader, tc.header)
			if res.StatusCode != http.StatusOK {
				t.Fatalf("status %d; parsing must never block a request", res.StatusCode)
			}
			if got := <-up.bodies; sha256.Sum256(got) != sha256.Sum256([]byte(tc.body)) {
				t.Fatalf("upstream body changed (%d bytes, sent %d)", len(got), len(tc.body))
			}

			rec := drainOneRecord(t, log)
			if !reflect.DeepEqual(rec.MCP, &mcpDetail{Calls: []mcpCall{}, Parsed: false}) {
				t.Fatalf("mcp = %+v", rec.MCP)
			}
			if encoded := recordJSON(t, rec); !strings.Contains(encoded, `"mcp":{"calls":[],"parsed":false}`) {
				t.Fatalf("record JSON is %s", encoded)
			}
		})
	}
}

func TestMCPDetailIsOmittedWhereNoParseIsAttempted(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		contentType string
		body        string
		kind        string
		serviceType string
	}{
		{"GET on an mcp service", http.MethodGet, "", "", serviceKindMCP, serviceKindMCP},
		{"DELETE on an mcp service", http.MethodDelete, "", "", serviceKindMCP, serviceKindMCP},
		{"non-JSON content type", http.MethodPost, "text/plain", `{"method":"tools/call","params":{"name":"x"}}`, serviceKindMCP, serviceKindMCP},
		{"http service", http.MethodPost, "application/json", `{"method":"tools/call","params":{"name":"x"}}`, serviceKindHTTP, serviceKindHTTP},
		{"service with no kind", http.MethodPost, "application/json", `{"method":"tools/call","params":{"name":"x"}}`, "", serviceKindHTTP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newMCPUpstream(t)
			svc := mcpService(up.host())
			svc.kind = tc.kind
			front, log, _ := newRecordingProxy(t, TrafficPolicyAnyHost, []*resolvedService{svc})

			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			proxiedDo(t, front, tc.method, up.server.URL+"/mcp", tc.contentType, body, nil)
			if got := <-up.bodies; string(got) != tc.body {
				t.Fatalf("upstream body changed: %q", got)
			}

			rec := drainOneRecord(t, log)
			if rec.MCP != nil {
				t.Fatalf("mcp = %+v, expected none", rec.MCP)
			}
			if rec.ServiceType == nil || *rec.ServiceType != tc.serviceType {
				t.Fatalf("serviceType = %v, want %q", rec.ServiceType, tc.serviceType)
			}
			if encoded := recordJSON(t, rec); strings.Contains(encoded, `"mcp":`) {
				t.Fatalf("record JSON is %s", encoded)
			}
		})
	}
}

func TestAnUnmatchedHostRecordsANullServiceType(t *testing.T) {
	up := newMCPUpstream(t)
	front, log, _ := newRecordingProxy(t, TrafficPolicyAnyHost, nil)

	body := `{"method":"tools/call","params":{"name":"x"}}`
	proxiedDo(t, front, http.MethodPost, up.server.URL+"/mcp", "application/json", strings.NewReader(body), nil)
	<-up.bodies

	rec := drainOneRecord(t, log)
	if rec.ServiceType != nil || rec.MCP != nil {
		t.Fatalf("passthrough record has serviceType %v and mcp %+v", rec.ServiceType, rec.MCP)
	}
	encoded := recordJSON(t, rec)
	if !strings.Contains(encoded, `"serviceType":null`) || strings.Contains(encoded, `"mcp":`) {
		t.Fatalf("record JSON is %s", encoded)
	}
}

func TestMCPParsingSeesTheBodyBeforeABodySubstitution(t *testing.T) {
	up := newMCPUpstream(t)
	front, log, _ := newRecordingProxy(t, TrafficPolicyAnyHost, []*resolvedService{
		mcpService(up.host(), subOn("__TOOL__", "secret_tool", surfaceBody)),
	})

	body := `{"method":"tools/call","params":{"name":"lookup","arguments":{"key":"__TOOL__"}}}`
	proxiedDo(t, front, http.MethodPost, up.server.URL+"/mcp", "application/json", strings.NewReader(body), nil)

	want := strings.Replace(body, "__TOOL__", "secret_tool", 1)
	if got := <-up.bodies; string(got) != want {
		t.Fatalf("upstream body is %s, want %s", got, want)
	}

	rec := drainOneRecord(t, log)
	if !reflect.DeepEqual(rec.MCP, &mcpDetail{Calls: []mcpCall{{Method: "tools/call", Tool: "lookup"}}, Parsed: true}) {
		t.Fatalf("mcp = %+v", rec.MCP)
	}
	if encoded := recordJSON(t, rec); strings.Contains(encoded, "secret_tool") {
		t.Fatalf("a substituted value reached the record: %s", encoded)
	}
}

func TestASubstitutedToolNameIsLoggedAsTheAgentSentIt(t *testing.T) {
	up := newMCPUpstream(t)
	front, log, _ := newRecordingProxy(t, TrafficPolicyAnyHost, []*resolvedService{
		mcpService(up.host(), subOn("__TOOL__", "secret_tool", surfaceBody)),
	})

	proxiedDo(t, front, http.MethodPost, up.server.URL+"/mcp", "application/json",
		strings.NewReader(`{"method":"tools/call","params":{"name":"__TOOL__"}}`), nil)
	if got := <-up.bodies; !bytes.Contains(got, []byte("secret_tool")) {
		t.Fatalf("the substitution never fired, so this proves nothing: %s", got)
	}

	rec := drainOneRecord(t, log)
	if len(rec.MCP.Calls) != 1 || rec.MCP.Calls[0].Tool != "__TOOL__" {
		t.Fatalf("mcp = %+v", rec.MCP)
	}
}

func TestAnUnreadableMCPBodyIsStillRefusedByABodySubstitution(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.test/mcp", io.MultiReader(strings.NewReader(`{"method"`), erroringReader{io.ErrUnexpectedEOF}))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1

	if got := inspectMCPRequest(req); got == nil || got.Parsed {
		t.Fatalf("mcp = %+v", got)
	}
	if _, err := applySubstitutions(req, "linear", []substitution{subOn("__X__", "y", surfaceBody)}); err != errBodyUnreadable {
		t.Fatalf("err = %v, want errBodyUnreadable", err)
	}
}

func TestResolveMapsTheServiceType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		services := []map[string]any{
			{"id": "1", "name": "linear", "type": "mcp", "hostPattern": "mcp.linear.app", "credential": map[string]any{"type": "passthrough"}},
			{"id": "2", "name": "github", "type": "http", "hostPattern": "api.github.com", "credential": map[string]any{"type": "passthrough"}},
			{"id": "3", "name": "future", "type": "grpc", "hostPattern": "a.example", "credential": map[string]any{"type": "passthrough"}},
			{"id": "4", "name": "older", "hostPattern": "b.example", "credential": map[string]any{"type": "passthrough"}},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sessionId": "s1", "services": services})
	}))
	defer srv.Close()
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	defer func() { config.INFISICAL_URL = old }()

	resolver, err := newInfisicalResolver(func() string { return "ptok" })
	if err != nil {
		t.Fatal(err)
	}
	res, err := resolver.resolve("tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, svc := range res.Services {
		got = append(got, fmt.Sprintf("%s=%s/%s", svc.name, svc.kind, svc.serviceType()))
	}
	want := []string{"linear=mcp/mcp", "github=http/http", "future=http/http", "older=http/http"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("kinds = %v, want %v", got, want)
	}
}
