package agentvault

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
)

const streamableAccept = "application/json, text/event-stream"

func TestResolveReadsTheToolAllowlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"sessionId":"s1","services":[
			{"id":"1","name":"listed","type":"mcp","hostPattern":"a.example","credential":{"type":"passthrough"},"allowedTools":["read_file","Read_File"]},
			{"id":"2","name":"null","type":"mcp","hostPattern":"b.example","credential":{"type":"passthrough"},"allowedTools":null},
			{"id":"3","name":"older","type":"mcp","hostPattern":"c.example","credential":{"type":"passthrough"}},
			{"id":"4","name":"empty","type":"mcp","hostPattern":"d.example","credential":{"type":"passthrough"},"allowedTools":[]}
		]}`)
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
	if got := res.Services[0].allowedTools; !reflect.DeepEqual(got, map[string]bool{"read_file": true, "Read_File": true}) {
		t.Fatalf("listed = %v", got)
	}
	if res.Services[1].allowedTools != nil || res.Services[2].allowedTools != nil {
		t.Fatalf("null and missing must mean every tool, got %v and %v", res.Services[1].allowedTools, res.Services[2].allowedTools)
	}
	if got := res.Services[3].allowedTools; got == nil || len(got) != 0 {
		t.Fatalf("an empty list must allow no tool, got %v", got)
	}
}

func allowlistedMCPService(host string, tools ...string) *resolvedService {
	svc := mcpService(host)
	svc.name = "github-mcp"
	svc.allowedTools = toToolSet(tools)
	return svc
}

type proxiedResponse struct {
	status int
	header http.Header
	body   string
}

func proxiedPost(t *testing.T, client *http.Client, target, contentType, body string, header http.Header) proxiedResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
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
	defer res.Body.Close()
	got, _ := io.ReadAll(res.Body)
	return proxiedResponse{status: res.StatusCode, header: res.Header, body: string(got)}
}

func assertUpstreamSawNothing(t *testing.T, up *mcpUpstream) {
	t.Helper()
	select {
	case got := <-up.bodies:
		t.Fatalf("the upstream received a refused request: %s", got)
	default:
	}
}

func TestAListedToolCallIsForwarded(t *testing.T) {
	up := newMCPUpstream(t)
	client, log := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "read_file")})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`
	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json", body, http.Header{"Accept": {streamableAccept}})
	if res.status != http.StatusOK {
		t.Fatalf("status %d", res.status)
	}
	if got := <-up.bodies; string(got) != body {
		t.Fatalf("upstream body changed: %s", got)
	}
	if got := <-up.auth; got != "Bearer real-oauth-token" {
		t.Fatalf("credential was not injected, upstream saw %q", got)
	}
	rec := drainOneRecord(t, log)
	if rec.Decision != decisionBrokered || !reflect.DeepEqual(rec.MCP, &mcpDetail{Calls: []mcpCall{{Method: "tools/call", Tool: "read_file"}}, Parsed: true}) {
		t.Fatalf("record = %s", recordJSON(t, rec))
	}
}

func TestAnUnlistedToolCallIsRefusedWithItsID(t *testing.T) {
	up := newMCPUpstream(t)
	client, log := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "read_file")})

	body := `{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"delete_repo","arguments":{}}}`
	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json", body, http.Header{"Accept": {streamableAccept}})
	assertUpstreamSawNothing(t, up)

	if res.status != http.StatusOK || res.header.Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, content type %q", res.status, res.header.Get("Content-Type"))
	}
	want := `{"jsonrpc":"2.0","id":"abc","error":{"code":-32602,"message":"Tool \"delete_repo\" isn't allowed on service \"github-mcp\". An admin controls which tools this service allows in Agent Vault."}}`
	if res.body != want {
		t.Fatalf("body is\n%s\nwant\n%s", res.body, want)
	}

	rec := drainOneRecord(t, log)
	if rec.Decision != decisionBlocked || rec.Status != http.StatusOK {
		t.Fatalf("record = %s", recordJSON(t, rec))
	}
	if !reflect.DeepEqual(rec.MCP, &mcpDetail{Calls: []mcpCall{{Method: "tools/call", Tool: "delete_repo"}}, Parsed: true}) {
		t.Fatalf("mcp = %+v", rec.MCP)
	}
}

func TestALegacySSEPostIsRefusedWithAFailedStatus(t *testing.T) {
	up := newMCPUpstream(t)
	client, _ := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "read_file")})

	body := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_repo"}}`
	res := proxiedPost(t, client, up.server.URL+"/messages?sessionId=x", "application/json", body, nil)
	assertUpstreamSawNothing(t, up)
	if res.status != http.StatusForbidden || !strings.Contains(res.body, `"id":4`) || !strings.Contains(res.body, `delete_repo`) {
		t.Fatalf("status %d body %s", res.status, res.body)
	}
}

func TestEnforcementDoesNotNeedSessionLogs(t *testing.T) {
	up := newMCPUpstream(t)
	_, client := newTLSProxy(t, up.server, fixedResolver{services: []*resolvedService{allowlistedMCPService(up.host(), "read_file")}})

	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`, http.Header{"Accept": {streamableAccept}})
	assertUpstreamSawNothing(t, up)
	if res.status != http.StatusOK || !strings.Contains(res.body, `"code":-32602`) {
		t.Fatalf("status %d body %s", res.status, res.body)
	}
}

func TestABatchWithAnUnlistedCallIsRefusedWhole(t *testing.T) {
	up := newMCPUpstream(t)
	client, _ := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "read_file")})

	calls := make([]string, 0, 12)
	for i := 0; i < 10; i++ {
		calls = append(calls, `{"jsonrpc":"2.0","method":"notifications/progress"}`)
	}
	calls = append(calls,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_repo"}}`,
	)
	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json", "["+strings.Join(calls, ",")+"]", http.Header{"Accept": {streamableAccept}})
	assertUpstreamSawNothing(t, up)

	var got []jsonrpcErrorResponse
	if err := json.Unmarshal([]byte(res.body), &got); err != nil {
		t.Fatalf("status %d body %s: %v", res.status, res.body, err)
	}
	if res.status != http.StatusOK || len(got) != 3 {
		t.Fatalf("status %d, %d errors, want 3: %s", res.status, len(got), res.body)
	}
	for i, wantID := range []string{"1", "2", "3"} {
		// Only the call that was refused names the tool, so the answer does not grow with the name times the batch.
		namesTool := strings.Contains(got[i].Error.Message, `"delete_repo"`)
		if string(got[i].ID) != wantID || got[i].Error.Code != jsonrpcInvalidParams || namesTool != (wantID == "3") ||
			!strings.Contains(got[i].Error.Message, "isn't allowed") {
			t.Fatalf("error %d = %+v", i, got[i])
		}
	}
}

func TestAnUnlistedNotificationGetsNoAnswer(t *testing.T) {
	up := newMCPUpstream(t)
	client, _ := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "read_file")})

	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json",
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_repo"}}`, http.Header{"Accept": {streamableAccept}})
	assertUpstreamSawNothing(t, up)
	if res.status != http.StatusAccepted || res.body != "" {
		t.Fatalf("status %d body %q", res.status, res.body)
	}
}

func gzipped(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = io.WriteString(zw, s)
	_ = zw.Close()
	return buf.String()
}

func TestABodyTheProxyCannotReadIsRefusedOnlyUnderAnAllowlist(t *testing.T) {
	listed := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`
	cases := []struct {
		name        string
		body        string
		contentType string
		header      http.Header
	}{
		{"gzip", gzipped(t, listed), "application/json", http.Header{"Content-Encoding": {"gzip"}}},
		{"text/plain holding malformed JSON-RPC", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","name":"delete_repo"}}`, "text/plain", nil},
		{"duplicate name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","name":"delete_repo"}}`, "application/json", nil},
		{"case-variant key", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","Name":"delete_repo"}}`, "application/json", nil},
		{"case-variant id", `{"jsonrpc":"2.0","Id":1,"method":"tools/call","params":{"name":"delete_repo"}}`, "application/json", nil},
		{"duplicate id", `{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":{"name":"delete_repo"}}`, "application/json", nil},
		{"trailing content", listed + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repo"}}`, "application/json", nil},
		{"tool name not a string", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":["delete_repo"]}}`, "application/json", nil},
		{"tool call naming no tool", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`, "application/json", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newMCPUpstream(t)
			client, log := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "read_file")})

			res := proxiedPost(t, client, up.server.URL+"/mcp", tc.contentType, tc.body, tc.header)
			assertUpstreamSawNothing(t, up)
			var got jsonrpcErrorResponse
			if err := json.Unmarshal([]byte(res.body), &got); err != nil {
				t.Fatalf("status %d body %s: %v", res.status, res.body, err)
			}
			if res.status != http.StatusBadRequest || string(got.ID) != "null" || got.Error.Code != jsonrpcInvalidRequest ||
				!strings.Contains(got.Error.Message, `"github-mcp"`) {
				t.Fatalf("status %d body %s", res.status, res.body)
			}
			if rec := drainOneRecord(t, log); rec.Decision != decisionBlocked {
				t.Fatalf("record = %s", recordJSON(t, rec))
			}
		})
		t.Run(tc.name+" without an allowlist", func(t *testing.T) {
			up := newMCPUpstream(t)
			client, _ := newMCPRecordingProxy(t, up, []*resolvedService{mcpService(up.host())})

			res := proxiedPost(t, client, up.server.URL+"/mcp", tc.contentType, tc.body, tc.header)
			if res.status != http.StatusOK {
				t.Fatalf("status %d body %s", res.status, res.body)
			}
			if got := <-up.bodies; string(got) != tc.body {
				t.Fatalf("upstream body changed (%d bytes, sent %d)", len(got), len(tc.body))
			}
		})
	}
}

func TestABodyIsCheckedWhateverItsContentType(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		contentType string
		// 0 when the body must reach the upstream unchanged.
		refusedWith int
	}{
		{"form-encoded token request", "grant_type=refresh_token&refresh_token=abc&client_id=agent", "application/x-www-form-urlencoded", 0},
		{"listed call as text/plain", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`, "text/plain", 0},
		{"unlisted call as text/plain", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`, "text/plain", http.StatusOK},
		{"call after a byte order mark as a form", " \xef\xbb\xbf[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\"}}]", "application/x-www-form-urlencoded", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newMCPUpstream(t)
			client, _ := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "read_file")})

			res := proxiedPost(t, client, up.server.URL+"/token", tc.contentType, tc.body, http.Header{"Accept": {streamableAccept}})
			if tc.refusedWith != 0 {
				assertUpstreamSawNothing(t, up)
				if res.status != tc.refusedWith || !strings.Contains(res.body, `\"github-mcp\"`) {
					t.Fatalf("status %d body %s", res.status, res.body)
				}
				return
			}
			if res.status != http.StatusOK {
				t.Fatalf("status %d body %s", res.status, res.body)
			}
			if got := <-up.bodies; string(got) != tc.body {
				t.Fatalf("upstream body changed: %s", got)
			}
		})
	}
}

func TestABodyOverTheCapIsRefused(t *testing.T) {
	up := newMCPUpstream(t)
	client, log := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "write_file")})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"x":"` + strings.Repeat("x", maxToolsAllowlistBody) + `"}}}`
	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json", body, http.Header{"Accept": {streamableAccept}})
	assertUpstreamSawNothing(t, up)
	var got jsonrpcErrorResponse
	if err := json.Unmarshal([]byte(res.body), &got); err != nil {
		t.Fatalf("status %d body %s: %v", res.status, res.body, err)
	}
	if res.status != http.StatusRequestEntityTooLarge || !strings.Contains(got.Error.Message, "32 MiB") {
		t.Fatalf("status %d body %s", res.status, res.body)
	}
	if rec := drainOneRecord(t, log); rec.Decision != decisionBlocked {
		t.Fatalf("record = %s", recordJSON(t, rec))
	}

	// Without a length, so the cap is found by reading rather than from Content-Length.
	chunked := proxiedDo(t, client, http.MethodPost, up.server.URL+"/mcp", "application/json",
		io.MultiReader(strings.NewReader(body)), http.Header{"Accept": {streamableAccept}})
	assertUpstreamSawNothing(t, up)
	if chunked.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked status %d", chunked.StatusCode)
	}
}

func TestAnEmptyAllowlistAllowsNoTool(t *testing.T) {
	up := newMCPUpstream(t)
	svc := allowlistedMCPService(up.host())
	svc.allowedTools = toToolSet([]string{})
	client, _ := newMCPRecordingProxy(t, up, []*resolvedService{svc})

	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`, http.Header{"Accept": {streamableAccept}})
	assertUpstreamSawNothing(t, up)
	if res.status != http.StatusOK || !strings.Contains(res.body, `"code":-32602`) {
		t.Fatalf("status %d body %s", res.status, res.body)
	}

	resp := jsonResponse(toolsListResult, nil)
	hideUnlistedTools(resp, svc.allowedTools)
	if got := readResponse(t, resp); got != `{"id":3,"jsonrpc":"2.0","result":{"nextCursor":"page-2","tools":[]}}` {
		t.Fatalf("got %s", got)
	}
}

func TestALargeListedCallIsForwarded(t *testing.T) {
	up := newMCPUpstream(t)
	client, log := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "write_file")})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"x":"` + strings.Repeat("x", 2*maxMCPInspectBody) + `"}}}`
	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json", body, http.Header{"Accept": {streamableAccept}})
	if res.status != http.StatusOK {
		t.Fatalf("status %d body %s", res.status, res.body)
	}
	if got := <-up.bodies; string(got) != body {
		t.Fatalf("upstream body changed (%d bytes, sent %d)", len(got), len(body))
	}
	if rec := drainOneRecord(t, log); rec.Decision != decisionBrokered {
		t.Fatalf("record = %s", recordJSON(t, rec))
	}
}

func TestAListedNameOutsideTheLogPatternCanBeCalled(t *testing.T) {
	up := newMCPUpstream(t)
	client, log := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "query+sum")})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query+sum"}}`
	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json", body, http.Header{"Accept": {streamableAccept}})
	if res.status != http.StatusOK {
		t.Fatalf("status %d body %s", res.status, res.body)
	}
	if got := <-up.bodies; string(got) != body {
		t.Fatalf("upstream body changed: %s", got)
	}
	if rec := drainOneRecord(t, log); !reflect.DeepEqual(rec.MCP, unparsedMCP()) {
		t.Fatalf("a name the log cannot hold must leave the record unparsed: %s", recordJSON(t, rec))
	}
}

func TestABodyOnAnotherMethodIsRefusedUnderAnAllowlist(t *testing.T) {
	up := newMCPUpstream(t)
	client, _ := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "read_file")})

	res := proxiedDo(t, client, http.MethodPut, up.server.URL+"/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`), nil)
	assertUpstreamSawNothing(t, up)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", res.StatusCode)
	}

	res = proxiedDo(t, client, http.MethodGet, up.server.URL+"/mcp", "", nil, http.Header{"Accept": {"text/event-stream"}})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a GET without a body must pass, status %d", res.StatusCode)
	}
	<-up.bodies
}

func TestAJSONOnlyAcceptIsTreatedAsLegacySSE(t *testing.T) {
	up := newMCPUpstream(t)
	client, _ := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "read_file")})

	res := proxiedPost(t, client, up.server.URL+"/messages?sessionId=x", "application/json",
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_repo"}}`, http.Header{"Accept": {"application/json"}})
	assertUpstreamSawNothing(t, up)
	if res.status != http.StatusForbidden {
		t.Fatalf("status %d body %s", res.status, res.body)
	}
}

func TestABodySubstitutionIsRecheckedAgainstTheAllowlist(t *testing.T) {
	up := newMCPUpstream(t)
	svc := allowlistedMCPService(up.host(), "read_file")
	svc.substitutions = []substitution{subOn("read_file", "delete_repo", surfaceBody)}
	client, log := newMCPRecordingProxy(t, up, []*resolvedService{svc})

	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`, http.Header{"Accept": {streamableAccept}})
	assertUpstreamSawNothing(t, up)
	if res.status != http.StatusForbidden || strings.Contains(res.body, "delete_repo") {
		t.Fatalf("status %d body %s", res.status, res.body)
	}
	if rec := drainOneRecord(t, log); rec.Decision != decisionBlocked {
		t.Fatalf("record = %s", recordJSON(t, rec))
	}
}

func TestOtherMethodsPassUnderAnAllowlist(t *testing.T) {
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"delete_repo"}}`,
		`{"jsonrpc":"2.0","id":6,"result":{}}`,
	} {
		up := newMCPUpstream(t)
		client, _ := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "read_file")})
		res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json", body, http.Header{"Accept": {streamableAccept}})
		if res.status != http.StatusOK {
			t.Fatalf("%s: status %d body %s", body, res.status, res.body)
		}
		if got := <-up.bodies; string(got) != body {
			t.Fatalf("upstream body changed: %s", got)
		}
	}
}

const toolsListResult = `{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"read_file","description":"Reads <a> file & more"},{"name":"delete_repo"},{"name":"search","inputSchema":{"type":"object"}}],"nextCursor":"page-2"}}`

func jsonResponse(body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	if header.Get("Content-Type") == "" {
		header.Set("Content-Type", "application/json")
	}
	header.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func readResponse(t *testing.T, resp *http.Response) string {
	t.Helper()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func TestToolsListResultsHideUnlistedTools(t *testing.T) {
	allowed := toToolSet([]string{"read_file", "search"})
	wantFiltered := `{"id":3,"jsonrpc":"2.0","result":{"nextCursor":"page-2","tools":[{"name":"read_file","description":"Reads <a> file & more"},{"name":"search","inputSchema":{"type":"object"}}]}}`

	t.Run("json", func(t *testing.T) {
		resp := jsonResponse(toolsListResult, nil)
		hideUnlistedTools(resp, allowed)
		got := readResponse(t, resp)
		if got != wantFiltered {
			t.Fatalf("got\n%s\nwant\n%s", got, wantFiltered)
		}
		if resp.Header.Get("Content-Length") != strconv.Itoa(len(got)) || resp.ContentLength != int64(len(got)) {
			t.Fatalf("content length %q / %d for %d bytes", resp.Header.Get("Content-Length"), resp.ContentLength, len(got))
		}
	})

	t.Run("json batch", func(t *testing.T) {
		resp := jsonResponse(`[{"jsonrpc":"2.0","id":1,"result":{}},`+toolsListResult+`]`, nil)
		hideUnlistedTools(resp, allowed)
		if got := readResponse(t, resp); got != `[{"jsonrpc":"2.0","id":1,"result":{}},`+wantFiltered+`]` {
			t.Fatalf("got %s", got)
		}
	})

	for name, body := range map[string]string{
		"nothing to hide": `{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"read_file"}]}}`,
		"not a result":    `{"jsonrpc":"2.0","id":3,"error":{"code":1,"message":"tools"}}`,
		"not json":        `{"tools":[`,
	} {
		t.Run(name, func(t *testing.T) {
			resp := jsonResponse(body, nil)
			hideUnlistedTools(resp, allowed)
			if got := readResponse(t, resp); got != body {
				t.Fatalf("got %s", got)
			}
		})
	}

	t.Run("a tool without a readable name is dropped", func(t *testing.T) {
		resp := jsonResponse(`{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"read_file"},{"name":"delete_repo"},{"title":"x"},7]}}`, nil)
		hideUnlistedTools(resp, allowed)
		if got := readResponse(t, resp); got != `{"id":3,"jsonrpc":"2.0","result":{"tools":[{"name":"read_file"}]}}` {
			t.Fatalf("got %s", got)
		}
	})

	t.Run("compressed passes through", func(t *testing.T) {
		zipped := gzipped(t, toolsListResult)
		resp := jsonResponse(zipped, http.Header{"Content-Encoding": {"gzip"}})
		hideUnlistedTools(resp, allowed)
		if got := readResponse(t, resp); got != zipped {
			t.Fatal("a compressed body was changed")
		}
	})

	t.Run("over the cap passes through", func(t *testing.T) {
		big := `{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"delete_repo","description":"` + strings.Repeat("x", maxToolsListRewrite) + `"}]}}`
		resp := jsonResponse(big, nil)
		hideUnlistedTools(resp, allowed)
		if got := readResponse(t, resp); got != big {
			t.Fatal("an oversized body was changed")
		}
	})

	t.Run("sse event", func(t *testing.T) {
		stream := ": keepalive\n\nevent: message\nid: 9\ndata: " + toolsListResult + "\n\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n"
		resp := jsonResponse(stream, http.Header{"Content-Type": {"text/event-stream"}})
		hideUnlistedTools(resp, allowed)
		want := ": keepalive\n\nevent: message\nid: 9\ndata: " + wantFiltered + "\n\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n"
		if got := readResponse(t, resp); got != want {
			t.Fatalf("got\n%q\nwant\n%q", got, want)
		}
		if resp.Header.Get("Content-Length") != "" || resp.ContentLength != -1 {
			t.Fatal("a rewritten stream kept its content length")
		}
	})

	t.Run("sse data split over lines", func(t *testing.T) {
		split := strings.Replace(toolsListResult, `,"nextCursor"`, "\ndata: ,\"nextCursor\"", 1)
		resp := jsonResponse("data: "+split+"\r\n\r\n", http.Header{"Content-Type": {"text/event-stream"}})
		hideUnlistedTools(resp, allowed)
		if got := readResponse(t, resp); got != "data: "+wantFiltered+"\n\r\n" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("escaped tools key", func(t *testing.T) {
		escaped := `{"jsonrpc":"2.0","id":3,"result":{"\u0074ools":[{"name":"read_file"},{"name":"delete_repo"}]}}`
		want := `{"id":3,"jsonrpc":"2.0","result":{"tools":[{"name":"read_file"}]}}`
		resp := jsonResponse(escaped, nil)
		hideUnlistedTools(resp, allowed)
		if got := readResponse(t, resp); got != want {
			t.Fatalf("json: got %s", got)
		}
		resp = jsonResponse("data: "+escaped+"\n\n", http.Header{"Content-Type": {"text/event-stream"}})
		hideUnlistedTools(resp, allowed)
		if got := readResponse(t, resp); got != "data: "+want+"\n\n" {
			t.Fatalf("sse: got %q", got)
		}
	})

	t.Run("sse lines ended by a bare CR", func(t *testing.T) {
		resp := jsonResponse(": ping\revent: message\rdata: "+toolsListResult+"\r\r", http.Header{"Content-Type": {"text/event-stream"}})
		hideUnlistedTools(resp, allowed)
		if got := readResponse(t, resp); got != ": ping\revent: message\rdata: "+wantFiltered+"\n\r" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("oversized sse event passes through", func(t *testing.T) {
		big := "data: " + `{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"delete_repo","description":"` + strings.Repeat("x", maxToolsListRewrite) + `"}]}}` + "\n\n"
		stream := big + "data: " + toolsListResult + "\n\n"
		resp := jsonResponse(stream, http.Header{"Content-Type": {"text/event-stream"}})
		hideUnlistedTools(resp, allowed)
		if got := readResponse(t, resp); got != big+"data: "+wantFiltered+"\n\n" {
			t.Fatalf("got %d bytes; the oversized event must pass unchanged and the next one still be filtered", len(got))
		}
	})
}

func TestAFilteredStreamHandsOnEachEventAsItArrives(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	resp := &http.Response{Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: pr}
	hideUnlistedTools(resp, toToolSet([]string{"read_file"}))

	go func() { _, _ = io.WriteString(pw, "data: "+toolsListResult+"\n\n") }()

	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		got <- string(buf[:n])
	}()
	select {
	case event := <-got:
		if !strings.Contains(event, "read_file") || strings.Contains(event, "delete_repo") {
			t.Fatalf("event = %s", event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first event was held back waiting for more of the stream")
	}
}

// A CR may end a line on its own, so an event ended by CRs is handed on without waiting for an LF that may
// never come, and an LF that does come next is kept with its CR rather than read as a blank line.
func TestAFilteredStreamHandsOnACREndedEventAtOnce(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	resp := &http.Response{Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: pr}
	hideUnlistedTools(resp, toToolSet([]string{"read_file"}))

	writes := []string{"data: " + toolsListResult + "\r", "\r", "\ndata: " + toolsListResult + "\r", "\n\r\n"}
	go func() {
		for _, w := range writes {
			_, _ = io.WriteString(pw, w)
		}
	}()

	got := make(chan string, 1)
	go func() {
		var all []byte
		buf := make([]byte, 4096)
		for strings.Count(string(all), "read_file") < 2 {
			n, err := resp.Body.Read(buf)
			all = append(all, buf[:n]...)
			if err != nil {
				break
			}
		}
		got <- string(all)
	}()
	select {
	case stream := <-got:
		if strings.Contains(stream, "delete_repo") || strings.Count(stream, "read_file") != 2 {
			t.Fatalf("stream = %q", stream)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an event ended by CRs was held back waiting for more of the stream")
	}
}

func TestAFilteredStreamHandsOnAKeepaliveAtOnce(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	resp := &http.Response{Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: pr}
	hideUnlistedTools(resp, toToolSet([]string{"read_file"}))

	go func() { _, _ = io.WriteString(pw, ": ping\n") }()

	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		got <- string(buf[:n])
	}()
	select {
	case line := <-got:
		if line != ": ping\n" {
			t.Fatalf("got %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the keepalive was held back waiting for a blank line")
	}
}

func TestACompressingUpstreamIsStillFiltered(t *testing.T) {
	sawEncoding := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawEncoding <- r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, gzipped(t, toolsListResult))
	}))
	t.Cleanup(upstream.Close)
	host := strings.TrimPrefix(upstream.URL, "https://")
	_, client := newTLSProxy(t, upstream, fixedResolver{services: []*resolvedService{allowlistedMCPService(host, "read_file")}})

	res := proxiedPost(t, client, upstream.URL+"/mcp", "application/json", `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		http.Header{"Accept": {streamableAccept}, "Accept-Encoding": {"br, deflate"}})
	if got := <-sawEncoding; got != "gzip" {
		t.Fatalf("upstream saw Accept-Encoding %q, want the transport's own gzip", got)
	}
	if res.status != http.StatusOK || !strings.Contains(res.body, `"read_file"`) || strings.Contains(res.body, "delete_repo") {
		t.Fatalf("status %d body %s", res.status, res.body)
	}
}

func TestToolsListIsFilteredThroughTheProxy(t *testing.T) {
	for _, contentType := range []string{"application/json", "text/event-stream"} {
		t.Run(contentType, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", contentType)
				if contentType == "application/json" {
					w.Header().Set("Content-Length", strconv.Itoa(len(toolsListResult)))
					_, _ = io.WriteString(w, toolsListResult)
					return
				}
				_, _ = io.WriteString(w, "event: message\ndata: "+toolsListResult+"\n\n")
			}))
			t.Cleanup(upstream.Close)
			host := strings.TrimPrefix(upstream.URL, "https://")
			_, client := newTLSProxy(t, upstream, fixedResolver{services: []*resolvedService{allowlistedMCPService(host, "read_file")}})

			res := proxiedPost(t, client, upstream.URL+"/mcp", "application/json", `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, http.Header{"Accept": {streamableAccept}})
			if res.status != http.StatusOK || !strings.Contains(res.body, `"read_file"`) || strings.Contains(res.body, "delete_repo") ||
				strings.Contains(res.body, `"search"`) || !strings.Contains(res.body, `"nextCursor":"page-2"`) {
				t.Fatalf("status %d body %s", res.status, res.body)
			}
		})
	}
}
