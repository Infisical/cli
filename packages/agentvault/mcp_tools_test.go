package agentvault

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// An ASCII string as UTF-16, big- or little-endian.
func utf16Body(s string, bigEndian bool) string {
	var buf bytes.Buffer
	for _, c := range []byte(s) {
		if bigEndian {
			buf.Write([]byte{0, c})
		} else {
			buf.Write([]byte{c, 0})
		}
	}
	return buf.String()
}

// An ASCII string as big-endian UTF-32.
func utf32BEBody(s string) string {
	var buf bytes.Buffer
	for _, c := range []byte(s) {
		buf.Write([]byte{0, 0, 0, c})
	}
	return buf.String()
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
		{"UTF-16BE call without a byte order mark", utf16Body(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`, true), "text/plain", http.StatusBadRequest},
		{"UTF-16LE call after a space", utf16Body(` {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`, false), "text/plain", http.StatusBadRequest},
		{"UTF-16LE call after a byte order mark", "\xff\xfe" + utf16Body(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`, false), "text/plain", http.StatusBadRequest},
		{"UTF-32BE call after a byte order mark", "\x00\x00\xfe\xff" + utf32BEBody(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`), "text/plain", http.StatusBadRequest},
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

func TestACharsetOtherThanUTF8IsRefused(t *testing.T) {
	listed := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`
	// Decoded as UTF-7, the string holds a second "name" key that a server keeping the last one would run.
	smuggled := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","x":"+ACI-,+ACI-name+ACI-:+ACI-delete+AF8-repo+ACI-,+ACI-y+ACI-:+ACI-"}}`
	cases := []struct {
		name   string
		body   string
		header http.Header
		// 0 when the body must reach the upstream unchanged.
		refusedWith int
	}{
		{"utf-7", smuggled, http.Header{"Content-Type": {"application/json; charset=utf-7"}}, http.StatusBadRequest},
		{"utf-7-imap", smuggled, http.Header{"Content-Type": {"application/json; charset=UTF-7-IMAP"}}, http.StatusBadRequest},
		{"charset named twice", smuggled, http.Header{"Content-Type": {"application/json; charset=utf-8; charset=utf-7-imap"}}, http.StatusBadRequest},
		{"utf-7 opening brace as text", `+AHs-"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`, http.Header{"Content-Type": {"text/plain; charset=utf-7"}}, http.StatusBadRequest},
		{"utf-8 in the RFC 2231 form", smuggled, http.Header{"Content-Type": {"application/json; charset=utf-7; charset*=utf-8''utf-8"}}, http.StatusBadRequest},
		{"utf-8 as an RFC 2231 continuation", smuggled, http.Header{"Content-Type": {"application/json; charset=utf-7; charset*0=utf-8"}}, http.StatusBadRequest},
		{"asterisk in a quoted value", listed, http.Header{"Content-Type": {`application/json; charset=utf-8; x="a;b*=c"`}}, 0},
		{"us-ascii", listed, http.Header{"Content-Type": {"application/json; charset=us-ascii"}}, http.StatusBadRequest},
		{"two content types", listed, http.Header{"Content-Type": {"application/json", "text/plain; charset=utf-7"}}, http.StatusBadRequest},
		{"upper-case utf-8", listed, http.Header{"Content-Type": {"application/json; charset=UTF-8"}}, 0},
		{"utf8", listed, http.Header{"Content-Type": {"application/json; charset=utf8"}}, 0},
		{"form-encoded token request in utf-8", "grant_type=refresh_token&refresh_token=abc", http.Header{"Content-Type": {"application/x-www-form-urlencoded; charset=UTF-8"}}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newMCPUpstream(t)
			client, _ := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "read_file")})

			tc.header.Set("Accept", streamableAccept)
			res := proxiedPost(t, client, up.server.URL+"/mcp", "", tc.body, tc.header)
			if tc.refusedWith != 0 {
				assertUpstreamSawNothing(t, up)
				if res.status != tc.refusedWith || !strings.Contains(res.body, "UTF-8") {
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

func TestRoutingHeadersMustMatchTheBody(t *testing.T) {
	call := func(tool string) string {
		return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `"}}`
	}
	cases := []struct {
		name        string
		body        string
		contentType string
		header      http.Header
		refused     bool
	}{
		{"name differs", call("read_file"), "application/json", http.Header{"Mcp-Method": {"tools/call"}, "Mcp-Name": {"delete_repo"}}, true},
		{"name alone differs", call("read_file"), "application/json", http.Header{"Mcp-Name": {"delete_repo"}}, true},
		{"method differs", call("read_file"), "application/json", http.Header{"Mcp-Method": {"tools/list"}}, true},
		{"name sent twice", call("read_file"), "application/json", http.Header{"Mcp-Name": {"read_file", "delete_repo"}}, true},
		{"headers on a batch", "[" + call("read_file") + "]", "application/json", http.Header{"Mcp-Name": {"read_file"}}, true},
		{"headers on a body that isn't JSON", "grant_type=x", "application/x-www-form-urlencoded", http.Header{"Mcp-Name": {"delete_repo"}}, true},
		{"headers match", call("read_file"), "application/json", http.Header{"Mcp-Method": {"tools/call"}, "Mcp-Name": {"read_file"}}, false},
		{"name of another method", `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"greet"}}`, "application/json",
			http.Header{"Mcp-Method": {"prompts/get"}, "Mcp-Name": {"greet"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newMCPUpstream(t)
			client, _ := newMCPRecordingProxy(t, up, []*resolvedService{allowlistedMCPService(up.host(), "read_file")})

			tc.header.Set("Accept", streamableAccept)
			res := proxiedPost(t, client, up.server.URL+"/mcp", tc.contentType, tc.body, tc.header)
			if tc.refused {
				assertUpstreamSawNothing(t, up)
				if res.status != http.StatusBadRequest || !strings.Contains(res.body, "Mcp-Name") {
					t.Fatalf("status %d body %s", res.status, res.body)
				}
				return
			}
			if res.status != http.StatusOK {
				t.Fatalf("status %d body %s", res.status, res.body)
			}
			<-up.bodies
		})
	}
}

func TestARefusalCutsALongToolName(t *testing.T) {
	svc := allowlistedMCPService("a.example", "read_file")
	tool := strings.Repeat("\xff", 1<<20)
	refusal := unlistedToolRefusal(svc, tool, []jsonrpcMessage{{mcpCall: mcpCall{Method: mcpMethodToolsCall, Tool: tool}, id: json.RawMessage("1")}}, false, true)
	if len(refusal.reason) > 1024 || len(refusal.body) > 2048 || !strings.Contains(refusal.reason, "[truncated]") {
		t.Fatalf("reason is %d bytes, body %d bytes", len(refusal.reason), len(refusal.body))
	}
}

// A legacy SSE server whose stream stays open until the test ends, and which answers each POST with 202.
func newLegacySSEUpstream(t *testing.T) (*httptest.Server, chan []byte) {
	t.Helper()
	posts := make(chan []byte, 4)
	stop := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "event: endpoint\ndata: /messages?sessionId=abc\n\n")
			w.(http.Flusher).Flush()
			select {
			case <-stop:
			case <-r.Context().Done():
			}
			return
		}
		body, _ := io.ReadAll(r.Body)
		posts <- body
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(func() {
		close(stop)
		upstream.Close()
	})
	return upstream, posts
}

func readSSEEvent(t *testing.T, stream *bufio.Reader) string {
	t.Helper()
	got := make(chan string, 1)
	go func() {
		var event strings.Builder
		for {
			line, err := stream.ReadString('\n')
			event.WriteString(line)
			if err != nil || line == "\n" {
				got <- event.String()
				return
			}
		}
	}()
	select {
	case event := <-got:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("no event arrived on the stream")
		return ""
	}
}

func TestALegacySSERefusalArrivesOnItsStream(t *testing.T) {
	upstream, posts := newLegacySSEUpstream(t)
	host := strings.TrimPrefix(upstream.URL, "https://")
	_, client := newTLSProxy(t, upstream, fixedResolver{services: []*resolvedService{allowlistedMCPService(host, "read_file")}})

	resp, err := client.Get(upstream.URL + "/sse")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	stream := bufio.NewReader(resp.Body)
	if event := readSSEEvent(t, stream); !strings.Contains(event, "/messages?sessionId=abc") {
		t.Fatalf("endpoint event = %q", event)
	}

	refused := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_repo"}}`
	res := proxiedPost(t, client, upstream.URL+"/messages?sessionId=abc", "application/json", refused, nil)
	if res.status != http.StatusAccepted || res.body != "" {
		t.Fatalf("status %d body %s", res.status, res.body)
	}
	event := readSSEEvent(t, stream)
	if !strings.HasPrefix(event, "event: message\ndata: ") || !strings.Contains(event, `"id":4`) || !strings.Contains(event, `delete_repo`) {
		t.Fatalf("event = %q", event)
	}

	listed := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file"}}`
	if res := proxiedPost(t, client, upstream.URL+"/messages?sessionId=abc", "application/json", listed, nil); res.status != http.StatusAccepted {
		t.Fatalf("a listed call after the refusal: status %d body %s", res.status, res.body)
	}
	if got := <-posts; string(got) != listed {
		t.Fatalf("upstream got %s", got)
	}

	// A POST to a URL no open stream announced still gets the 403.
	if res := proxiedPost(t, client, upstream.URL+"/messages?sessionId=other", "application/json", refused, nil); res.status != http.StatusForbidden {
		t.Fatalf("status %d body %s", res.status, res.body)
	}
}

func TestASSERefusalOnlyReachesAStreamOfTheSameSessionAndService(t *testing.T) {
	var registry sseStreamRegistry
	pr, pw := io.Pipe()
	defer pw.Close()
	filter := newSSEToolsFilter(pr, toToolSet([]string{"read_file"}))
	streamURL, _ := url.Parse("https://mcp.example:443/sse")
	registry.watch(filter, "session-a", "svc-1", *streamURL)

	go func() {
		_, _ = io.WriteString(pw, "event: endpoint\ndata: https://MCP.example/messages?sessionId=abc\n\n")
	}()
	if event := readSSEEvent(t, bufio.NewReader(filter)); !strings.Contains(event, "endpoint") {
		t.Fatalf("event = %q", event)
	}

	refusal := func() *mcpToolRefusal {
		return &mcpToolRefusal{status: http.StatusForbidden, overStream: true, streamEvent: []byte("event: message\ndata: {}\n\n")}
	}
	post, _ := url.Parse("https://mcp.example:443/messages?sessionId=abc")
	if got := registry.deliver("session-b", "svc-1", post, refusal()); got.status != http.StatusForbidden {
		t.Fatalf("another session's POST got %d", got.status)
	}
	if got := registry.deliver("session-a", "svc-2", post, refusal()); got.status != http.StatusForbidden {
		t.Fatalf("another service's POST got %d", got.status)
	}
	if got := registry.deliver("session-a", "svc-1", post, refusal()); got.status != http.StatusAccepted {
		t.Fatalf("the stream's own POST got %d", got.status)
	}

	_ = filter.Close()
	if got := registry.deliver("session-a", "svc-1", post, refusal()); got.status != http.StatusForbidden {
		t.Fatalf("a POST after the stream closed got %d", got.status)
	}
}

func TestAStreamOpeningWithAByteOrderMarkIsStillFiltered(t *testing.T) {
	resp := jsonResponse("\xef\xbb\xbfdata: "+toolsListResult+"\n\n", http.Header{"Content-Type": {"text/event-stream"}})
	hideUnlistedTools(resp, toToolSet([]string{"read_file"}))
	if got := readResponse(t, resp); !strings.Contains(got, `"read_file"`) || strings.Contains(got, "delete_repo") {
		t.Fatalf("stream = %q", got)
	}
}

func TestARepeatedEndpointKeepsOneRegistration(t *testing.T) {
	var registry sseStreamRegistry
	pr, pw := io.Pipe()
	defer pw.Close()
	filter := newSSEToolsFilter(pr, toToolSet([]string{"read_file"}))
	streamURL, _ := url.Parse("https://mcp.example:443/sse")
	registry.watch(filter, "session-a", "svc-1", *streamURL)

	stream := bufio.NewReader(filter)
	for i := range 50 {
		// The first event opens the stream with a byte order mark, which must not hide it.
		bom := ""
		if i == 0 {
			bom = "\xef\xbb\xbf"
		}
		go func() {
			_, _ = io.WriteString(pw, bom+"event: endpoint\ndata: /messages?sessionId="+strconv.Itoa(i%2)+"\n\n")
		}()
		readSSEEvent(t, stream)
	}
	registry.mu.Lock()
	n := len(registry.streams)
	registry.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d registrations, want 1", n)
	}
	post, _ := url.Parse("https://mcp.example:443/messages?sessionId=1")
	refusal := &mcpToolRefusal{status: http.StatusForbidden, overStream: true}
	if got := registry.deliver("session-a", "svc-1", post, refusal); got.status != http.StatusAccepted {
		t.Fatalf("the latest endpoint got %d", got.status)
	}
}

func hookedMCPService(host string, hook *serviceHook) *resolvedService {
	svc := mcpService(host)
	svc.name = "github-mcp"
	svc.hook = hook
	return svc
}

func TestEveryMCPRequestAsksTheHook(t *testing.T) {
	fake := newFakeHook(t, answerHook(`{"decision":"allow"}`))
	up := newMCPUpstream(t)
	client, _ := newMCPRecordingProxy(t, up, []*resolvedService{hookedMCPService(up.host(), fake.hook())})

	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	} {
		if res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json", body, http.Header{"Accept": {streamableAccept}}); res.status != http.StatusOK {
			t.Fatalf("status %d", res.status)
		}
		if got := <-up.bodies; string(got) != body {
			t.Fatalf("upstream got %s", got)
		}
		<-up.auth
	}
	calls := fake.calls()
	if len(calls) != 2 {
		t.Fatalf("the hook was asked %d times, want 2", len(calls))
	}
	want := &hookPayloadMCP{Calls: []hookMCPCall{{ID: json.RawMessage("2"), Method: "tools/list"}}, Parsed: true}
	if got := calls[1].payload(t).MCP; !reflect.DeepEqual(got, want) {
		t.Fatalf("mcp = %+v", got)
	}
}

func TestAHookDenialOfAToolCallIsAToolErrorResult(t *testing.T) {
	fake := newFakeHook(t, answerHook(`{"decision":"deny","message":"Ask Ana first.","reason":"needs approval"}`))
	up := newMCPUpstream(t)
	client, log := newMCPRecordingProxy(t, up, []*resolvedService{hookedMCPService(up.host(), fake.hook())})

	body := `{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"merge_pull_request","arguments":{}}}`
	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json", body, http.Header{"Accept": {streamableAccept}})
	assertUpstreamSawNothing(t, up)
	want := `{"jsonrpc":"2.0","id":"abc","result":{"isError":true,"content":[{"type":"text","text":"Ask Ana first."}]}}`
	if res.status != http.StatusOK || res.body != want {
		t.Fatalf("status %d body\n%s\nwant\n%s", res.status, res.body, want)
	}
	if res.header.Get(HeaderError) != errorCodeHookDenied || res.header.Get(HeaderDecision) != decisionBlocked {
		t.Fatalf("headers = %v", res.header)
	}
	if p := fake.only(t).payload(t).MCP; !reflect.DeepEqual(p.Calls, []hookMCPCall{{ID: json.RawMessage(`"abc"`), Method: "tools/call", Tool: "merge_pull_request"}}) {
		t.Fatalf("mcp = %+v", p)
	}
	rec := drainOneRecord(t, log)
	if rec.Decision != decisionBlocked || rec.Hook == nil || rec.Hook.Reason != "needs approval" {
		t.Fatalf("record = %s", recordJSON(t, rec))
	}
}

func TestAHookFailureOnAnotherMCPRequestIsAJSONRPCError(t *testing.T) {
	fake := newFakeHook(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	up := newMCPUpstream(t)
	client, log := newMCPRecordingProxy(t, up, []*resolvedService{hookedMCPService(up.host(), fake.hook())})

	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json", `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`, http.Header{"Accept": {streamableAccept}})
	assertUpstreamSawNothing(t, up)
	want := `{"jsonrpc":"2.0","id":7,"error":{"code":-31000,"message":"` + hookFailedRequestMessage + `"}}`
	if res.status != http.StatusOK || res.body != want {
		t.Fatalf("status %d body %s", res.status, res.body)
	}
	if res.header.Get(HeaderError) != errorCodeHookFailed || res.header.Get(HeaderDecision) != decisionError {
		t.Fatalf("headers = %v", res.header)
	}
	if rec := drainOneRecord(t, log); rec.Decision != decisionError || rec.Hook == nil || rec.Hook.Cause != "status_500" {
		t.Fatalf("record = %s", recordJSON(t, rec))
	}
}

func TestAHookRefusalAnswersEveryIDInABatch(t *testing.T) {
	fake := newFakeHook(t, answerHook(`{"decision":"deny","message":"no"}`))
	up := newMCPUpstream(t)
	client, _ := newMCPRecordingProxy(t, up, []*resolvedService{hookedMCPService(up.host(), fake.hook())})

	batch := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}},{"jsonrpc":"2.0","id":2,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`
	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json", batch, http.Header{"Accept": {streamableAccept}})
	want := `[{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"no"}]}},{"jsonrpc":"2.0","id":2,"error":{"code":-31000,"message":"` + hookBatchRefusedMessage + `"}}]`
	if res.status != http.StatusOK || res.body != want {
		t.Fatalf("status %d body %s", res.status, res.body)
	}

	res = proxiedPost(t, client, up.server.URL+"/mcp", "application/json", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, http.Header{"Accept": {streamableAccept}})
	if res.status != http.StatusAccepted || res.body != "" {
		t.Fatalf("a notification got status %d body %s", res.status, res.body)
	}

	res = proxiedPost(t, client, up.server.URL+"/mcp", "application/json", `{"jsonrpc":`, http.Header{"Accept": {streamableAccept}})
	if res.status != http.StatusForbidden || res.body != `{"jsonrpc":"2.0","id":null,"error":{"code":-31000,"message":"no"}}` {
		t.Fatalf("an unreadable body got status %d body %s", res.status, res.body)
	}
	assertUpstreamSawNothing(t, up)
}

func TestOnlyTheFirstAnswerInAHookRefusedBatchCarriesTheHooksText(t *testing.T) {
	text := strings.Repeat("x", 1000)
	messages := make([]jsonrpcMessage, 0, 500)
	for i := range 500 {
		message := jsonrpcMessage{id: json.RawMessage(strconv.Itoa(i)), mcpCall: mcpCall{Method: "tools/list"}}
		if i%2 == 0 {
			message.Method = mcpMethodToolsCall
		}
		messages = append(messages, message)
	}
	refusal := hookDeniedMCPRefusal(text, messages, true, true, true)
	if n := strings.Count(string(refusal.body), text); n != 1 {
		t.Fatalf("the hook's text appears %d times", n)
	}
	if n := strings.Count(string(refusal.body), hookBatchRefusedMessage); n != 499 {
		t.Fatalf("the batch line appears %d times, want 499", n)
	}
	if len(refusal.body) > 100_000 {
		t.Fatalf("body is %d bytes", len(refusal.body))
	}
	if !strings.HasPrefix(string(refusal.body), `[{"jsonrpc":"2.0","id":0,"result":{"isError":true,"content":[{"type":"text","text":"`+text+`"}]}},{"jsonrpc":"2.0","id":1,"error":{"code":-31000,"message":"`+hookBatchRefusedMessage+`"}},{"jsonrpc":"2.0","id":2,"result":{"isError":true,"content":[{"type":"text","text":"`+hookBatchRefusedMessage+`"}]}}`) {
		t.Fatalf("body starts %s", refusal.body[:min(len(refusal.body), 1500)])
	}
}

func TestAHookRefusedBatchGivesTheHooksTextToTheFirstToolCall(t *testing.T) {
	messages := []jsonrpcMessage{
		{id: json.RawMessage("1"), mcpCall: mcpCall{Method: "tools/list"}},
		{id: json.RawMessage("2"), mcpCall: mcpCall{Method: mcpMethodToolsCall, Tool: "merge"}},
	}
	refusal := hookDeniedMCPRefusal("Ask Ana first.", messages, true, true, true)
	want := `[{"jsonrpc":"2.0","id":1,"error":{"code":-31000,"message":"` + hookBatchRefusedMessage + `"}},{"jsonrpc":"2.0","id":2,"result":{"isError":true,"content":[{"type":"text","text":"Ask Ana first."}]}}]`
	if string(refusal.body) != want {
		t.Fatalf("body %s", refusal.body)
	}
}

func TestAnMCPHookFailureTellsTheClientWhenToRetry(t *testing.T) {
	fake := newFakeHook(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	up := newMCPUpstream(t)
	client, _ := newMCPRecordingProxy(t, up, []*resolvedService{hookedMCPService(up.host(), fake.hook())})

	res := proxiedPost(t, client, up.server.URL+"/mcp", "application/json", `{"jsonrpc":`, http.Header{"Accept": {streamableAccept}})
	assertUpstreamSawNothing(t, up)
	if res.status != http.StatusServiceUnavailable || res.header.Get(HeaderError) != errorCodeHookFailed {
		t.Fatalf("status %d headers %v", res.status, res.header)
	}
	if got := res.header.Get("Retry-After"); got != hookFailedRetryAfter {
		t.Fatalf("Retry-After = %q", got)
	}
}

func TestAHookedMCPServiceWithoutAnAllowlistStillDropsAcceptEncoding(t *testing.T) {
	fake := newFakeHook(t, answerHook(`{"decision":"allow"}`))
	sawEncoding := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawEncoding <- r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3,"result":{}}`)
	}))
	t.Cleanup(upstream.Close)
	host := strings.TrimPrefix(upstream.URL, "https://")
	_, client := newTLSProxy(t, upstream, fixedResolver{services: []*resolvedService{hookedMCPService(host, fake.hook())}})

	res := proxiedPost(t, client, upstream.URL+"/mcp", "application/json", `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		http.Header{"Accept": {streamableAccept}, "Accept-Encoding": {"br, deflate"}})
	if got := <-sawEncoding; got != "gzip" {
		t.Fatalf("upstream saw Accept-Encoding %q, want the transport's own gzip", got)
	}
	if res.status != http.StatusOK {
		t.Fatalf("status %d body %s", res.status, res.body)
	}
}

func TestAHookRefusalReachesALegacySSEStream(t *testing.T) {
	var fake *fakeHook
	fake = newFakeHook(t, func(w http.ResponseWriter, _ *http.Request) {
		calls := fake.calls()
		var p hookPayload
		if json.Unmarshal(calls[len(calls)-1].body, &p) == nil && p.Request != nil && p.Request.Method == http.MethodGet {
			_, _ = io.WriteString(w, `{"decision":"allow"}`)
			return
		}
		_, _ = io.WriteString(w, `{"decision":"deny","message":"Ask Ana first."}`)
	})
	upstream, posts := newLegacySSEUpstream(t)
	host := strings.TrimPrefix(upstream.URL, "https://")
	_, client := newTLSProxy(t, upstream, fixedResolver{services: []*resolvedService{hookedMCPService(host, fake.hook())}})

	resp, err := client.Get(upstream.URL + "/sse")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	stream := bufio.NewReader(resp.Body)
	if event := readSSEEvent(t, stream); !strings.Contains(event, "/messages?sessionId=abc") {
		t.Fatalf("endpoint event = %q", event)
	}

	res := proxiedPost(t, client, upstream.URL+"/messages?sessionId=abc", "application/json", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"merge"}}`, nil)
	if res.status != http.StatusAccepted || res.body != "" || res.header.Get(HeaderError) != errorCodeHookDenied {
		t.Fatalf("status %d body %s headers %v", res.status, res.body, res.header)
	}
	event := readSSEEvent(t, stream)
	if !strings.Contains(event, `"id":4`) || !strings.Contains(event, `"isError":true`) || !strings.Contains(event, "Ask Ana first.") {
		t.Fatalf("event = %q", event)
	}
	select {
	case got := <-posts:
		t.Fatalf("the upstream got a refused call: %s", got)
	default:
	}
}
