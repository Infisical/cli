package agentvault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

const testHookSecret = "ascii-signing-secret-for-hooks-0123456789"

type hookHit struct {
	header http.Header
	body   []byte
}

func (h hookHit) payload(t *testing.T) hookPayload {
	t.Helper()
	var p hookPayload
	if err := json.Unmarshal(h.body, &p); err != nil {
		t.Fatalf("the hook payload is not JSON (%v): %s", err, h.body)
	}
	return p
}

// A hook server that records every call and answers with answer.
type fakeHook struct {
	server *httptest.Server
	mu     sync.Mutex
	hits   []hookHit
}

func newFakeHook(t *testing.T, answer http.HandlerFunc) *fakeHook {
	t.Helper()
	f := &fakeHook{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.hits = append(f.hits, hookHit{header: r.Header.Clone(), body: body})
		f.mu.Unlock()
		answer(w, r)
	}))
	t.Cleanup(f.server.Close)
	return f
}

// No narrowing, so it is asked about every request of its service, unless narrowing is given.
func (f *fakeHook) hook(narrowing ...api.AgentVaultServiceHook) *serviceHook {
	var wire api.AgentVaultServiceHook
	if len(narrowing) > 0 {
		wire = narrowing[0]
	}
	name := "refund-gate"
	wire.ID, wire.Name, wire.URL, wire.Secret = "hook-1", &name, f.server.URL+"/agent-vault/hook", testHookSecret
	return toServiceHook(&wire)
}

func (f *fakeHook) calls() []hookHit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hookHit(nil), f.hits...)
}

func (f *fakeHook) only(t *testing.T) hookHit {
	t.Helper()
	calls := f.calls()
	if len(calls) != 1 {
		t.Fatalf("the hook was called %d times, want once", len(calls))
	}
	return calls[0]
}

func answerHook(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
}

func testHookPayload() *hookPayload {
	return &hookPayload{Version: hookPayloadVersion, Service: hookPayloadService{ID: "svc-1", Name: "stripe", Type: serviceKindHTTP}}
}

func TestTheHookSignatureMatchesStandardWebhooks(t *testing.T) {
	// The Standard Webhooks reference vector, whose key is the base64 after whsec_.
	key, _ := base64.StdEncoding.DecodeString("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
	if got := signHook(key, "msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265330", []byte(`{"test": 2432232314}`)); got != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Fatalf("signature = %s", got)
	}
	// An admin's secret is used as its own bytes, as the libraries' raw-key mode does.
	got := signHook([]byte(testHookSecret), "018f3b4e-2a1c-7d10-9b2e-4c5d6e7f8091", "1731400000", []byte(`{"version":"1"}`))
	if got != "v1,Pj2Kn6ZHUNV4QQBD/0I/iER+DqTM4B6tGUwlrVb7W4g=" {
		t.Fatalf("signature = %s", got)
	}
}

type getBodyRecorder struct {
	next   http.RoundTripper
	mu     sync.Mutex
	seen   bool
	setAll bool
}

func (r *getBodyRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.seen, r.setAll = true, req.GetBody != nil
	r.mu.Unlock()
	return r.next.RoundTrip(req)
}

func TestAHookCallIsSignedAndCanBeResent(t *testing.T) {
	fake := newFakeHook(t, answerHook(`{"decision":"allow"}`))
	client := newHookClient(nil)
	recorder := &getBodyRecorder{next: client.client.Transport}
	client.client.Transport = recorder

	before := time.Now().Unix()
	result := client.ask(context.Background(), fake.hook(), testHookPayload())
	if result.Decision != hookAllow {
		t.Fatalf("outcome = %+v (%v)", result, result.err)
	}
	if !recorder.seen || !recorder.setAll {
		t.Fatal("the hook request had no GetBody, so Go can't resend it on a connection the hook closed")
	}

	hit := fake.only(t)
	id := hit.header.Get("webhook-id")
	if parsed, err := uuid.Parse(id); err != nil || parsed.Version() != 7 {
		t.Fatalf("webhook-id %q is not a uuid v7", id)
	}
	if hit.header.Get("Idempotency-Key") != id || hit.payload(t).DeliveryID != id || result.DeliveryID != id {
		t.Fatalf("Idempotency-Key %q, deliveryId %q, outcome %q, want all %q", hit.header.Get("Idempotency-Key"), hit.payload(t).DeliveryID, result.DeliveryID, id)
	}
	ts := hit.header.Get("webhook-timestamp")
	if n, err := strconv.ParseInt(ts, 10, 64); err != nil || n < before || n > time.Now().Unix() {
		t.Fatalf("webhook-timestamp %q is not now in unix seconds", ts)
	}
	mac := hmac.New(sha256.New, []byte(testHookSecret))
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(hit.body)
	if want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)); hit.header.Get("webhook-signature") != want {
		t.Fatalf("webhook-signature %q, want %q", hit.header.Get("webhook-signature"), want)
	}
	if hit.header.Get("Content-Type") != "application/json" || !strings.HasPrefix(hit.header.Get("User-Agent"), "infisical-agent-vault-proxy/") {
		t.Fatalf("headers = %v", hit.header)
	}
}

// A hook server that drops idle connections is answered on a fresh one, with the same delivery and signature.
func TestAHookCallIsResentWhenThePooledConnectionWasClosed(t *testing.T) {
	var mu sync.Mutex
	var ids []string
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		requests++
		n := requests
		ids = append(ids, r.Header.Get("webhook-id"))
		mu.Unlock()
		if n == 2 {
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
			return
		}
		_, _ = io.WriteString(w, `{"decision":"allow"}`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	hook := &serviceHook{url: u, secret: []byte(testHookSecret)}
	client := newHookClient(nil)

	for i := range 2 {
		if result := client.ask(context.Background(), hook, testHookPayload()); result.Decision != hookAllow {
			t.Fatalf("call %d: %+v (%v)", i, result, result.err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ids) != 3 || ids[1] != ids[2] {
		t.Fatalf("webhook-ids seen = %v, want the second call sent twice", ids)
	}
}

func TestAHookRedirectIsNotFollowed(t *testing.T) {
	followed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed = true
			_, _ = io.WriteString(w, `{"decision":"allow"}`)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/hook")

	result := newHookClient(nil).ask(context.Background(), &serviceHook{url: u, secret: []byte(testHookSecret)}, testHookPayload())
	if result.Decision != hookFailed || result.Cause != hookCauseRedirect || followed {
		t.Fatalf("outcome = %+v, followed = %v", result, followed)
	}
}

func TestAHookRedirectToABadURLLogsNoTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/tok-in-redirect/%zz?x=tok-in-query")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/hook")

	result := newHookClient(nil).ask(context.Background(), &serviceHook{url: u, secret: []byte(testHookSecret)}, testHookPayload())
	if result.Decision != hookFailed || result.Cause != hookCauseRedirect {
		t.Fatalf("outcome = %+v (%v)", result, result.err)
	}
	var out bytes.Buffer
	logger := zerolog.New(&out)
	result.logFields(logger.Error()).Msg("agent-vault: request")
	if strings.Contains(out.String(), "tok-in-redirect") || strings.Contains(out.String(), "tok-in-query") {
		t.Fatalf("the redirect target reached the log: %s", out.String())
	}
}

func TestHookAnswersThatAreNotAllowOrDenyFail(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer http.HandlerFunc
		cause  string
	}{
		{"server error", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }, "status_500"},
		{"unauthorized", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }, "status_401"},
		{"not JSON", answerHook(`allow`), hookCauseInvalidJSON},
		{"empty", answerHook(``), hookCauseInvalidJSON},
		{"array", answerHook(`["allow"]`), hookCauseInvalidJSON},
		{"message not a string", answerHook(`{"decision":"allow","message":5}`), hookCauseInvalidJSON},
		{"no decision", answerHook(`{}`), hookCauseBadDecision},
		{"null", answerHook(`null`), hookCauseBadDecision},
		{"capitalised", answerHook(`{"decision":"Allow"}`), hookCauseBadDecision},
		{"unknown", answerHook(`{"decision":"maybe"}`), hookCauseBadDecision},
		{"over the cap", answerHook(`{"decision":"allow","reason":"` + strings.Repeat("a", maxHookAnswer) + `"}`), hookCauseTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeHook(t, tc.answer)
			result := newHookClient(nil).ask(context.Background(), fake.hook(), testHookPayload())
			if result.Decision != hookFailed || result.Cause != tc.cause {
				t.Fatalf("outcome = %+v (%v), want failed with %s", result, result.err, tc.cause)
			}
		})
	}
}

func TestAHookAnswerJustUnderTheCapIsRead(t *testing.T) {
	prefix, suffix := `{"decision":"deny","reason":"`, `"}`
	fake := newFakeHook(t, answerHook(prefix+strings.Repeat("a", maxHookAnswer-len(prefix)-len(suffix))+suffix))
	result := newHookClient(nil).ask(context.Background(), fake.hook(), testHookPayload())
	if result.Decision != hookDeny || len(result.Reason) != maxHookReason {
		t.Fatalf("outcome = %+v (%v)", result.Decision, result.err)
	}
}

func TestASlowHookTimesOut(t *testing.T) {
	fake := newFakeHook(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	start := time.Now()
	result := newHookClient(nil).ask(context.Background(), fake.hook(), testHookPayload())
	elapsed := time.Since(start)
	if result.Decision != hookFailed || result.Cause != hookCauseTimeout {
		t.Fatalf("outcome = %+v (%v)", result, result.err)
	}
	if elapsed < hookTimeout-100*time.Millisecond || elapsed > hookTimeout+2*time.Second {
		t.Fatalf("the call took %v, want about %v", elapsed, hookTimeout)
	}
}

func TestAHookThatStallsAfterItsHeadersTimesOut(t *testing.T) {
	fake := newFakeHook(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"decision":`)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	result := newHookClient(nil).ask(context.Background(), fake.hook(), testHookPayload())
	if result.Decision != hookFailed || result.Cause != hookCauseTimeout {
		t.Fatalf("outcome = %+v (%v)", result, result.err)
	}
}

func TestCancellingTheCallerEndsTheHookCall(t *testing.T) {
	fake := newFakeHook(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	result := newHookClient(nil).ask(ctx, fake.hook(), testHookPayload())
	if result.Decision != hookFailed || time.Since(start) > time.Second {
		t.Fatalf("outcome = %+v after %v", result, time.Since(start))
	}
}

func TestAHookInfisicalSentUnusableAlwaysFails(t *testing.T) {
	for _, wire := range []struct{ url, secret string }{
		{"ftp://hooks.example.com/x", testHookSecret},
		{"https:///no-host", testHookSecret},
		{"://bad", testHookSecret},
		{"https://hooks.example.com/x", ""},
	} {
		hook := toServiceHook(&api.AgentVaultServiceHook{URL: wire.url, Secret: wire.secret})
		if hook == nil {
			t.Fatalf("%+v mapped to no hook, which would skip it", wire)
		}
		result := newHookClient(nil).ask(context.Background(), hook, testHookPayload())
		if result.Decision != hookFailed || result.Cause != hookCauseBrokenConfig {
			t.Fatalf("%+v: outcome = %+v", wire, result)
		}
	}
	if toServiceHook(nil) != nil {
		t.Fatal("a service with no hook got one")
	}
}

func TestAFailedHookCallLogsNoPathOrQuery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	u, _ := url.Parse("http://" + addr + "/services/T123/tok-in-path?x=tok-in-query")

	result := newHookClient(nil).ask(context.Background(), &serviceHook{url: u, secret: []byte(testHookSecret)}, testHookPayload())
	if result.Decision != hookFailed || result.Cause != hookCauseUnreachable {
		t.Fatalf("outcome = %+v (%v)", result, result.err)
	}
	var out bytes.Buffer
	logger := zerolog.New(&out)
	result.logFields(logger.Error()).Msg("agent-vault: request")
	if strings.Contains(out.String(), "tok-in-path") || strings.Contains(out.String(), "tok-in-query") {
		t.Fatalf("the hook URL's path reached the log: %s", out.String())
	}
	if !strings.Contains(out.String(), `"hookUrl":"http://`+addr+`"`) || !strings.Contains(out.String(), `"hookCause":"unreachable"`) {
		t.Fatalf("log line = %s", out.String())
	}
}

func TestHookTextIsCleaned(t *testing.T) {
	if got := cleanHookText(" ok\x00\x1b[31m​red‮\nnext\tline \xff", maxHookMessage); got != "ok[31mred next line" {
		t.Fatalf("cleaned = %q", got)
	}
	long := cleanHookText(strings.Repeat("é", maxHookMessage), maxHookMessage)
	if len(long) > maxHookMessage || !utf8.ValidString(long) || len(long) < maxHookMessage-1 {
		t.Fatalf("cut to %d bytes, valid %v", len(long), utf8.ValidString(long))
	}
	if got := capText("aé", 2); got != "a" {
		t.Fatalf("capText cut inside a character: %q", got)
	}
}

func TestTheBodyPrefixKeepsTheWholeBodyForTheUpstream(t *testing.T) {
	big := strings.Repeat("x", 10)
	req := httptest.NewRequest(http.MethodPost, "/", io.NopCloser(strings.NewReader(big)))
	prefix, truncated, err := hookBodyPrefix(req, 4)
	if err != nil || !truncated || string(prefix) != "xxxx" {
		t.Fatalf("prefix %q truncated %v err %v", prefix, truncated, err)
	}
	if rest, _ := io.ReadAll(req.Body); string(rest) != big {
		t.Fatalf("the upstream would get %q", rest)
	}

	req = httptest.NewRequest(http.MethodPost, "/", io.NopCloser(strings.NewReader("abc")))
	prefix, truncated, _ = hookBodyPrefix(req, 4)
	if _, ok := req.Body.(*bufferedBody); !ok || truncated || string(prefix) != "abc" {
		t.Fatalf("a body that fits should be held for a resend, got %T %q", req.Body, prefix)
	}
	if replay, ok := replayableBody(req); !ok || string(replay) != "abc" {
		t.Fatal("a held body is not replayable")
	}
	again, truncated, _ := hookBodyPrefix(req, 2)
	if string(again) != "ab" || !truncated {
		t.Fatalf("a held body was read again as %q", again)
	}
}

func TestTheBodyIsSentAsTextOrBase64(t *testing.T) {
	cut := []byte("h\xc3")
	if body, encoding := hookBodyText(cut, true, http.Header{}); body != "h" || encoding != "utf8" {
		t.Fatalf("a cut character made %q %s", body, encoding)
	}
	if _, encoding := hookBodyText(cut, false, http.Header{}); encoding != "base64" {
		t.Fatal("a whole body that isn't UTF-8 went out as text")
	}
	if body, encoding := hookBodyText([]byte("plain"), false, http.Header{"Content-Encoding": {"gzip"}}); encoding != "base64" || body != base64.StdEncoding.EncodeToString([]byte("plain")) {
		t.Fatalf("a compressed body went out as %s", encoding)
	}
}

func TestAnHTTPSHookIsVerifiedAgainstTheTrustedRoots(t *testing.T) {
	srv := httptest.NewTLSServer(answerHook(`{"decision":"allow"}`))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	hook := &serviceHook{url: u, secret: []byte(testHookSecret)}

	if result := newHookClient(nil).ask(context.Background(), hook, testHookPayload()); result.Decision != hookFailed || result.Cause != hookCauseUnreachable {
		t.Fatalf("an untrusted certificate gave %+v", result)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	if result := newHookClient(pool).ask(context.Background(), hook, testHookPayload()); result.Decision != hookAllow {
		t.Fatalf("a trusted certificate gave %+v (%v)", result, result.err)
	}
}

func TestTheSessionLogCopyOfAHookOutcomeLeavesOutTheMessage(t *testing.T) {
	o := &hookOutcome{Decision: hookDeny, Reason: "needs approval", Cause: "", DurationMs: 12, DeliveryID: "d1",
		message: "Ask Ana first.", err: errors.New("boom"), origin: "https://hook.example"}
	got := o.sessionLogHook()
	want := &hookOutcome{Decision: hookDeny, Reason: "needs approval", DurationMs: 12, DeliveryID: "d1"}
	if got == o || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if (&hookOutcome{Decision: hookAllow}).sessionLogHook() != nil {
		t.Fatal("an allowed call was recorded")
	}
}

func TestTheHookMatcher(t *testing.T) {
	httpSvc := &resolvedService{name: "github", kind: serviceKindHTTP}
	mcpSvc := &resolvedService{name: "linear", kind: serviceKindMCP}
	pgSvc := &resolvedService{name: "db", kind: serviceKindPostgres}
	substitutingSvc := &resolvedService{name: "github", kind: serviceKindHTTP, substitutions: []substitution{
		subOn("__ORG__", "acme", surfacePath), subOn("{{TEAM}}", "core", surfacePath), subOn("__REPO__", "secret", surfaceQuery, surfaceHeader, surfaceBody)}}
	get := func(path string) *http.Request { return httptest.NewRequest(http.MethodGet, "https://h"+path, nil) }
	post := func(path string) *http.Request {
		return httptest.NewRequest(http.MethodPost, "https://h"+path, strings.NewReader("{}"))
	}
	calls := func(tools ...string) *hookPayloadMCP {
		out := &hookPayloadMCP{Calls: []hookMCPCall{{Method: "initialize"}}, Parsed: true}
		for _, tool := range tools {
			out.Calls = append(out.Calls, hookMCPCall{Method: mcpMethodToolsCall, Tool: tool})
		}
		return out
	}
	withHeader := func(req *http.Request, name, value string) *http.Request {
		req.Header.Set(name, value)
		return req
	}
	narrow := func(methods, paths, tools []string) *api.AgentVaultServiceHook {
		return &api.AgentVaultServiceHook{Methods: methods, Paths: paths, Tools: tools}
	}
	list := func(values ...string) []string { return values }

	for _, tc := range []struct {
		name      string
		narrowing *api.AgentVaultServiceHook
		svc       *resolvedService
		req       *http.Request
		mcp       *hookPayloadMCP
		want      bool
	}{
		{"no narrowing picks every HTTP request", nil, httpSvc, get("/x"), nil, true},
		{"no narrowing picks every MCP request", nil, mcpSvc, post("/mcp"), calls("a"), true},
		{"no narrowing picks every connection", nil, pgSvc, nil, nil, true},
		{"empty lists are no narrowing", narrow(list(), list(), list()), httpSvc, get("/x"), nil, true},
		{"method in the set", narrow(list("get", "PUT"), nil, nil), httpSvc, get("/x"), nil, true},
		{"method not in the set", narrow(list("PUT"), nil, nil), httpSvc, get("/x"), nil, false},
		{"method override counts", narrow(list("DELETE"), nil, nil), httpSvc,
			withHeader(post("/x"), "X-HTTP-Method-Override", "delete"), nil, true},
		{"each comma-separated override counts", narrow(list("DELETE"), nil, nil), httpSvc,
			withHeader(post("/x"), "X-HTTP-Method-Override", "DELETE, POST"), nil, true},
		{"a form POST counts as any method", narrow(list("DELETE"), nil, nil), httpSvc,
			withHeader(post("/x"), "Content-Type", "application/x-www-form-urlencoded"), nil, true},
		{"a multipart POST counts as any method", narrow(list("DELETE"), nil, nil), httpSvc,
			withHeader(post("/x"), "Content-Type", "Multipart/Form-Data; boundary=x"), nil, true},
		{"a JSON POST is only a POST", narrow(list("DELETE"), nil, nil), httpSvc,
			withHeader(post("/x"), "Content-Type", "application/json"), nil, false},
		{"a form PUT is only a PUT", narrow(list("DELETE"), nil, nil), httpSvc,
			withHeader(httptest.NewRequest(http.MethodPut, "https://h/x", nil), "Content-Type", "application/x-www-form-urlencoded"), nil, false},
		{"a query _method counts on a JSON POST", narrow(list("DELETE"), nil, nil), httpSvc,
			withHeader(post("/x?_method=delete"), "Content-Type", "application/json"), nil, true},
		{"a query _method naming another method", narrow(list("DELETE"), nil, nil), httpSvc,
			withHeader(post("/x?_method=PATCH"), "Content-Type", "application/json"), nil, false},
		{"an unparseable query counts as any method", narrow(list("DELETE"), nil, nil), httpSvc,
			post("/x?_method=%zz"), nil, true},
		{"a form POST still needs the path", narrow(list("DELETE"), list("/repos"), nil), httpSvc,
			withHeader(post("/user"), "Content-Type", "application/x-www-form-urlencoded"), nil, false},
		{"path under a prefix", narrow(nil, list("/repos/"), nil), httpSvc, get("/repos/a/b"), nil, true},
		{"path equal to a prefix", narrow(nil, list("/repos"), nil), httpSvc, get("/repos"), nil, true},
		{"path sharing a prefix's letters", narrow(nil, list("/repos"), nil), httpSvc, get("/repository"), nil, false},
		{"path outside every prefix", narrow(nil, list("/repos"), nil), httpSvc, get("/user"), nil, false},
		{"path case is ignored", narrow(nil, list("/anything/refunds"), nil), httpSvc,
			get("/ANYTHING/Refunds/x"), nil, true},
		{"prefix case is ignored", narrow(nil, list("/V1/Refunds"), nil), httpSvc, get("/v1/refunds"), nil, true},
		{"an encoded uppercase path matches", narrow(nil, list("/v1/refunds"), nil), httpSvc,
			get("/v1/%52efunds/1"), nil, true},
		{"a substituted path in another case matches", narrow(nil, list("/repos/acme"), nil), substitutingSvc,
			get("/REPOS/__ORG__/issues"), nil, true},
		{"an ambiguous path matches", narrow(nil, list("/admin"), nil), httpSvc, get("/repos/..;/admin"), nil, true},
		{"an encoded path matches its decoded prefix", narrow(nil, list("/v1/refunds"), nil), httpSvc,
			get("/v1/%72efunds/1"), nil, true},
		{"an encoded path outside every prefix", narrow(nil, list("/v1/refunds"), nil), httpSvc,
			get("/v1/%63harges/1"), nil, false},
		{"a substituted path matches", narrow(nil, list("/repos/acme"), nil), substitutingSvc,
			get("/repos/__ORG__/issues"), nil, true},
		{"a substituted placeholder in escaped form matches", narrow(nil, list("/teams/core"), nil), substitutingSvc,
			get("/teams/%7b%7bTEAM%7d%7d/members"), nil, true},
		{"the unsubstituted path still matches", narrow(nil, list("/repos/__ORG__"), nil), substitutingSvc,
			get("/repos/__ORG__/issues"), nil, true},
		{"only path substitutions count", narrow(nil, list("/repos/secret"), nil), substitutingSvc,
			get("/repos/__REPO__/issues"), nil, false},
		{"a substitution elsewhere in the path", narrow(nil, list("/repos/acme"), nil), substitutingSvc,
			get("/repos/other/__ORG__"), nil, false},
		{"method and path both have to fit", narrow(list("POST"), list("/repos"), nil), httpSvc, get("/repos/a"), nil, false},
		{"tools on an HTTP service pick the whole service", narrow(nil, nil, list("a")), httpSvc, get("/x"), nil, true},
		{"a listed tool", narrow(nil, nil, list("delete_issue")), mcpSvc, post("/mcp"), calls("delete_issue"), true},
		{"an unlisted tool", narrow(nil, nil, list("delete_issue")), mcpSvc, post("/mcp"), calls("create_issue"), false},
		{"tools compare exactly", narrow(nil, nil, list("delete_issue")), mcpSvc, post("/mcp"), calls("Delete_Issue"), false},
		{"a listed tool in a batch", narrow(nil, nil, list("delete_issue")), mcpSvc, post("/mcp"),
			calls("create_issue", "delete_issue"), true},
		{"a tools/call naming no tool", narrow(nil, nil, list("delete_issue")), mcpSvc, post("/mcp"), calls(""), true},
		{"a tool named only in Mcp-Name", narrow(nil, nil, list("delete_issue")), mcpSvc,
			withHeader(post("/mcp"), mcpNameHeader, "delete_issue"), calls("create_issue"), true},
		{"an unparseable MCP body", narrow(nil, nil, list("delete_issue")), mcpSvc, post("/mcp"),
			&hookPayloadMCP{Calls: []hookMCPCall{}}, true},
		{"an MCP request with no body", narrow(nil, nil, list("delete_issue")), mcpSvc, get("/sse"), nil, false},
		{"methods on an MCP service pick the whole service", narrow(list("DELETE"), list("/x"), nil), mcpSvc,
			post("/mcp"), calls("a"), true},
		{"native ignores narrowing", narrow(list("GET"), list("/x"), list("a")), pgSvc, nil, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := api.AgentVaultServiceHook{}
			if tc.narrowing != nil {
				wire = *tc.narrowing
			}
			wire.ID, wire.URL, wire.Secret = "h", "https://hook.example", "s"
			if got := toServiceHook(&wire).matches(tc.svc, tc.req, tc.mcp); got != tc.want {
				t.Fatalf("matches = %v, want %v", got, tc.want)
			}
		})
	}

	var none *serviceHook
	if none.matches(httpSvc, get("/x"), nil) || none.matches(pgSvc, nil, nil) {
		t.Fatal("a service with no hook matched")
	}
}

func TestTheHookPayloadNamesTheHookAndTheSessionMetadata(t *testing.T) {
	ps := &proxyServer{}
	svc := &resolvedService{id: "svc-1", name: "github", kind: serviceKindHTTP}
	session := &api.AgentVaultResolvedSession{Actor: api.AgentVaultSessionActor{Type: "user", ID: "u-1", Name: "Ana"},
		Metadata: map[string]string{"ticket": "T-1"}}

	svc.hook = &serviceHook{id: "h-2"}
	body, _ := encodeJSON(ps.newHookPayload(svc, cacheLookup{sessionID: "s1", session: session}))
	if !bytes.Contains(body, []byte(`"hook":{"id":"h-2","name":null}`)) || !bytes.Contains(body, []byte(`"metadata":{"ticket":"T-1"}`)) {
		t.Fatalf("payload = %s", body)
	}

	body, _ = encodeJSON(ps.newHookPayload(svc, cacheLookup{sessionID: "s1"}))
	if !bytes.Contains(body, []byte(`"metadata":{}`)) {
		t.Fatalf("a session with no metadata should send an empty object: %s", body)
	}
}
