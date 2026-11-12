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

func (f *fakeHook) hook() *serviceHook {
	u, _ := url.Parse(f.server.URL + "/agent-vault/hook")
	return &serviceHook{url: u, secret: []byte(testHookSecret)}
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
		hook := toServiceHook(&api.AgentVaultHook{URL: wire.url, Secret: wire.secret})
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
