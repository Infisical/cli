package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-resty/resty/v2"
)

func TestA422WithZodIssuesRendersTheMessages(t *testing.T) {
	body := `{"reqId":"r","statusCode":422,"message":[{"code":"custom","message":"TTL must be a duration of at least 1 minute, such as 30m, 8h or 7d, or never","path":["ttl"]}],"error":"ValidationFailure"}`
	msg, name, ok := parseValidationBody(body)
	if !ok || msg != "ttl: TTL must be a duration of at least 1 minute, such as 30m, 8h or 7d, or never" {
		t.Fatalf("ok=%v message=%q", ok, msg)
	}
	if name != "ValidationFailure" {
		t.Fatalf("name = %q", name)
	}
}

func TestA422WithSeveralIssuesListsEachField(t *testing.T) {
	body := `{"statusCode":422,"message":[{"message":"Required","path":["accessBundles",0]},{"message":"too long","path":["name"]}],"error":"ValidationFailure"}`
	msg, _, ok := parseValidationBody(body)
	if !ok || msg != "accessBundles.[0]: Required; name: too long" {
		t.Fatalf("ok=%v message=%q", ok, msg)
	}
}

func TestA422WithAPlainMessageRendersIt(t *testing.T) {
	body := `{"statusCode":422,"message":"One or more field values exceed the maximum length allowed for this resource","error":"ValidationFailure"}`
	msg, _, ok := parseValidationBody(body)
	if !ok || msg != "One or more field values exceed the maximum length allowed for this resource" {
		t.Fatalf("ok=%v message=%q", ok, msg)
	}
}

func TestA422OfAnUnknownShapeIsNotParsed(t *testing.T) {
	for _, body := range []string{`not json`, `{"message":[]}`, `{"message":{"nested":true}}`, `{"other":1}`, `{"message":""}`} {
		if _, _, ok := parseValidationBody(body); ok {
			t.Fatalf("body %q was parsed; it should fall back to the raw body", body)
		}
	}
}

// Through a real response: the 422 branch renders the message and keeps the raw body only as the fallback.
func TestTryParseErrorBodyOnA422(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"zod issues": {`{"statusCode":422,"message":[{"message":"bad","path":["ttl"]}],"error":"ValidationFailure"}`, "ttl: bad"},
		"unknown":    {`garbage`, "garbage"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(422)
			_, _ = w.Write([]byte(tc.body))
		}))
		res, err := resty.New().R().Post(srv.URL)
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if msg, _, _ := TryParseErrorBody(res); msg != tc.want {
			t.Fatalf("%s: message = %q, want %q", name, msg, tc.want)
		}
	}
}
