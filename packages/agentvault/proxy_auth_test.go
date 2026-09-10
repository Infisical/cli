package agentvault

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// undici, urllib, requests and libcurl only send Proxy-Authorization when both halves are present, and
// git refuses to start without a password at all, so the token has to ride in one of a filled pair. It
// is the password half: tools mask that one and print the username, and a token containing a colon
// survives there because the split takes the first one only.
func TestRequestSessionTokenReadsThePasswordHalf(t *testing.T) {
	basic := func(user, pass string) *http.Request {
		r, _ := http.NewRequest(http.MethodConnect, "https://example.com/", nil)
		r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
		return r
	}

	for _, tc := range []struct {
		name, user, pass, want string
	}{
		{"the shape av run hands out", ProxyAuthUsername, "agv_tok", "agv_tok"},
		{"a token carrying a colon", ProxyAuthUsername, "agv_a:b", "agv_a:b"},
		{"the username is ignored", "someone-else", "agv_tok", "agv_tok"},
	} {
		got, ok := requestSessionToken(basic(tc.user, tc.pass))
		if !ok || got != tc.want {
			t.Fatalf("%s: got %q ok=%v, want %q", tc.name, got, ok, tc.want)
		}
	}

	if _, ok := requestSessionToken(basic("agv_tok", "")); ok {
		t.Fatal("an empty password half must not authenticate")
	}
}
