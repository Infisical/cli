package session

import "testing"

func TestMaskURL(t *testing.T) {
	cases := map[string]string{
		"https://user:pass@grafana.internal/d/abc?orgId=1&token=secret#tab=x&flag": "https://grafana.internal/d/abc?orgId=***&token=***#tab=***&flag",
		"https://grafana.internal/path":                                            "https://grafana.internal/path",
		"https://grafana.internal/?flag":                                           "https://grafana.internal/?flag",
		"https://grafana.internal/#access=abc123":                                  "https://grafana.internal/#access=***",
		"://bad": "***",
	}
	for in, want := range cases {
		if got := MaskURL(in); got != want {
			t.Errorf("MaskURL(%q) = %q, want %q", in, got, want)
		}
	}
}
