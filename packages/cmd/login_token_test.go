package cmd

import "testing"

func TestCleanPastedBrowserToken(t *testing.T) {
	const token = "sample-token"

	tests := []struct {
		name  string
		input string
	}{
		{name: "plain", input: token},
		{name: "bracketed paste", input: "\x1b[200~" + token + "\x1b[201~"},
		{name: "bracketed paste with surrounding whitespace", input: " \n\x1b[200~" + token + "\x1b[201~\r\n "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanPastedBrowserToken(tt.input); got != token {
				t.Fatalf("cleanPastedBrowserToken() = %q, want %q", got, token)
			}
		})
	}
}
