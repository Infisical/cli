package util

import (
	"strings"
	"testing"
)

// An invalid -o is printed back as an error, so a credential pasted there by mistake must not be.
func TestFormatOutputNeverRepeatsACredential(t *testing.T) {
	token := "ghp" + "_" + strings.Repeat("aB3", 12)
	_, err := FormatOutput(token, struct{}{}, nil)
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "invalid output format: <output>.") {
		t.Errorf("got %v", err)
	}

	_, err = FormatOutput("jsno", struct{}{}, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "invalid output format: jsno. Supported formats are ") || !strings.Contains(err.Error(), "Did you mean 'json'?") {
		t.Errorf("a typo reads as before: %v", err)
	}
}
