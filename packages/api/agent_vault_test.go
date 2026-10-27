package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCreateAgentVaultSessionRequestSendsALabelOnlyWhenGiven(t *testing.T) {
	// Without --label the request body stays exactly what it was before sessions had labels.
	unlabeled, err := json.Marshal(CreateAgentVaultSessionRequest{AccessBundles: []string{"coding-agent"}, TTL: "never"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unlabeled), "label") {
		t.Errorf("want no label key, got %s", unlabeled)
	}

	labeled, err := json.Marshal(CreateAgentVaultSessionRequest{AccessBundles: []string{"coding-agent"}, TTL: "never", Label: "nightly deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(labeled), `"label":"nightly deploy"`) {
		t.Errorf("want the label in the body, got %s", labeled)
	}
}
