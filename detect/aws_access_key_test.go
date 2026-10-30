package detect

import (
	"context"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/detect/sources"
)

func TestDefaultConfigReportsStandaloneAWSAccessKeyID(t *testing.T) {
	const keyID = "AKIA" + "K3COQOCE55OFYHTR"
	secret := strings.Join([]string{
		"IPmc3x6F",
		"LlN9yA+/",
		"6nAe4CVU",
		"CX42VARe",
		"PV+0200o",
	}, "")

	tests := []struct {
		name        string
		content     string
		expectedIDs []string
	}{
		{
			name:        "standalone key ID",
			content:     "AWS_ACCESS_KEY_ID=" + keyID + "\n",
			expectedIDs: []string{"aws-access-key-id"},
		},
		{
			name:        "paired key",
			content:     "AWS_ACCESS_KEY_ID=" + keyID + "\nAWS_SECRET_ACCESS_KEY=" + secret + "\n",
			expectedIDs: []string{"aws-access-token"},
		},
		{
			name:        "key assigned to generic API key variable",
			content:     "API_KEY=" + keyID + "\n",
			expectedIDs: []string{"aws-access-key-id"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector, err := NewDetectorDefaultConfig()
			if err != nil {
				t.Fatal(err)
			}

			findings, err := detector.DetectSource(context.Background(), &sources.File{
				Content: strings.NewReader(tt.content),
				Path:    "credentials.env",
			})
			if err != nil {
				t.Fatal(err)
			}

			if len(findings) != len(tt.expectedIDs) {
				t.Fatalf("expected %d findings, got %d: %#v", len(tt.expectedIDs), len(findings), findings)
			}
			for i, expectedID := range tt.expectedIDs {
				if findings[i].RuleID != expectedID {
					t.Errorf("finding %d: expected rule %q, got %q", i, expectedID, findings[i].RuleID)
				}
			}
		})
	}
}
